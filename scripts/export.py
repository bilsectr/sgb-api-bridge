#!/usr/bin/env python3
"""
SGB Feed Export - SQLite indicator store'undan SIEM/threat-intel artifact'lari.

Cikti dizini: feeds/
  sgb-master.csv          Kanonik tablo (tum aktif valid kayitlar).
  sgb-master.jsonl        Programatik tuketim.
  stix/sgb-{type}.stix2.json   STIX 2.1 indicator bundle (type basina).
  by-connectiontype/{ct}-{type}.txt   AC/BC/EK/MC/MF/MM/OT/PH dilimleri.
  by-description/{desc}-{type}.txt    PH/MD/MI/MU/MC/BP/CA dilimleri.
  by-criticality/level-{N}-{type}.txt
  by-source/{src}-{type}.txt
  index.json              Tum cikti dosyalarinin manifest'i.

Davranis: feeds/ dizinini her run'da yeniden uretir (atomik temp + replace).
Yalniz removed_at_utc IS NULL AND valid = 1 kayitlar export edilir.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import sgb_db  # noqa: F401 (DB sema garantisi icin)

__version__ = "1.0.0"

_ROOT_OVERRIDE = os.environ.get("SGB_BRIDGE_ROOT")
ROOT = Path(_ROOT_OVERRIDE) if _ROOT_OVERRIDE else Path(__file__).resolve().parent.parent
FEEDS_DIR = ROOT / "feeds"

# Deterministik STIX indicator id icin namespace (uuid5).
# Bu UUID sabit: ayni SGB ID hep ayni STIX indicator id'sine donusur.
STIX_NS = uuid.UUID("c0ffee00-5664-4b1d-9c1d-5b00b50000d1")

# SGB Identity (STIX) - bundle'lara dahil edilir.
SGB_IDENTITY_ID = "identity--" + str(
    uuid.uuid5(STIX_NS, "sgb-siber-guvenlik-baskanligi")
)

# Source -> STIX confidence (0-100). SGB'nin ic kaynaklari yuksek; ihbar dusuk.
SOURCE_CONFIDENCE = {
    "US": 85,  # TR-CERT (eski USOM)
    "SB": 85,  # SGB
    "SO": 70,  # SOME/CERT
    "RS": 60,  # RSA
    "IH": 40,  # Ihbar
}

# Connectiontype -> STIX 2.1 indicator_types vocab (en yakin esleme).
CT_TO_INDICATOR_TYPES = {
    "PH": ["malicious-activity"],   # phishing
    "BC": ["malicious-activity"],   # botnet C&C
    "AC": ["malicious-activity"],   # APT C&C
    "EK": ["malicious-activity"],   # exploit kit
    "MF": ["malicious-activity"],   # malware download
    "MM": ["malicious-activity"],   # mining
    "MC": ["malicious-activity"],   # mobile C&C
    "OT": ["unknown"],
}

# Insan-okunabilir etiketler (STIX labels).
CT_LABELS = {
    "PH": "phishing",
    "BC": "botnet-c2",
    "AC": "apt-c2",
    "EK": "exploit-kit",
    "MF": "malware-download",
    "MM": "mining",
    "MC": "mobile-c2",
    "OT": "other",
}
DESC_LABELS = {
    "PH": "phishing",
    "MD": "malware-distribution-domain",
    "MI": "malware-distribution-ip",
    "MU": "malware-distribution-url",
    "MC": "malware-command-center",
    "BP": "financial-phishing",
    "CA": "cyber-attack",
}

TYPES = ("domain", "url", "ip", "ip6", "ip6net")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("export")


# ---------------------------------------------------------------------------
# DB IO
# ---------------------------------------------------------------------------

def open_db_readonly() -> sqlite3.Connection:
    p = ROOT / "state" / "sgb.db"
    if not p.exists():
        raise SystemExit(f"DB bulunamadi: {p} (once sync.py --mode full calistir)")
    # immutable=0; standart RO ile aciyoruz ki WAL'i de gorebilelim.
    conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def iter_active(conn: sqlite3.Connection):
    """Aktif + valid tum kayitlari id sirasinda yield eder."""
    cur = conn.execute(
        """
        SELECT id, type, value_clean, category, connectiontype, source,
               criticality_level, api_date, first_seen_utc, last_seen_utc
          FROM indicators
         WHERE removed_at_utc IS NULL AND valid = 1
         ORDER BY id
        """
    )
    for row in cur:
        yield row


# ---------------------------------------------------------------------------
# Dosya yardimcilari (atomik yazim)
# ---------------------------------------------------------------------------

def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8", newline="\n")
    tmp.replace(path)


class AtomicTextFile:
    """Context manager: tmp dosyaya yaz, basariliysa hedefe replace et."""

    def __init__(self, path: Path):
        self.path = path
        self.tmp = path.with_suffix(path.suffix + ".tmp")

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.f = self.tmp.open("w", encoding="utf-8", newline="\n")
        return self.f

    def __exit__(self, exc_type, exc, tb):
        self.f.close()
        if exc is None:
            self.tmp.replace(self.path)
        else:
            try:
                self.tmp.unlink()
            except OSError:
                pass
        return False


# ---------------------------------------------------------------------------
# Master CSV + JSONL
# ---------------------------------------------------------------------------

MASTER_FIELDS = [
    "id", "type", "value", "description", "connectiontype",
    "source", "criticality_level", "api_date",
    "first_seen_utc", "last_seen_utc",
]


def write_master(conn: sqlite3.Connection) -> tuple[int, int]:
    csv_path = FEEDS_DIR / "sgb-master.csv"
    jsonl_path = FEEDS_DIR / "sgb-master.jsonl"
    n = 0
    with AtomicTextFile(csv_path) as cf, AtomicTextFile(jsonl_path) as jf:
        w = csv.DictWriter(cf, fieldnames=MASTER_FIELDS, lineterminator="\n")
        w.writeheader()
        for row in iter_active(conn):
            rec = {
                "id": row["id"],
                "type": row["type"],
                "value": row["value_clean"],
                "description": row["category"],
                "connectiontype": row["connectiontype"],
                "source": row["source"],
                "criticality_level": row["criticality_level"],
                "api_date": row["api_date"],
                "first_seen_utc": row["first_seen_utc"],
                "last_seen_utc": row["last_seen_utc"],
            }
            w.writerow(rec)
            jf.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return n, csv_path.stat().st_size


# ---------------------------------------------------------------------------
# Slice'lar
# ---------------------------------------------------------------------------

def write_slices(conn: sqlite3.Connection) -> dict[str, int]:
    """Slice gruplari: by-connectiontype, by-description, by-criticality, by-source.
    Her slice plain-text value listesi (sortlu, benzersiz)."""
    # Bellek profili: en kotuk ihtimalde 470K * ~50B = ~24MB. Sorun degil.
    groups: dict[tuple[str, str, str], set[str]] = {}
    for row in iter_active(conn):
        val = row["value_clean"]
        typ = row["type"]
        ct = row["connectiontype"]
        cat = row["category"]
        crit = row["criticality_level"]
        src = row["source"]
        if ct:
            groups.setdefault(("by-connectiontype", ct.lower(), typ), set()).add(val)
        if cat:
            groups.setdefault(("by-description", cat.lower(), typ), set()).add(val)
        if crit is not None:
            groups.setdefault(("by-criticality", f"level-{crit}", typ), set()).add(val)
        if src:
            groups.setdefault(("by-source", src.lower(), typ), set()).add(val)

    counts: dict[str, int] = {}
    for (group, key, typ), values in groups.items():
        out = FEEDS_DIR / group / f"{key}-{typ}.txt"
        atomic_write_text(
            out,
            "\n".join(sorted(values)) + ("\n" if values else ""),
        )
        counts[f"{group}/{key}-{typ}"] = len(values)
    return counts


# ---------------------------------------------------------------------------
# STIX 2.1
# ---------------------------------------------------------------------------

def _stix_pattern(typ: str, value: str) -> str | None:
    if typ == "domain":
        return f"[domain-name:value = '{_esc(value)}']"
    if typ == "url":
        return f"[url:value = '{_esc(value)}']"
    if typ == "ip":
        return f"[ipv4-addr:value = '{_esc(value)}']"
    if typ == "ip6":
        return f"[ipv6-addr:value = '{_esc(value)}']"
    if typ == "ip6net":
        # STIX'te tek bir IPv6 range standardi yok; ipv6-addr value CIDR ile
        # gozlemcilerin cogu tarafindan kabul ediliyor. Uyumsuz tarafta filter
        # icin x_sgb_value ham olarak da var.
        return f"[ipv6-addr:value = '{_esc(value)}']"
    return None


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'")


def _indicator_id(sgb_id: int) -> str:
    return "indicator--" + str(uuid.uuid5(STIX_NS, f"sgb:{sgb_id}"))


def _identity_object() -> dict:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": SGB_IDENTITY_ID,
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "Siber Guvenlik Baskanligi (SGB)",
        "identity_class": "organization",
        "contact_information": "https://siberguvenlik.gov.tr",
    }


def _to_stix_indicator(row: sqlite3.Row) -> dict | None:
    pattern = _stix_pattern(row["type"], row["value_clean"])
    if pattern is None:
        return None
    ct = row["connectiontype"]
    cat = row["category"]
    src = row["source"]
    labels = []
    if ct and ct in CT_LABELS:
        labels.append(CT_LABELS[ct])
    if cat and cat in DESC_LABELS and DESC_LABELS[cat] not in labels:
        labels.append(DESC_LABELS[cat])
    if not labels:
        labels = ["malicious-activity"]

    valid_from = (row["api_date"] or row["first_seen_utc"] or "").replace(" ", "T")
    if valid_from and not valid_from.endswith("Z") and "+" not in valid_from[10:]:
        valid_from = valid_from + "Z"

    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _indicator_id(row["id"]),
        "created_by_ref": SGB_IDENTITY_ID,
        "created": (row["first_seen_utc"] or "").replace("+00:00", "Z"),
        "modified": (row["last_seen_utc"] or "").replace("+00:00", "Z"),
        "name": f"SGB {row['type']} indicator #{row['id']}",
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": valid_from,
        "indicator_types": CT_TO_INDICATOR_TYPES.get(ct or "OT", ["malicious-activity"]),
        "labels": labels,
        "confidence": SOURCE_CONFIDENCE.get(src or "", 50),
        "external_references": [
            {
                "source_name": "sgb",
                "external_id": str(row["id"]),
                "url": "https://siberguvenlik.gov.tr",
            }
        ],
        # Custom alanlar (x_ prefix STIX 2.1 ile uyumlu).
        "x_sgb_id": row["id"],
        "x_sgb_type": row["type"],
        "x_sgb_value": row["value_clean"],
        "x_sgb_connectiontype": ct,
        "x_sgb_description": cat,
        "x_sgb_source": src,
        "x_sgb_criticality": row["criticality_level"],
        "x_sgb_api_date": row["api_date"],
    }
    return obj


def write_stix(conn: sqlite3.Connection) -> dict[str, int]:
    """Type basina ayri STIX 2.1 bundle yazar (bellek profili + ingest kolayligi).
    Tek dosya yerine type-bazli: ip-only ingest yapan urunler icin pratik.
    """
    out_dir = FEEDS_DIR / "stix"
    counts: dict[str, int] = {}
    identity = _identity_object()
    for typ in TYPES:
        bundle_id = "bundle--" + str(uuid.uuid5(STIX_NS, f"bundle:{typ}"))
        path = out_dir / f"sgb-{typ}.stix2.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        n = 0
        with tmp.open("w", encoding="utf-8", newline="\n") as f:
            # Streamli yazim: dev bundle'i memory'e almiyoruz.
            f.write('{\n')
            f.write(f'  "type": "bundle",\n')
            f.write(f'  "id": "{bundle_id}",\n')
            f.write(f'  "spec_version": "2.1",\n')
            f.write('  "objects": [\n')
            f.write("    " + json.dumps(identity, ensure_ascii=False))
            cur = conn.execute(
                """
                SELECT id, type, value_clean, category, connectiontype, source,
                       criticality_level, api_date, first_seen_utc, last_seen_utc
                  FROM indicators
                 WHERE removed_at_utc IS NULL AND valid = 1 AND type = ?
                 ORDER BY id
                """,
                (typ,),
            )
            for row in cur:
                ind = _to_stix_indicator(row)
                if ind is None:
                    continue
                f.write(",\n    " + json.dumps(ind, ensure_ascii=False))
                n += 1
            f.write("\n  ]\n}\n")
        tmp.replace(path)
        counts[typ] = n
        log.info(f"[stix:{typ}] {n} indicator -> {path.relative_to(ROOT)}")
    return counts


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(extra: dict) -> None:
    items = []
    for p in sorted(FEEDS_DIR.rglob("*")):
        if not p.is_file() or p.name in ("index.json",) or p.suffix == ".tmp":
            continue
        items.append({
            "path": str(p.relative_to(FEEDS_DIR)).replace("\\", "/"),
            "size_bytes": p.stat().st_size,
            "sha256": _sha256(p),
        })
    manifest = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "exporter_version": __version__,
        "files": items,
        **extra,
    }
    atomic_write_text(FEEDS_DIR / "index.json", json.dumps(manifest, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Orkestrasyon
# ---------------------------------------------------------------------------

def clean_feeds_dir() -> None:
    """feeds/ dizinini sifirla (eski slice'lar kalmasin).
    Yalniz feeds/ altini siler, baska bir yere dokunmaz.
    """
    if FEEDS_DIR.exists():
        for child in FEEDS_DIR.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    FEEDS_DIR.mkdir(parents=True, exist_ok=True)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--skip-stix", action="store_true",
                   help="STIX bundle'lari atla (hizli iterasyon icin).")
    p.add_argument("--keep-dir", action="store_true",
                   help="feeds/ dizinini silme; ustune yaz.")
    args = p.parse_args()

    log.info(f"== EXPORT basliyor (v{__version__}) ==")
    if not args.keep_dir:
        clean_feeds_dir()
    else:
        FEEDS_DIR.mkdir(parents=True, exist_ok=True)

    conn = open_db_readonly()
    try:
        master_n, master_size = write_master(conn)
        log.info(f"master: {master_n} kayit, {master_size/1e6:.1f}MB")
        slice_counts = write_slices(conn)
        log.info(f"slices: {len(slice_counts)} dosya")
        stix_counts = {}
        if not args.skip_stix:
            stix_counts = write_stix(conn)
    finally:
        conn.close()

    write_manifest({
        "master_records": master_n,
        "slice_files": len(slice_counts),
        "stix_counts": stix_counts,
    })
    log.info("EXPORT tamamlandi.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
