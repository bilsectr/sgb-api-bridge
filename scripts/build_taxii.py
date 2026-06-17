#!/usr/bin/env python3
"""
SGB TAXII 2.1 statik servis agaci uretici.

Cikti: docs/taxii/
  taxii2/index.json                        Discovery
  api/index.json                           API Root
  api/collections/index.json               Collections listesi
  api/collections/{cid}/index.json         Collection metadata
  api/collections/{cid}/objects/page-NNNN.json   Envelope + STIX objects
  api/collections/{cid}/manifest/page-NNNN.json  Envelope + manifest records
  api/collections/{cid}/pages.json         Cursor index (Worker/nginx kullanir)

URL'ler `__TAXII_BASE__` placeholder ile yazilir; Cloudflare Worker (GitHub
modeli) ve nginx sub_filter (Docker/K8s) serve sirasinda asil host'a rewrite
eder. Bu sayede tek statik artifact 4 dagitim modelini de besler.

Koleksiyonlar (connectiontype bazli; SIEM use case kutuphanesi hedefli):
  sgb-phishing      (PH)
  sgb-botnet-cc     (BC)
  sgb-apt-cc        (AC)
  sgb-exploit-kit   (EK)
  sgb-malware-download (MF)
  sgb-mining        (MM)
  sgb-mobile-cc     (MC)
  sgb-other         (OT)
  sgb-all           (hepsi)

Siralama: id ASC (SGB id'leri global monoton artan).
- Yeni kayit  -> her zaman son sayfaya eklenir; eski sayfalar git diff'inde sabit.
- Silinen kayit -> aktif listeden cikar, sonraki sayfalar bir indicator shift olur.
  Saatlik full sync ile silmeler azaltilamiyor ama nadir oldugu icin kabul.

STIX 'modified' alani = indicators.last_changed_utc (sgb_db smart upsert ile
yalniz icerik gercekten degistiyse tazelenir). Bu sayede degismeyen kayitlar
icin STIX cikti'si byte-identical kalir -> git diff sifir.

Worker `added_after=T` filtresi icin sayfa metadata'sinda max_last_changed
tutulur; T'den buyuk max'a sahip sayfalar dondurulur.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import stix_convert as _export  # STIX converter + identity + namespace
import sgb_db  # noqa: F401

__version__ = "1.0.0"

_ROOT_OVERRIDE = os.environ.get("SGB_BRIDGE_ROOT")
ROOT = Path(_ROOT_OVERRIDE) if _ROOT_OVERRIDE else Path(__file__).resolve().parent.parent
TAXII_DIR = ROOT / "docs" / "taxii"

PAGE_SIZE_DEFAULT = 5000
BASE_PLACEHOLDER = "__TAXII_BASE__"

# Connectiontype kodu -> (collection id, human title, aciklama)
COLLECTIONS = [
    ("PH", "sgb-phishing",         "SGB Phishing",          "Phishing site / kullanici kandirma URL ve domain'leri."),
    ("BC", "sgb-botnet-cc",        "SGB Botnet C&C",        "Botnet komuta-kontrol sunuculari (outbound C2 tespiti)."),
    ("AC", "sgb-apt-cc",           "SGB APT C&C",           "APT komuta-kontrol — yuksek oncelikli tehdit."),
    ("EK", "sgb-exploit-kit",      "SGB Exploit Kit",       "Exploit kit landing / driver sayfalari."),
    ("MF", "sgb-malware-download", "SGB Malware Download",  "Malware dagitim noktalari (payload host)."),
    ("MM", "sgb-mining",           "SGB Cryptomining",      "Tarayicidan veya zararlidan cryptomining noktalari."),
    ("MC", "sgb-mobile-cc",        "SGB Mobile C&C",        "Mobil zararli C2."),
    ("OT", "sgb-other",            "SGB Other",             "Diger / siniflandirilmamis kotucul gostergeler."),
]
ALL_COLLECTION_ID = "sgb-all"
ALL_COLLECTION_TITLE = "SGB All Indicators"
ALL_COLLECTION_DESC = "Tum SGB kotucul gostergeler (tum connectiontype + tum tipler)."

# TAXII discovery / API root sabit ID'leri (Worker rewrite etmesin diye burada).
DISCOVERY_TITLE = "SGB Threat Intelligence (TAXII 2.1)"
DISCOVERY_DESC = (
    "Siber Guvenlik Baskanligi (SGB, eski USOM) acik tehdit beslemesinin "
    "TAXII 2.1 sunumu. Anonim erisim, public veri."
)
API_ROOT_TITLE = "SGB Default API Root"
API_ROOT_DESC = "Tek API root altinda connectiontype bazli koleksiyonlar."
API_ROOT_PATH = "api"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("build_taxii")


# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------

def open_db_readonly() -> sqlite3.Connection:
    p = ROOT / "state" / "sgb.db"
    if not p.exists():
        raise SystemExit(f"DB bulunamadi: {p} (once sync.py calistir)")
    # Once RW acip migration'i tetikle (eski schema'lar icin gerekli),
    # ardindan kapat ve RO ac.
    _mig = sgb_db.connect(ROOT)
    _mig.close()
    conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


_SELECT_COLS = (
    "id, type, value_clean, category, connectiontype, source, "
    "criticality_level, api_date, first_seen_utc, last_seen_utc, last_changed_utc"
)


def iter_collection_rows(conn: sqlite3.Connection, ct_code: str | None):
    """ct_code None ise hepsi (sgb-all). id ASC -> stabil sayfalama."""
    if ct_code is None:
        cur = conn.execute(
            f"""
            SELECT {_SELECT_COLS}
              FROM indicators
             WHERE removed_at_utc IS NULL AND valid = 1
             ORDER BY id ASC
            """
        )
    else:
        cur = conn.execute(
            f"""
            SELECT {_SELECT_COLS}
              FROM indicators
             WHERE removed_at_utc IS NULL AND valid = 1 AND connectiontype = ?
             ORDER BY id ASC
            """,
            (ct_code,),
        )
    for row in cur:
        yield row


# ---------------------------------------------------------------------------
# Yazim
# ---------------------------------------------------------------------------

_COMPACT = False  # main() override eder

def atomic_write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as f:
        if _COMPACT:
            json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
        else:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")
    tmp.replace(path)


def _iso(ts: str | None) -> str:
    if not ts:
        return "1970-01-01T00:00:00.000Z"
    return ts.replace("+00:00", "Z").replace(" ", "T")


# ---------------------------------------------------------------------------
# Discovery & API Root & Collections list
# ---------------------------------------------------------------------------

def write_discovery() -> None:
    obj = {
        "title": DISCOVERY_TITLE,
        "description": DISCOVERY_DESC,
        "contact": "https://github.com/bilsectr/sgb-api-bridge",
        "default": f"{BASE_PLACEHOLDER}/{API_ROOT_PATH}/",
        "api_roots": [f"{BASE_PLACEHOLDER}/{API_ROOT_PATH}/"],
    }
    atomic_write_json(TAXII_DIR / "taxii2" / "index.json", obj)


def write_api_root(collection_meta: list[dict]) -> None:
    obj = {
        "title": API_ROOT_TITLE,
        "description": API_ROOT_DESC,
        "versions": ["application/taxii+json;version=2.1"],
        "max_content_length": 104857600,
    }
    atomic_write_json(TAXII_DIR / "api" / "index.json", obj)
    atomic_write_json(
        TAXII_DIR / "api" / "collections" / "index.json",
        {"collections": collection_meta},
    )


# Collection `id` = alias (cid). TAXII 2.1'de koleksiyon URL yolu (`/collections/{id}/`)
# bu `id` alanindan kurulur; spec'e uygun istemciler (OASIS taxii2client, dolayisiyla
# QRadar TI) discovery'den gelen `id`yi kullanir. Ayri bir UUID verirsek o yol 404 olur.
def collection_metadata(cid: str, title: str, desc: str) -> dict:
    return {
        "id": cid,
        "title": title,
        "description": desc,
        "alias": cid,
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    }


# ---------------------------------------------------------------------------
# Collection sayfalama
# ---------------------------------------------------------------------------

def write_collection(
    conn: sqlite3.Connection,
    ct_code: str | None,
    cid: str,
    title: str,
    desc: str,
    page_size: int,
) -> dict:
    """Tek bir collection'i yazar; metadata + pages.json + obj/manifest sayfalari."""
    col_dir = TAXII_DIR / "api" / "collections" / cid
    obj_dir = col_dir / "objects"
    man_dir = col_dir / "manifest"
    # Eski sayfalari sil (deterministik cikti).
    for d in (obj_dir, man_dir):
        if d.exists():
            shutil.rmtree(d)
    obj_dir.mkdir(parents=True, exist_ok=True)
    man_dir.mkdir(parents=True, exist_ok=True)

    atomic_write_json(col_dir / "index.json", collection_metadata(cid, title, desc))

    pages_meta: list[dict] = []
    page_idx = 0
    total = 0
    buf_objects: list[dict] = []
    buf_manifest: list[dict] = []
    min_id = None
    max_id = None
    min_added = None
    max_added = None
    max_changed = None  # Worker `added_after` icin kritik
    identity = _export._identity_object()

    def flush(force: bool = False):
        nonlocal page_idx, buf_objects, buf_manifest
        nonlocal min_id, max_id, min_added, max_added, max_changed
        if not buf_manifest and not force:
            return
        page_idx += 1
        page_name = f"page-{page_idx:04d}.json"
        objs_with_identity = [identity] + buf_objects
        atomic_write_json(obj_dir / page_name, {
            "more": False,
            "objects": objs_with_identity,
        })
        atomic_write_json(man_dir / page_name, {
            "more": False,
            "objects": buf_manifest,
        })
        pages_meta.append({
            "page": page_idx,
            "file": page_name,
            "count": len(buf_manifest),
            "min_id": min_id,
            "max_id": max_id,
            "min_date_added": min_added,
            "max_date_added": max_added,
            "max_last_changed": max_changed,
        })
        buf_objects = []
        buf_manifest = []
        min_id = max_id = None
        min_added = max_added = max_changed = None

    for row in iter_collection_rows(conn, ct_code):
        ind = _export._to_stix_indicator(row)
        if ind is None:
            continue
        # STIX 'modified' alanini last_changed_utc'den uret (stabilite icin).
        modified = _iso(row["last_changed_utc"] or row["first_seen_utc"])
        ind["modified"] = modified

        date_added = _iso(row["first_seen_utc"])
        rid = row["id"]
        if min_id is None or rid < min_id: min_id = rid
        if max_id is None or rid > max_id: max_id = rid
        if min_added is None or date_added < min_added: min_added = date_added
        if max_added is None or date_added > max_added: max_added = date_added
        if max_changed is None or modified > max_changed: max_changed = modified

        buf_objects.append(ind)
        buf_manifest.append({
            "id": ind["id"],
            "date_added": date_added,
            "version": modified,
            "media_type": "application/stix+json;version=2.1",
        })
        total += 1
        if len(buf_manifest) >= page_size:
            flush()

    # Bos collection icin de en az 1 sayfa (bos envelope) yazariz; client tutarli kalsin.
    flush(force=(page_idx == 0))

    # Sayfalar arasi `more`/`next` baglantilarini duzelt.
    n_pages = len(pages_meta)
    for i, pm in enumerate(pages_meta, start=1):
        is_last = (i == n_pages)
        next_cursor = None if is_last else f"{i + 1:04d}"
        for kind in ("objects", "manifest"):
            p = col_dir / kind / pm["file"]
            data = json.loads(p.read_text(encoding="utf-8"))
            data["more"] = not is_last
            if next_cursor:
                data["next"] = next_cursor
            atomic_write_json(p, data)

    pages_index = {
        "collection_id": cid,
        "alias": cid,
        "page_size": page_size,
        "total_objects": total,
        "pages": pages_meta,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write_json(col_dir / "pages.json", pages_index)
    log.info(f"[{cid}] {total} indicator, {n_pages} sayfa")
    return {"cid": cid, "total": total, "pages": n_pages}


# ---------------------------------------------------------------------------
# Orkestrasyon
# ---------------------------------------------------------------------------

def clean_taxii_dir() -> None:
    if TAXII_DIR.exists():
        shutil.rmtree(TAXII_DIR)
    TAXII_DIR.mkdir(parents=True, exist_ok=True)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--page-size", type=int, default=PAGE_SIZE_DEFAULT,
                   help=f"Sayfa basina indicator sayisi (default: {PAGE_SIZE_DEFAULT})")
    p.add_argument("--keep-dir", action="store_true",
                   help="docs/taxii/ dizinini once silme")
    p.add_argument("--compact", action="store_true",
                   help="Sayfa JSON'larini kompakt yaz (production icin ~%%40 kucuk).")
    p.add_argument("--with-all", action="store_true",
                   help="sgb-all (tum kayitlar) koleksiyonunu da yaz. Boyutu ~2x'ler.")
    args = p.parse_args()

    global _COMPACT
    _COMPACT = args.compact

    log.info(f"== TAXII build basliyor (v{__version__}, compact={args.compact}) ==")
    if not args.keep_dir:
        clean_taxii_dir()
    else:
        TAXII_DIR.mkdir(parents=True, exist_ok=True)

    conn = open_db_readonly()
    try:
        collection_meta: list[dict] = []
        summaries = []

        for ct_code, cid, title, desc in COLLECTIONS:
            s = write_collection(conn, ct_code, cid, title, desc, args.page_size)
            summaries.append(s)
            collection_meta.append(collection_metadata(cid, title, desc))

        if args.with_all:
            s = write_collection(conn, None, ALL_COLLECTION_ID,
                                 ALL_COLLECTION_TITLE, ALL_COLLECTION_DESC,
                                 args.page_size)
            summaries.append(s)
            collection_meta.append(collection_metadata(
                ALL_COLLECTION_ID, ALL_COLLECTION_TITLE, ALL_COLLECTION_DESC))

        write_discovery()
        write_api_root(collection_meta)

        # Build summary (debug/CI icin)
        atomic_write_json(TAXII_DIR / "build-info.json", {
            "version": __version__,
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "page_size": args.page_size,
            "collections": summaries,
            "base_placeholder": BASE_PLACEHOLDER,
        })
    finally:
        conn.close()

    log.info("TAXII build tamamlandi.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
