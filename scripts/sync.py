#!/usr/bin/env python3
"""
SGB API Bridge - SGB (eski USOM) API'sini duz metin feed'e donusturur.

Modlar:
    --mode full         : Tum tipler icin tum sayfalari ceker. per-page=1000 ile ~10-15 dk.
                          Ilk bootstrap ve periyodik reconcile (silinen kayitlari temizleme)
                          icin kullanilir.
    --mode delta        : Tum tipler icin yalniz yeni kayitlari ceker (~saniyeler). Saatlik.
                          Silinen kayitlari yakalayamaz - bunun icin full reconcile gerekir.
    --mode loop         : Container'lar icin: delta'yi sureki tetikler, N delta'da bir
                          full reconcile calistirir (SGB_BRIDGE_RECONCILE_EVERY).
    --mode healthcheck  : stats.json fresh mi diye bakar (delta workflow'da kullaniliyor).
    --mode catalog-sync : 3 lookup endpoint'ini (category/source/connection-type) DB'ye yazar.

Storage:
    docs/*-list.txt  : geriye uyumlu duz metin feed (degismedi).
    state/sgb.db     : zengin SQLite store (id, category, connectiontype, source,
                       criticality_level, first/last_seen, removed_at). SIEM
                       export'lari (Faz 1+) bu DB'den uretilir.

API:
    GET https://siberguvenlik.gov.tr/api/address/index?type={domain|url|ip|ip6|ip6net}&page=N&per-page=K
    Response: {"totalCount": N, "count": K, "models": [...], "page": P, "pageCount": M}
    Kayitlar tarihe gore newest-first siralanmis durumda.
    ID'ler tum tipler arasinda global ve monoton artan.
    Liste mutable: API'den kayit SILINEBILIR; bu nedenle loop modu periyodik
    full reconcile calistirir (bkz. SGB_BRIDGE_RECONCILE_EVERY).
    Rate limit: 20 rps / 400 rpm.
"""
import argparse
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

import sgb_db

__version__ = "2.1.0"

API_URL = "https://siberguvenlik.gov.tr/api/address/index"
CATALOG_ENDPOINTS = {
    # API kayit alani 'desc' -> bu lookup endpoint: address-description
    # (SGB taksonomisinde "description" denir; kayitta tek harfli kod: PH/MD/MI/MU/MC/BP/CA)
    "description":    "https://siberguvenlik.gov.tr/api/address-description/index",
    "source":         "https://siberguvenlik.gov.tr/api/address-source/index",
    "connectiontype": "https://siberguvenlik.gov.tr/api/address-connection-type/index",
}
TYPES = ("domain", "url", "ip", "ip6", "ip6net")
# API per-page parametresi: tek istekte donen kayit sayisi. pratikte 10000 bile kabul ediliyor. 1000 muhafazakar bir varsayilan: full sync
# domain icin 22562 -> 452 sayfaya duser (~50x daha az istek).
PER_PAGE = int(os.environ.get("SGB_BRIDGE_PER_PAGE", "1000"))
SLEEP_OK_FULL = 1.0
SLEEP_OK_DELTA = 1.0
SLEEP_429_BASE = 15.0
MAX_RETRIES = 6
TIMEOUT = 30
UA = "sgb-api-bridge/2.0 (+https://github.com/bilsectr/sgb-api-bridge)"
STOP_AFTER_KNOWN = 40
# Delta'nin tek calismada gezecegi maksimum sayfa. per-page=1000 ile normal saatlik delta
# 1 sayfada biter; bu tavan yalniz state cok bayatsa (orn. haftalarca delta calismadi)
# devreye girer.
DELTA_MAX_PAGES = int(os.environ.get("SGB_BRIDGE_DELTA_MAX_PAGES", "1000"))
CHECKPOINT_EVERY = 25  # full sync: kac sayfada bir state'i diske yaz

_ROOT_OVERRIDE = os.environ.get("SGB_BRIDGE_ROOT")
ROOT = Path(_ROOT_OVERRIDE) if _ROOT_OVERRIDE else Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
STATE_FILE = ROOT / "state" / "seen_ids.json"

# Loop mode: delta'yi surekli, full'u N delta'da bir tetikler.
# Full reconcile gereklidir cunku API'den kayit silinebilir; saf delta silinmis
# kayitlari final dosyadan temizleyemez (sadece yeni id'leri ekler).
# 0 = full reconcile devre disi (eski davranis).
LOOP_DELTA_INTERVAL = int(os.environ.get("SGB_BRIDGE_DELTA_INTERVAL_SEC", "3600"))
LOOP_RECONCILE_EVERY = int(os.environ.get("SGB_BRIDGE_RECONCILE_EVERY", "24"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sgb")


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log.warning("State JSON parse edilemedi - sifirdan basliyoruz")
    return {t: {"max_id": 0, "last_full_sync": None, "last_delta_sync": None} for t in TYPES}


def save_state(state: dict) -> None:
    """Atomik yazim: SIGKILL state dosyasini bozmasin."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_name(STATE_FILE.name + ".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(STATE_FILE)  # atomik (POSIX ve modern Windows)


def fetch_page(session: requests.Session, typ: str, page: int) -> dict:
    delay = SLEEP_429_BASE
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = session.get(
                API_URL,
                params={"type": typ, "page": page, "per-page": PER_PAGE},
                timeout=TIMEOUT,
                headers={"User-Agent": UA, "Accept": "application/json"},
            )
            if r.status_code == 429:
                log.warning(f"{typ} page={page} 429 - {delay}s bekle (deneme {attempt})")
                time.sleep(delay)
                delay *= 2
                continue
            r.raise_for_status()
            return r.json()
        except requests.RequestException as e:
            last_err = e
            log.warning(f"{typ} page={page} hata: {e} (deneme {attempt})")
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"{typ} page={page} {MAX_RETRIES} denemede basarisiz: {last_err}")


MD_LINK_RE = re.compile(r"\[[^\]]+\]\((https?://[^)]+)\)")


def clean_entry(raw: str, typ: str) -> str:
    if not raw:
        return ""
    s = raw.strip()
    # Markdown link syntax: [text](https://example.com/path) -> https://example.com/path
    m = MD_LINK_RE.search(s)
    if m:
        s = m.group(1)
    s = s.strip().lower()
    if typ in ("domain", "ip", "ip6", "ip6net"):
        # Olasi scheme/path artifact'larini temizle
        if "://" in s:
            s = s.split("://", 1)[1]
        # IPv6 literal'leri [::1]:port formatinda gelebilir
        if s.startswith("["):
            end = s.find("]")
            if end != -1:
                s = s[1:end]
        elif typ != "ip6":
            s = s.split("/", 1)[0] if typ != "ip6net" else s
    return s


IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
IP6_RE = re.compile(r"^[0-9a-f:]+(/\d{1,3})?$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _valid_ipv4(entry: str, allow_cidr: bool) -> bool:
    if not IP_RE.match(entry):
        return False
    if "/" in entry and not allow_cidr:
        return False
    addr = entry.split("/", 1)[0]
    return all(0 <= int(p) <= 255 for p in addr.split("."))


def _valid_ipv6(entry: str, allow_cidr: bool) -> bool:
    if not IP6_RE.match(entry):
        return False
    has_cidr = "/" in entry
    if has_cidr and not allow_cidr:
        return False
    addr = entry.split("/", 1)[0]
    if "::" in addr:
        # Compressed form: cifte iki nokta yalniz bir kez gecmeli
        if addr.count("::") > 1:
            return False
    else:
        # Tam form: tam olarak 8 grup olmali
        if len(addr.split(":")) != 8:
            return False
    return ":" in addr  # IPv4 not allowed


def valid_for(entry: str, typ: str) -> bool:
    if not entry:
        return False
    if typ == "ip":
        return _valid_ipv4(entry, allow_cidr=False)
    if typ == "ip6":
        return _valid_ipv6(entry, allow_cidr=False)
    if typ == "ip6net":
        return _valid_ipv6(entry, allow_cidr=True)
    if typ == "domain":
        return bool(DOMAIN_RE.match(entry))
    if typ == "url":
        return len(entry) >= 3 and all(c.isprintable() for c in entry)
    return False


def partial_path(typ: str) -> Path:
    return DOCS_DIR / f"{typ}-list.txt.partial"


def final_path(typ: str) -> Path:
    return DOCS_DIR / f"{typ}-list.txt"


def append_to_partial(typ: str, records: list, conn=None) -> tuple:
    """Records'lari partial dosyaya yazar; (yazilan, atilan, max_id) doner.

    conn verilirse ayni records DB'ye de upsert edilir (dual-write).
    """
    written = 0
    skipped = 0
    max_id = 0
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    with partial_path(typ).open("a", encoding="utf-8") as f:
        for rec in records:
            try:
                rid = int(rec.get("id"))
                if rid > max_id:
                    max_id = rid
            except (TypeError, ValueError):
                pass
            cleaned = clean_entry(rec.get("url") or "", typ)
            if valid_for(cleaned, typ):
                f.write(cleaned + "\n")
                written += 1
            else:
                skipped += 1
    if conn is not None and records:
        sgb_db.upsert_indicators(conn, records, typ, clean_entry, valid_for)
    return written, skipped, max_id


def finalize_partial(typ: str) -> int:
    """Partial dosyayi dedupe + sort edip final dosyaya yazar; satir sayisi doner."""
    pp = partial_path(typ)
    fp = final_path(typ)
    if not pp.exists():
        fp.write_text("", encoding="utf-8")
        return 0
    lines = {ln.strip() for ln in pp.read_text(encoding="utf-8").splitlines() if ln.strip()}
    fp.write_text("\n".join(sorted(lines)) + ("\n" if lines else ""), encoding="utf-8")
    pp.unlink()
    return len(lines)


def _sync_full(session: requests.Session, typ: str, state: dict, conn=None) -> int:
    """Full sync: resume-capable. Return: bu run'da yazilan satir sayisi (partial'a).

    conn verilirse her sayfa DB'ye de upsert edilir; finalize'da bu run'in
    cutoff'undan eski (= bu run'da gorulmeyen) kayitlar removed_at damgalanir.
    """
    tstate = state.setdefault(typ, {"max_id": 0, "last_full_sync": None, "last_delta_sync": None})
    resume_page = int(tstate.get("resume_page") or 0)
    max_known = int(tstate.get("max_id") or 0)
    partial_exists = partial_path(typ).exists()
    # Reconcile cutoff: resume durumunda onceki run'in cutoff'unu kullan, yoksa simdi.
    # Kayitli cutoff yalniz partial dosyasi mevcutsa anlamli (resume).
    if resume_page > 0 and tstate.get("full_run_started_utc"):
        cutoff_utc = tstate["full_run_started_utc"]
    else:
        cutoff_utc = datetime.now(timezone.utc).isoformat()
        tstate["full_run_started_utc"] = cutoff_utc

    # Partial dosyayi ASLA silme. Duplicate ekleme zararsiz (dedupe en sonda).
    # State kaybolsa bile partial korunsun.
    if partial_exists and resume_page <= 0:
        log.warning(f"[{typ}] partial mevcut ama resume_page yok - basa donup partial'a ekleyecegim")
    elif partial_exists and resume_page > 0:
        log.info(f"[{typ}] partial bulundu, page={resume_page}'den devam")
    elif not partial_exists and resume_page > 0:
        log.warning(f"[{typ}] resume_page={resume_page} ama partial yok - basa doniyorum")
        resume_page = 0

    first = fetch_page(session, typ, 1)
    total = first.get("totalCount")
    page_count = first.get("pageCount") or 1
    tstate["total_count"] = total
    log.info(f"[{typ}] FULL totalCount={total} pageCount={page_count} resume_from={resume_page or 1}")

    written_total = 0

    if resume_page <= 1:
        w, s, mid = append_to_partial(typ, first.get("models") or [], conn=conn)
        written_total += w
        if mid > max_known:
            max_known = mid

    start_page = max(2, resume_page if resume_page > 0 else 2)
    page = start_page
    while page <= page_count:
        time.sleep(SLEEP_OK_FULL)
        try:
            data = fetch_page(session, typ, page)
        except RuntimeError as e:
            # Bir sayfa kalici basarisiz oldu: checkpoint kaydet ve cik
            log.error(f"[{typ}] page={page} kalici basarisizlik: {e}")
            tstate["resume_page"] = page
            tstate["max_id"] = max_known
            save_state(state)
            raise
        recs = data.get("models") or []
        if not recs:
            log.info(f"[{typ}] page={page} bos - bitti")
            break
        w, s, mid = append_to_partial(typ, recs, conn=conn)
        written_total += w
        if mid > max_known:
            max_known = mid

        if page % CHECKPOINT_EVERY == 0:
            tstate["resume_page"] = page + 1
            tstate["max_id"] = max_known
            save_state(state)
        if page % 200 == 0:
            log.info(f"[{typ}] ilerleme {page}/{page_count} - partial'a yazilan {written_total}")
        page += 1

    # Normal tamamlandi: partial'i finalize et, resume_page'i temizle
    line_count = finalize_partial(typ)
    tstate["max_id"] = max_known
    tstate["last_full_sync"] = datetime.now(timezone.utc).isoformat()
    tstate.pop("resume_page", None)
    tstate.pop("full_run_started_utc", None)
    if conn is not None:
        removed = sgb_db.mark_removed_by_cutoff(conn, typ, cutoff_utc)
        if removed:
            log.info(f"[{typ}] FULL reconcile: {removed} kayit removed_at damgalandi")
    log.info(f"[{typ}] FULL tamamlandi: {line_count} benzersiz satir, max_id={max_known}")
    return written_total


def _sync_delta(session: requests.Session, typ: str, state: dict, conn=None) -> int:
    """Delta sync: max_id'den buyuk kayitlari ceker, mevcut dosyaya ekler. Return: eklenen sayi.

    conn verilirse yeni kayitlar DB'ye de upsert edilir.
    """
    tstate = state.setdefault(typ, {"max_id": 0, "last_full_sync": None, "last_delta_sync": None})
    max_known = int(tstate.get("max_id") or 0)

    log.info(f"[{typ}] DELTA sync (max_id={max_known})")
    first = fetch_page(session, typ, 1)
    total = first.get("totalCount")
    page_count = first.get("pageCount") or 1
    tstate["total_count"] = total

    existing = read_lines(final_path(typ))
    new_records: list = []
    consecutive_known = 0
    page = 1
    recs_to_scan = first.get("models") or []

    while True:
        for rec in recs_to_scan:
            try:
                rid = int(rec.get("id"))
            except (TypeError, ValueError):
                continue
            if rid <= max_known:
                consecutive_known += 1
            else:
                consecutive_known = 0
                new_records.append(rec)
        if consecutive_known >= STOP_AFTER_KNOWN:
            log.info(f"[{typ}] page={page}'de {STOP_AFTER_KNOWN}+ bilinen - delta tamam")
            break
        page += 1
        if page > page_count or page > DELTA_MAX_PAGES:
            if page > DELTA_MAX_PAGES:
                log.warning(f"[{typ}] delta {DELTA_MAX_PAGES} sayfa siniri asildi")
            break
        time.sleep(SLEEP_OK_DELTA)
        data = fetch_page(session, typ, page)
        recs_to_scan = data.get("models") or []
        if not recs_to_scan:
            break

    added = 0
    for rec in new_records:
        try:
            rid = int(rec.get("id"))
            if rid > max_known:
                max_known = rid
        except (TypeError, ValueError):
            pass
        cleaned = clean_entry(rec.get("url") or "", typ)
        if valid_for(cleaned, typ) and cleaned not in existing:
            existing.add(cleaned)
            added += 1
    if conn is not None and new_records:
        sgb_db.upsert_indicators(conn, new_records, typ, clean_entry, valid_for)

    final_path(typ).write_text(
        "\n".join(sorted(existing)) + ("\n" if existing else ""), encoding="utf-8"
    )
    tstate["max_id"] = max_known
    tstate["last_delta_sync"] = datetime.now(timezone.utc).isoformat()
    log.info(f"[{typ}] DELTA: yeni {added} satir, toplam {len(existing)}, max_id={max_known}")
    return added


def read_lines(p: Path) -> set:
    if not p.exists():
        return set()
    return {ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()}


def write_stats(mode: str, state: dict) -> None:
    counts = {}
    for typ in TYPES:
        fp = final_path(typ)
        if fp.exists():
            counts[typ] = sum(1 for ln in fp.read_text(encoding="utf-8").splitlines() if ln.strip())
        else:
            counts[typ] = 0
    in_progress = {typ: state.get(typ, {}).get("resume_page") for typ in TYPES
                   if state.get(typ, {}).get("resume_page")}
    db_block = _db_stats_block()
    stats = {
        "last_update_utc": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "counts": counts,
        "in_progress": in_progress or None,
        "state": state,
        "db": db_block,
    }
    (DOCS_DIR / "stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    log.info(f"stats: {counts} in_progress={in_progress or 'none'} db={db_block.get('total_active') if db_block else 'n/a'}")


def _db_stats_block() -> dict | None:
    """stats.json icin DB ozetini hazirlar (varsa). Hata olursa None doner."""
    db_file = sgb_db.db_path(ROOT)
    if not db_file.exists():
        return None
    try:
        conn = sgb_db.connect(ROOT)
        try:
            per_type = sgb_db.counts_by_type(conn)
            total_active = sum(per_type.values())
            removed = conn.execute(
                "SELECT COUNT(*) FROM indicators WHERE removed_at_utc IS NOT NULL"
            ).fetchone()[0]
            by_ct = dict(
                conn.execute(
                    """
                    SELECT connectiontype, COUNT(*)
                      FROM indicators
                     WHERE removed_at_utc IS NULL AND valid = 1 AND connectiontype IS NOT NULL
                     GROUP BY connectiontype
                    """
                ).fetchall()
            )
            by_cat = dict(
                conn.execute(
                    """
                    SELECT category, COUNT(*)
                      FROM indicators
                     WHERE removed_at_utc IS NULL AND valid = 1 AND category IS NOT NULL
                     GROUP BY category
                    """
                ).fetchall()
            )
            return {
                "per_type_active": per_type,
                "total_active": total_active,
                "removed": removed,
                "by_connectiontype": by_ct,
                "by_category": by_cat,
            }
        finally:
            conn.close()
    except Exception as e:
        log.warning(f"db stats okunamadi: {e}")
        return None


def sync(mode: str) -> None:
    state = load_state()
    # Diagnostic: baslangic state'i
    log.info(f"== {mode.upper()} sync basliyor ==")
    for t in TYPES:
        ts = state.get(t, {})
        log.info(
            f"  [{t}] max_id={ts.get('max_id', 0)} resume_page={ts.get('resume_page')} "
            f"partial_exists={partial_path(t).exists()} "
            f"final_exists={final_path(t).exists()}"
        )
    session = requests.Session()
    conn = sgb_db.connect(ROOT)
    run_id = sgb_db.start_run(conn, mode)
    ok = False
    err = None
    try:
        for typ in TYPES:
            if mode == "full":
                _sync_full(session, typ, state, conn=conn)
            else:
                _sync_delta(session, typ, state, conn=conn)
            save_state(state)
        ok = True
    except Exception as e:
        err = repr(e)
        raise
    finally:
        save_state(state)
        write_stats(mode, state)
        try:
            db_counts = sgb_db.counts_by_type(conn)
            log.info(f"db counts (valid, not removed): {db_counts}")
            sgb_db.finish_run(conn, run_id, ok, counts=db_counts, error=err)
        finally:
            conn.close()


def catalog_sync() -> None:
    """3 lookup endpoint'i (category/source/connectiontype) DB'ye yazar.

    Bunlar siklikla degismez; haftalik veya release oncesi calistirmak yeter.
    """
    log.info("== CATALOG sync basliyor ==")
    session = requests.Session()
    conn = sgb_db.connect(ROOT)
    run_id = sgb_db.start_run(conn, "catalog")
    counts = {}
    ok = False
    err = None
    try:
        for kind, url in CATALOG_ENDPOINTS.items():
            r = session.get(
                url,
                timeout=TIMEOUT,
                headers={"User-Agent": UA, "Accept": "application/json"},
            )
            r.raise_for_status()
            data = r.json()
            models = data.get("models") or []
            n = sgb_db.upsert_catalog(conn, kind, models)
            counts[kind] = n
            log.info(f"[catalog:{kind}] {n} kayit yazildi")
        ok = True
    except Exception as e:
        err = repr(e)
        raise
    finally:
        sgb_db.finish_run(conn, run_id, ok, counts=counts, error=err)
        conn.close()


def loop() -> None:
    """Cron'suz container'lar icin: delta'yi LOOP_DELTA_INTERVAL'da surekli tetikler ve
    LOOP_RECONCILE_EVERY delta'da bir full reconcile calistirir (silinen kayitlari temizler).

    Ilk bootstrap iki yoldan biriyle saglanir:
      1. Imaja gomulu seed verisi (docs/ + state/ build aninda kopyalanir), veya
      2. Bir kez elle `python sync.py --mode full` calistirilmasi.
    """
    log.info(
        f"LOOP basliyor (v{__version__}) - delta her {LOOP_DELTA_INTERVAL}s, "
        f"reconcile her {LOOP_RECONCILE_EVERY} delta'da bir"
        if LOOP_RECONCILE_EVERY > 0
        else f"LOOP basliyor (v{__version__}) - delta her {LOOP_DELTA_INTERVAL}s (reconcile kapali)"
    )
    state = load_state()
    if all(int(state.get(t, {}).get("max_id") or 0) == 0 for t in TYPES):
        log.warning(
            "DIKKAT: state bos (tum max_id=0). Delta sinirli bir bootstrap yapacak "
            f"(en fazla {DELTA_MAX_PAGES} sayfa/tip). Tam gecmis veri icin once "
            "`--mode full` calistir ya da seed verili imaj kullan."
        )
    iteration = 0
    while True:
        do_reconcile = (
            LOOP_RECONCILE_EVERY > 0
            and iteration > 0
            and iteration % LOOP_RECONCILE_EVERY == 0
        )
        try:
            sync("full" if do_reconcile else "delta")
        except KeyboardInterrupt:
            log.info("KeyboardInterrupt - cikiliyor")
            return
        except Exception:
            log.exception("loop sync sirasinda hata - devam ediyor")
        iteration += 1
        log.info(f"loop: {LOOP_DELTA_INTERVAL}s uyuyor (iter={iteration})")
        try:
            time.sleep(LOOP_DELTA_INTERVAL)
        except KeyboardInterrupt:
            return


def health_check() -> int:
    stats_file = DOCS_DIR / "stats.json"
    if not stats_file.exists():
        log.error("stats.json yok")
        return 1
    stats = json.loads(stats_file.read_text(encoding="utf-8"))
    last = stats.get("last_update_utc")
    if not last:
        log.error("last_update_utc yok")
        return 1
    dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
    age_h = (datetime.now(timezone.utc) - dt).total_seconds() / 3600
    if age_h > 48:
        log.error(f"Son guncelleme {age_h:.1f} saat onceydi - 48s esigi asildi")
        return 1
    log.info(f"OK: son guncelleme {age_h:.1f} saat once")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument(
        "--mode",
        choices=["full", "delta", "loop", "healthcheck", "catalog-sync"],
        required=True,
    )
    args = p.parse_args()
    if args.mode == "healthcheck":
        sys.exit(health_check())
    if args.mode == "loop":
        loop()
    elif args.mode == "catalog-sync":
        catalog_sync()
    else:
        sync(args.mode)
