#!/usr/bin/env python3
"""
USOM Bridge - USOM API'sini duz metin feed'e donusturur.

Modlar:
    --mode full         : Tum tipler icin tum sayfalari ceker (~4 saat). Haftalik refresh.
    --mode delta        : Tum tipler icin yalniz yeni kayitlari ceker (~1-3 dk). Saatlik.
    --mode healthcheck  : stats.json fresh mi diye bakar (delta workflow'da kullaniliyor).

API:
    GET https://www.usom.gov.tr/api/address/index?type={domain|url|ip}&page=N
    Response: {"totalCount": N, "count": 20, "models": [...], "page": P, "pageCount": M}
    Kayitlar tarihe gore newest-first siralanmis durumda.
    ID'ler tum tipler arasinda global ve monoton artan.
"""
import argparse
import json
import logging
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

API_URL = "https://www.usom.gov.tr/api/address/index"
TYPES = ("domain", "url", "ip", "ip6", "ip6net")
SLEEP_OK_FULL = 1.0
SLEEP_OK_DELTA = 1.0
SLEEP_429_BASE = 15.0
MAX_RETRIES = 6
TIMEOUT = 30
UA = "usom-bridge/1.0 (+https://github.com/sinansh/usom-bridge)"
STOP_AFTER_KNOWN = 40
DELTA_MAX_PAGES = 200
CHECKPOINT_EVERY = 25  # full sync: kac sayfada bir state'i diske yaz

ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
STATE_FILE = ROOT / "state" / "seen_ids.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("usom")


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log.warning("State JSON parse edilemedi - sifirdan basliyoruz")
    return {t: {"max_id": 0, "last_full_sync": None, "last_delta_sync": None} for t in TYPES}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def fetch_page(session: requests.Session, typ: str, page: int) -> dict:
    delay = SLEEP_429_BASE
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = session.get(
                API_URL,
                params={"type": typ, "page": page},
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


def append_to_partial(typ: str, records: list) -> tuple:
    """Records'lari partial dosyaya yazar; (yazilan, atilan, max_id) doner."""
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


def _sync_full(session: requests.Session, typ: str, state: dict) -> int:
    """Full sync: resume-capable. Return: bu run'da yazilan satir sayisi (partial'a)."""
    tstate = state.setdefault(typ, {"max_id": 0, "last_full_sync": None, "last_delta_sync": None})
    resume_page = int(tstate.get("resume_page") or 0)
    max_known = int(tstate.get("max_id") or 0)

    # Resume_page yoksa fresh start: partial varsa sil
    if resume_page <= 0 and partial_path(typ).exists():
        log.info(f"[{typ}] eski partial bulundu, fresh start oncesi siliniyor")
        partial_path(typ).unlink()

    first = fetch_page(session, typ, 1)
    total = first.get("totalCount")
    page_count = first.get("pageCount") or 1
    tstate["total_count"] = total
    log.info(f"[{typ}] FULL totalCount={total} pageCount={page_count} resume_from={resume_page or 1}")

    written_total = 0

    if resume_page <= 1:
        w, s, mid = append_to_partial(typ, first.get("models") or [])
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
        w, s, mid = append_to_partial(typ, recs)
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
    log.info(f"[{typ}] FULL tamamlandi: {line_count} benzersiz satir, max_id={max_known}")
    return written_total


def _sync_delta(session: requests.Session, typ: str, state: dict) -> int:
    """Delta sync: max_id'den buyuk kayitlari ceker, mevcut dosyaya ekler. Return: eklenen sayi."""
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
    stats = {
        "last_update_utc": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "counts": counts,
        "in_progress": in_progress or None,
        "state": state,
    }
    (DOCS_DIR / "stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    log.info(f"stats: {counts} in_progress={in_progress or 'none'}")


def write_badge(state: dict) -> None:
    # En son sync (herhangi bir tipin son delta'si) zamanini al
    candidates = []
    for typ in TYPES:
        for k in ("last_delta_sync", "last_full_sync"):
            v = state.get(typ, {}).get(k)
            if v:
                candidates.append(v)
    if not candidates:
        badge = {"schemaVersion": 1, "label": "last sync", "message": "never", "color": "lightgrey"}
    else:
        last = max(candidates)
        dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
        mins = int((datetime.now(timezone.utc) - dt).total_seconds() // 60)
        if mins < 60:
            msg = f"{mins}m ago"
        elif mins < 60 * 48:
            msg = f"{mins // 60}h ago"
        else:
            msg = f"{mins // (60 * 24)}d ago"
        color = "brightgreen" if mins < 180 else ("yellow" if mins < 60 * 48 else "red")
        badge = {"schemaVersion": 1, "label": "last sync", "message": msg, "color": color}
    (DOCS_DIR / "badge.json").write_text(json.dumps(badge), encoding="utf-8")


def sync(mode: str) -> None:
    state = load_state()
    session = requests.Session()
    try:
        for typ in TYPES:
            if mode == "full":
                _sync_full(session, typ, state)
            else:
                _sync_delta(session, typ, state)
            save_state(state)
    finally:
        save_state(state)
        write_stats(mode, state)
        write_badge(state)


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
    p.add_argument("--mode", choices=["full", "delta", "healthcheck"], required=True)
    args = p.parse_args()
    if args.mode == "healthcheck":
        sys.exit(health_check())
    sync(args.mode)
