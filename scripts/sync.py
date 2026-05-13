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
SLEEP_OK_FULL = 0.6
SLEEP_OK_DELTA = 1.0
SLEEP_429_BASE = 10.0
MAX_RETRIES = 5
TIMEOUT = 30
UA = "usom-bridge/1.0 (+https://github.com/sinansh/usom-bridge)"
STOP_AFTER_KNOWN = 40
DELTA_MAX_PAGES = 200

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


def sync_type(session: requests.Session, typ: str, mode: str, state: dict) -> list:
    """Bir tip icin sync yapar; yeni kayitlarin listesini doner."""
    tstate = state.setdefault(typ, {"max_id": 0, "last_full_sync": None, "last_delta_sync": None})
    max_known = int(tstate.get("max_id") or 0)
    new_records: list = []
    sleep_dur = SLEEP_OK_FULL if mode == "full" else SLEEP_OK_DELTA

    log.info(f"[{typ}] {mode.upper()} sync basliyor (max_id={max_known})")

    first = fetch_page(session, typ, 1)
    total = first.get("totalCount")
    page_count = first.get("pageCount") or 1
    records = first.get("models") or []
    log.info(f"[{typ}] totalCount={total} pageCount={page_count}")

    if mode == "full":
        new_records.extend(records)
        page = 2
        while page <= page_count:
            time.sleep(sleep_dur)
            data = fetch_page(session, typ, page)
            recs = data.get("models") or []
            if not recs:
                log.info(f"[{typ}] page={page} bos - bitti")
                break
            new_records.extend(recs)
            if page % 200 == 0:
                log.info(f"[{typ}] ilerleme {page}/{page_count} - toplam {len(new_records)}")
            page += 1
    else:  # delta
        consecutive_known = 0
        page = 1
        recs_to_scan = records
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
                log.info(f"[{typ}] page={page}'de {STOP_AFTER_KNOWN}+ bilinen kayit - delta tamam")
                break
            page += 1
            if page > page_count or page > DELTA_MAX_PAGES:
                if page > DELTA_MAX_PAGES:
                    log.warning(f"[{typ}] delta {DELTA_MAX_PAGES} sayfa siniri asildi")
                break
            time.sleep(sleep_dur)
            data = fetch_page(session, typ, page)
            recs_to_scan = data.get("models") or []
            if not recs_to_scan:
                break

    # max_id'yi guncelle
    for rec in new_records:
        try:
            rid = int(rec.get("id"))
            if rid > max_known:
                max_known = rid
        except (TypeError, ValueError):
            pass
    tstate["max_id"] = max_known
    tstate[f"last_{mode}_sync"] = datetime.now(timezone.utc).isoformat()
    tstate["total_count"] = total

    log.info(f"[{typ}] yeni kayit: {len(new_records)}, yeni max_id={max_known}")
    return new_records


def read_lines(p: Path) -> set:
    if not p.exists():
        return set()
    return {ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()}


def write_outputs(by_type: dict, mode: str, state: dict) -> None:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    files = {
        "domain": DOCS_DIR / "domain-list.txt",
        "url": DOCS_DIR / "url-list.txt",
        "ip": DOCS_DIR / "ip-list.txt",
        "ip6": DOCS_DIR / "ip6-list.txt",
        "ip6net": DOCS_DIR / "ip6net-list.txt",
    }
    counts = {}
    rejected = {}

    for typ, path in files.items():
        new_recs = by_type.get(typ, [])
        existing = set() if mode == "full" else read_lines(path)
        skipped = 0
        for rec in new_recs:
            raw = rec.get("url") or ""
            cleaned = clean_entry(raw, typ)
            if valid_for(cleaned, typ):
                existing.add(cleaned)
            else:
                skipped += 1
        path.write_text("\n".join(sorted(existing)) + ("\n" if existing else ""), encoding="utf-8")
        counts[typ] = len(existing)
        rejected[typ] = skipped

    stats = {
        "last_update_utc": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "counts": counts,
        "rejected_this_run": rejected,
        "state": state,
    }
    (DOCS_DIR / "stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    log.info(f"Output: {counts} (gecersiz atilan: {rejected})")


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
    by_type = {}
    for typ in TYPES:
        by_type[typ] = sync_type(session, typ, mode, state)
    write_outputs(by_type, mode, state)
    save_state(state)
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
