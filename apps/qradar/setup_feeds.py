#!/usr/bin/env python3
"""
QRadar SGB kurulum otomasyonu — TAXII feed'leri + reference set'ler.

Lab/uretim QRadar'inda iki seyi REST ile kurar (content extension'a
gomulemedikleri icin):

  1. Threat Intelligence app'ine 8 SGB TAXII 2.1 feed'i
     (POST /api/threat_intelligence/feeds — TI app v3+/QRadar 7.5 endpoint'i;
     TI app surumune gore alan adlari degisebilir, --dry-run ile payload'u
     gorup gerekirse FEED_PAYLOAD_TEMPLATE'i uyarlayin)
  2. UC rule response'larinin kullandigi operasyonel/exception reference
     set'leri (POST /api/reference_data/sets)

Kullanim:
  python setup_feeds.py --host qradar.lab.local --token $env:QRADAR_TOKEN --dry-run
  python setup_feeds.py --host qradar.lab.local --token ... --insecure
  python setup_feeds.py ... --skip-feeds          # yalniz reference set'ler
  python setup_feeds.py ... --skip-refsets        # yalniz feed'ler
  python setup_feeds.py ... --taxii-base https://sgb-taxii.kurum.local

Idempotent: var olan feed/set atlanir. Yalniz stdlib kullanir.
"""
import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TAXII_BASE = "https://sgb-taxii.bilsec.tr"
API_VERSION = "19.0"  # QRadar 7.5 UP7+; eski UP'lerde dusurun

# (feed adi, collection alias) — docs/integrations/qradar.md Adim 1 tablosu
FEEDS = [
    ("SGB-Phishing", "sgb-phishing"),
    ("SGB-Botnet-CC", "sgb-botnet-cc"),
    ("SGB-APT-CC", "sgb-apt-cc"),
    ("SGB-Exploit-Kit", "sgb-exploit-kit"),
    ("SGB-Malware-Download", "sgb-malware-download"),
    ("SGB-Mining", "sgb-mining"),
    ("SGB-Mobile-CC", "sgb-mobile-cc"),
    ("SGB-Other", "sgb-other"),
]

# UC rule response'larinin yazdigi / okudugu set'ler (docs/usecases/*).
# TTL'ler UI'dan ayarlanir (or. SGB_SUSPECTED_HOSTS = 7 gun, UC-PH-001).
REFERENCE_SETS = [
    ("SGB_SUSPECTED_HOSTS", "IP"),       # UC-PH-001/002 response
    ("SGB_INFECTED_HOSTS", "IP"),        # UC-BC-002 response
    ("SGB_EXPLOITED_HOSTS", "IP"),       # UC-EK-001 response
    ("SGB_DOWNLOADED_MALWARE", "IP"),    # UC-MF-001 response
    ("SGB_MINING_HOSTS", "IP"),          # UC-MM-001 response
    ("SGB_MC_DEVICES", "ALN"),           # UC-MC-001 response
    ("SGB_PHISH_TARGETS", "ALN"),        # UC-PH-003 response
    ("SGB_CANDIDATE_IOC", "ALN"),        # UC-BC-004 response (SGB geri bildirim)
    ("SGB_PH_EXEMPT_ASSETS", "IP"),      # exception listeleri
    ("SGB_BC_EXEMPT_ASSETS", "IP"),
    ("SGB_AC_EXEMPT_ASSETS", "IP"),
    ("SGB_PHISH_SIM_DOMAINS", "ALN"),    # UC-PH-003 simulasyon beyaz listesi
]

FEED_PAYLOAD_TEMPLATE = {
    "name": None,
    "type": "TAXII_2_1",
    "discovery_url": None,   # {taxii_base}/taxii2/
    "collection_id": None,   # alias
    "poll_interval_minutes": 60,
}


def api(host, token, method, path, payload=None, params=None, insecure=False):
    url = f"https://{host}/api{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {
        "SEC": token,
        "Version": API_VERSION,
        "Accept": "application/json",
    }
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    ctx = ssl._create_unverified_context() if insecure else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8") or "null")


def setup_feeds(args):
    discovery_url = args.taxii_base.rstrip("/") + "/taxii2/"
    existing_names = set()
    if not args.dry_run:
        status, existing = api(args.host, args.token, "GET", "/threat_intelligence/feeds",
                               insecure=args.insecure)
        if status != 200:
            print(f"UYARI: feed listesi alinamadi (HTTP {status}): {existing}")
            print("Threat Intelligence app kurulu mu? Endpoint TI app surumune gore degisebilir.")
            existing = []
        existing_names = {f.get("name") for f in (existing or [])}

    for name, collection in FEEDS:
        payload = dict(FEED_PAYLOAD_TEMPLATE,
                       name=name, discovery_url=discovery_url, collection_id=collection)
        if name in existing_names:
            print(f"SKIP feed {name} (zaten var)")
            continue
        if args.dry_run:
            print(f"DRY  POST /threat_intelligence/feeds {json.dumps(payload)}")
            continue
        status, body = api(args.host, args.token, "POST", "/threat_intelligence/feeds",
                           payload=payload, insecure=args.insecure)
        ok = "OK  " if status in (200, 201) else f"HATA(HTTP {status}) "
        print(f"{ok} feed {name}: {body if status not in (200, 201) else 'olusturuldu'}")


def setup_refsets(args):
    for name, element_type in REFERENCE_SETS:
        params = {"name": name, "element_type": element_type}
        if args.dry_run:
            print(f"DRY  POST /reference_data/sets {params}")
            continue
        status, _ = api(args.host, args.token, "GET",
                        f"/reference_data/sets/{urllib.parse.quote(name)}",
                        insecure=args.insecure)
        if status == 200:
            print(f"SKIP refset {name} (zaten var)")
            continue
        status, body = api(args.host, args.token, "POST", "/reference_data/sets",
                           params=params, insecure=args.insecure)
        ok = "OK  " if status in (200, 201) else f"HATA(HTTP {status}) "
        print(f"{ok} refset {name} ({element_type})")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", required=True, help="QRadar console host adi/IP")
    p.add_argument("--token", default=os.environ.get("QRADAR_TOKEN"),
                   help="Authorized service token (SEC); default: QRADAR_TOKEN env")
    p.add_argument("--taxii-base", default=DEFAULT_TAXII_BASE,
                   help=f"TAXII base URL (default: {DEFAULT_TAXII_BASE}; self-hosted icin degistirin)")
    p.add_argument("--insecure", action="store_true",
                   help="TLS sertifika dogrulamasini atla (yalniz lab self-signed icin)")
    p.add_argument("--dry-run", action="store_true", help="istekleri yazdir, gonderme")
    p.add_argument("--skip-feeds", action="store_true")
    p.add_argument("--skip-refsets", action="store_true")
    args = p.parse_args()

    if not args.token and not args.dry_run:
        p.error("--token veya QRADAR_TOKEN env gerekli")
    if args.insecure:
        print("UYARI: TLS dogrulama kapali — yalniz lab ortaminda kullanin.\n")

    if not args.skip_feeds:
        setup_feeds(args)
    if not args.skip_refsets:
        setup_refsets(args)
    print("\nSonraki adim: kurallari rule-sheet.md sirasiyla lab UI'da olusturun, "
          "sonra CMT ile export edin (README.md).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
