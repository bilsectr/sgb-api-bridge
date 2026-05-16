# Entegrasyon: MISP

**Hedef:** SGB STIX 2.1 bundle'larini MISP'e otomatik ingest et; her saatlik
delta'da fresh kal.

**Tuketilen artifact:** `feeds/stix/sgb-{domain,url,ip,ip6,ip6net}.stix2.json`

## On kosullar

- MISP 2.4.150+ (STIX 2.1 importer)
- Admin yetkisi (Feed olusturma + sync)
- MISP host'undan SGB STIX URL'lerine HTTP(S) erisim
  (GitHub Release public host edilirse direkt; ic ortamda internal mirror)

## URL formati (onemli)

STIX bundle'lari **GitHub Release** uzerinden yayinlanir; her sync sonrasi
GitHub Pages'a commit edilmez (~150MB bundle, repo bloat olmasin diye).
Kalici "latest" URL'leri:

```
https://github.com/bilsectr/sgb-api-bridge/releases/latest/download/sgb-domain.stix2.json
https://github.com/bilsectr/sgb-api-bridge/releases/latest/download/sgb-url.stix2.json
https://github.com/bilsectr/sgb-api-bridge/releases/latest/download/sgb-ip.stix2.json
```

(Versiyon kilitlemek: `releases/download/v<X.Y.Z>/sgb-domain.stix2.json`)

## Yontem A — Feed olarak ekle (onerilen)

MISP'in **Feeds** ozelligi STIX URL'lerinden periyodik ingest yapar.

### Adim 1 — Feed olustur

UI: **Sync Actions > List Feeds > Add Feed**

| Alan | Deger |
|------|-------|
| Enabled | ✓ |
| Caching enabled | ✓ |
| Name | SGB STIX 2.1 — Domain |
| Provider | Siber Guvenlik Baskanligi |
| URL | `https://github.com/bilsectr/sgb-api-bridge/releases/latest/download/sgb-domain.stix2.json` |
| Source format | STIX 2.x JSON |
| Default tag | `tlp:white`, `sgb:domain` |
| Lookup visible | ✓ |
| Publish | Off (manuel onayla) |

Ayni adimi her tip icin tekrarla (domain/url/ip/ip6/ip6net) — 5 feed.

CLI / API esdegeri:

```bash
curl -k -X POST "https://$MISP/feeds/add" \
  -H "Authorization: $MISP_KEY" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"Feed": {
    "name": "SGB STIX 2.1 - Domain",
    "provider": "SGB",
    "url": "https://github.com/bilsectr/sgb-api-bridge/releases/latest/download/sgb-domain.stix2.json",
    "enabled": true,
    "source_format": "stix",
    "input_source": "network",
    "default": false,
    "publish": false
  }}'
```

### Adim 2 — Ilk fetch'i tetikle

```bash
# UI: Sync Actions > List Feeds > [SGB STIX 2.1 - Domain] > Fetch all events
# CLI:
sudo -u www-data /var/www/MISP/app/Console/cake Server fetchFeed 1 1
```

### Adim 3 — Dogrula

UI: **Events > List Events** -> "SGB" tag ile filtreyle. Her tip icin bir
event olusur, indicator'lar attribute olarak listelenir.

### Adim 4 — Otomatik refresh

MISP scheduler: **Administration > Scheduled Tasks > fetch_feeds**
- Default 24 saat; SGB delta'larina paralel olarak 1 saate cekin.

## Yontem B — Manuel PyMISP script (air-gapped ortam)

MISP'in feed URL'lerine direkt erisemediği ortamlarda dosyayi indir,
PyMISP ile bulk add yap.

```python
# scripts/contrib/push_to_misp.py (commit'li degil, ornek)
from pymisp import PyMISP, MISPEvent
import json, sys

misp = PyMISP("https://misp.kurum.local", "API_KEY", ssl=False)

for typ in ("domain", "url", "ip", "ip6", "ip6net"):
    bundle = json.load(open(f"feeds/stix/sgb-{typ}.stix2.json"))
    ev = MISPEvent()
    ev.info = f"SGB STIX 2.1 — {typ}"
    ev.distribution = 0  # your org only
    ev.threat_level_id = 2
    ev.add_tag("source:sgb")
    ev.add_tag(f"sgb:{typ}")
    for obj in bundle["objects"]:
        if obj.get("type") != "indicator":
            continue
        attr_type = {
            "domain": "domain",
            "url": "url",
            "ip": "ip-dst",
            "ip6": "ip-dst",
            "ip6net": "ip-dst",
        }[typ]
        ev.add_attribute(attr_type, obj["x_sgb_value"], to_ids=True,
                         comment=f"CT={obj['x_sgb_connectiontype']} "
                                 f"CRIT={obj['x_sgb_criticality']} "
                                 f"SRC={obj['x_sgb_source']}")
    misp.add_event(ev, pythonify=True)
```

## Yontem C — TAXII 2.1 (gelecek)

MISP TAXII server eklentisi (`misp-taxii-server`) varsa STIX bundle'larimizi
TAXII collection olarak da yayinlayabiliriz. **Henuz uygulanmadi**; ihtiyaca
gore eklenecek (issue ac).

## Tag stratejisi

| Tag | Anlam | Otomatik |
|------|-------|----------|
| `source:sgb` | Tum SGB indicator'lari | Evet |
| `sgb:domain` / `sgb:url` / `sgb:ip` | Tip | Evet |
| `sgb:ct:PH` / `sgb:ct:BC` ... | Connectiontype | Manuel (script ile) |
| `sgb:src:US` / `sgb:src:IH` ... | Kaynak guvenilirligi | Manuel |
| `tlp:white` | Public veri | Evet |

## Sync to other MISP instances

Eger MISP'iniz SGB feed'ini diger MISP'lere yayinliyorsa:
- **Distribution: This community** (yalniz kendi sync grubuna)
- Veya **All communities** (TLP:WHITE ise uygun)

## Troubleshooting

| Belirti | Sebep | Cozum |
|---------|-------|-------|
| Feed fetch hata: invalid STIX | Bundle 2.0 vs 2.1 uyumsuzluk | bundle `spec_version` "2.1" oldugundan emin ol; MISP 2.4.150+ kullan |
| Indicator yok, sadece identity event'inde | STIX parser bypass | MISP log: `/var/www/MISP/app/tmp/logs/error.log` |
| Duplicate event her fetch'te | Feed dedup off | "Caching enabled" + "Lookup visible" ikisini de ac |
