# Entegrasyon: MISP

> **Hedef:** SGB STIX 2.1 bundle'larını MISP'e otomatik ingest et; her
> saatlik delta'da taze kal.

**Tüketilen artifact:**
`feeds/stix/sgb-{domain,url,ip,ip6,ip6net}.stix2.json`

## BG Rehberi karşılığı

| Madde | Madde adı | Bu entegrasyon nasıl karşılar? |
|-------|-----------|--------------------------------|
| **3.1.10.4** ⭐ | Siber Tehdit Bildirimlerinin Yönetilmesi | MISP = TI yönetim hub'ı; SGB feed bu hub'a otomatik akıyor. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | MISP indicator'ları SIEM'e push edilebilir. |
| **3.1.5.1** | Zararlı Yazılımdan Korunma + Merkezi Yönetim | MISP merkezi IoC veri tabanıdır. |

MISP genelde **SIEM beslemeyen, başka TI kaynaklarıyla korelasyon kuran**
bir hub olarak konumlandırılır. SGB feed'i + diğer TI kaynakları + iç
research = zenginleştirilmiş gözlem havuzu.

## Ön koşullar

- MISP 2.4.150+ (STIX 2.1 importer)
- Admin yetkisi (Feed oluşturma + sync)
- MISP host'undan SGB STIX URL'lerine HTTP(S) erişimi
  (GitHub Release public host edilirse direkt; iç ortamda internal mirror)

## URL formatı (önemli)

STIX bundle'ları **GitHub Release** üzerinden yayınlanır; her sync sonrası
GitHub Pages'a commit edilmez (~150MB bundle, repo bloat olmasın diye).
Kalıcı "latest" URL'leri:

```
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-domain.stix2.json
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-url.stix2.json
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-ip.stix2.json
```

(Versiyon kilitlemek: `releases/download/v<X.Y.Z>/sgb-domain.stix2.json`)

## Yöntem A — Feed olarak ekle (önerilen)

MISP'in **Feeds** özelliği STIX URL'lerinden periyodik ingest yapar.

### Adım 1 — Feed oluştur

UI: **Sync Actions > List Feeds > Add Feed**

| Alan | Değer |
|------|-------|
| Enabled | ✓ |
| Caching enabled | ✓ |
| Name | SGB STIX 2.1 — Domain |
| Provider | Siber Güvenlik Başkanlığı |
| URL | `https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-domain.stix2.json` |
| Source format | STIX 2.x JSON |
| Default tag | `tlp:white`, `sgb:domain` |
| Lookup visible | ✓ |
| Publish | Off (manuel onayla) |

Aynı adımı her tip için tekrarla (domain/url/ip/ip6/ip6net) — 5 feed.

CLI / API eşdeğeri:

```bash
curl -k -X POST "https://$MISP/feeds/add" \
  -H "Authorization: $MISP_KEY" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"Feed": {
    "name": "SGB STIX 2.1 - Domain",
    "provider": "SGB",
    "url": "https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-domain.stix2.json",
    "enabled": true,
    "source_format": "stix",
    "input_source": "network",
    "default": false,
    "publish": false
  }}'
```

### Adım 2 — İlk fetch'i tetikle

```bash
# UI: Sync Actions > List Feeds > [SGB STIX 2.1 - Domain] > Fetch all events
# CLI:
sudo -u www-data /var/www/MISP/app/Console/cake Server fetchFeed 1 1
```

### Adım 3 — Doğrula

UI: **Events > List Events** → "SGB" tag ile filtrele. Her tip için bir
event oluşur, indicator'lar attribute olarak listelenir.

### Adım 4 — Otomatik refresh

MISP scheduler: **Administration > Scheduled Tasks > fetch_feeds**

- Default 24 saat; SGB delta'larına paralel olarak **1 saate çekin**.

## Yöntem B — Manuel PyMISP script (air-gapped ortam)

MISP'in feed URL'lerine direkt erişemediği ortamlarda dosyayı indir,
PyMISP ile bulk add yap.

```python
# scripts/contrib/push_to_misp.py (commit'li değil, örnek)
from pymisp import PyMISP, MISPEvent
import json

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
            "domain": "domain", "url": "url",
            "ip": "ip-dst", "ip6": "ip-dst", "ip6net": "ip-dst",
        }[typ]
        ev.add_attribute(attr_type, obj["x_sgb_value"], to_ids=True,
                         comment=f"CT={obj['x_sgb_connectiontype']} "
                                 f"CRIT={obj['x_sgb_criticality']} "
                                 f"SRC={obj['x_sgb_source']}")
    misp.add_event(ev, pythonify=True)
```

## Yöntem C — TAXII 2.1 (gelecek)

MISP TAXII server eklentisi (`misp-taxii-server`) varsa STIX bundle'larımızı
TAXII collection olarak da yayınlayabiliriz. **Henüz uygulanmadı**; ihtiyaca
göre eklenecek (issue açın).

## Tag stratejisi

| Tag | Anlam | Otomatik |
|------|-------|----------|
| `source:sgb` | Tüm SGB indicator'ları | Evet |
| `sgb:domain` / `sgb:url` / `sgb:ip` | Tip | Evet |
| `sgb:ct:PH` / `sgb:ct:BC` ... | Connectiontype | Manuel (script ile) |
| `sgb:src:US` / `sgb:src:IH` ... | Kaynak güvenilirliği | Manuel |
| `tlp:white` | Public veri | Evet |

## Sync to other MISP instances

Eğer MISP'iniz SGB feed'ini diğer MISP'lere yayınlıyorsa:

- **Distribution: This community** (yalnız kendi sync grubuna)
- Veya **All communities** (TLP:WHITE ise uygun)

## BG raporlama için kullanım

MISP'i SGB feed'i + iç research + diğer TI kaynaklarının birleştiği yer
yaparsanız, BG Rehberi **3.1.10.5** kapsamında üretmeniz gereken siber
olay raporlarına aşağıdaki bilgileri kolayca dahil edebilirsiniz:

- Indicator hangi kampanyaya / hangi APT grubuna bağlı (MISP galaxy)
- Aynı indicator başka kuruluşlarda görüldü mü (MISP sharing communities)
- IoC yaşam döngüsü (ilk görülme, son görülme)

## Troubleshooting

| Belirti | Sebep | Çözüm |
|---------|-------|-------|
| Feed fetch hata: invalid STIX | Bundle 2.0 vs 2.1 uyumsuzluk | bundle `spec_version` "2.1" olduğundan emin ol; MISP 2.4.150+ kullan |
| Indicator yok, sadece identity event'inde | STIX parser bypass | MISP log: `/var/www/MISP/app/tmp/logs/error.log` |
| Duplicate event her fetch'te | Feed dedup off | "Caching enabled" + "Lookup visible" ikisini de aç |
