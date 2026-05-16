# Entegrasyon: Diğer Ürünler (Generic STIX 2.1 + CSV/JSONL)

> **Hedef:** STIX 2.1 / TAXII destekleyen veya CSV/JSONL'i tüketebilen
> herhangi bir SIEM/XDR/EDR/SOAR için generic ingest rehberi.

**Tüketilen artifact:** İhtiyaca göre:

- `feeds/stix/sgb-*.stix2.json` — STIX 2.1 bundle
- `feeds/sgb-master.csv` / `sgb-master.jsonl` — kanonik tablo
- `feeds/by-connectiontype/*.txt` — basit text slice'lar

## BG Rehberi karşılığı

| Madde | Madde adı | Bu entegrasyon nasıl karşılar? |
|-------|-----------|--------------------------------|
| **3.1.5.1** ⭐ | Zararlı Yazılımdan Korunma + Merkezi Yönetim | EDR/XDR'a SGB IoC besleme = "imza/IoC veri tabanını güncel tut" |
| **3.1.10.4** ⭐ | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB feed'in operasyonel ürünlere taşınması |
| **3.1.6.4** | Kara Liste Kullanımı | Suricata/Wazuh text slice = kara liste |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Elastic / Securonix / Exabeam — alternatif SIEM'ler |

## Hedef sistem matrisi

| Sistem | Önerilen artifact | Method | Birincil BG madde |
|--------|---------------------|--------|-------------------|
| **CrowdStrike Falcon** | CSV master | Indicator Upload API (`/iocs/entities/indicators/v1`) | 3.1.5.1 |
| **Microsoft Defender XDR** | STIX bundle | TI Upload API (Graph) — Sentinel ile aynı | 3.1.5.1 |
| **Palo Alto Cortex XSOAR** | STIX bundle | Built-in "Generic STIX Feed" integration | 3.1.10.4 |
| **Trellix XDR (eski FireEye)** | STIX bundle | TAXII 2.1 client (server kurarsak) | 3.1.10.4 |
| **Elastic Security** | CSV/JSONL | Threat Intelligence filebeat module | 3.1.8.7 |
| **Wazuh** | text slice | Active Response + CDB list | 3.1.6.4 |
| **Securonix / Exabeam UEBA** | CSV | Watchlist / Threat Intel import | 3.1.8.7 |
| **OPNsense / pfSense** | text slice | pfBlockerNG (zaten ana sayfada) | 3.1.6.4 |
| **Suricata / Snort** | text slice | rule files / IPONLY ruleset | 3.1.6.18 |

## Pattern: CSV-based ingest (Falcon, Securonix, Exabeam, Elastic vb.)

Master CSV şeması:

```
id,type,value,description,connectiontype,source,criticality_level,api_date,first_seen_utc,last_seen_utc
```

CrowdStrike Falcon örneği (PSFalcon):

```powershell
Import-Module PSFalcon
Request-FalconToken -ClientId $env:CSID -ClientSecret $env:CSSEC

Import-Csv feeds/sgb-master.csv | ForEach-Object {
  $type = switch ($_.type) {
    'ip'     { 'ipv4' }
    'ip6'    { 'ipv6' }
    'domain' { 'domain' }
    'url'    { 'url' }
  }
  if (-not $type) { return }
  New-FalconIoc -Type $type -Value $_.value `
    -Action 'detect' -Severity (if ([int]$_.criticality_level -ge 8) {'high'} else {'medium'}) `
    -Description "SGB $($_.connectiontype) ($($_.description))" `
    -Source 'SGB' -Tags @("sgb:$($_.connectiontype.ToLower())")
}
```

## Pattern: STIX 2.1 bundle ingest (Defender XDR, Cortex XSOAR, vb.)

Cortex XSOAR'da:

1. **Settings > Integrations** > "Generic STIX Feed"
2. URL: `https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-domain.stix2.json` (her tip için ayrı instance)
3. Fetch interval: 60 dakika
4. Indicator types map:
   - `domain-name` → `Domain`
   - `ipv4-addr` → `IP`
   - `ipv6-addr` → `IPv6`
   - `url` → `URL`
5. Default reputation: Malicious
6. Run → Indicators sekmesinde SGB indicator'lar görülür

## Pattern: TAXII 2.1 (server kurarsak)

Henüz aktif değil. Roadmap'te `medallion` veya OASIS reference TAXII server
ile `feeds/stix/*` collection'larını yayınlamak var. Etkinleştiğinde URL:

```
https://taxii.bilsectr.github.io/api/v21/collections/sgb-{type}/objects/
```

## Pattern: Text slice (Suricata, Wazuh CDB)

```bash
# Suricata IP-only ruleset - Release tarball'ından tek dosya çek
curl -sLO https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-feeds.tar.gz
tar -xzf sgb-feeds.tar.gz feeds/by-connectiontype/bc-ip.txt \
  -O > /etc/suricata/rules/sgb-bc-ip.txt
rm sgb-feeds.tar.gz

# Suricata ip-only rules (her satıra drop kuralı oluşturur)
awk '{print "drop ip any any -> "$1" any (msg:\"SGB Botnet C2\"; sid:9000001+NR;)"}' \
  /etc/suricata/rules/sgb-bc-ip.txt > /etc/suricata/rules/sgb-bc-ip.rules

systemctl reload suricata
```

Wazuh CDB list (özellik: O(log n) lookup):

```bash
curl -sf .../feeds/by-connectiontype/ph-domain.txt \
  | awk '{print $1":sgb_phishing"}' > /var/ossec/etc/lists/sgb_phishing.txt

# Wazuh API ile reload
/var/ossec/bin/wazuh-control reload
```

## Pattern: Webhook / SOAR enrichment

Generic enrichment endpoint pattern'i:

```python
# SOAR/n8n/Zapier/Power Automate'te HTTP node
def is_sgb_indicator(value, typ):
    """Lokalde indir, tek-lookup performanslı kullan."""
    if not hasattr(is_sgb_indicator, "cache"):
        is_sgb_indicator.cache = {
            "ip": set(open("feeds/by-connectiontype/bc-ip.txt").read().split()),
            "domain": set(open("feeds/by-connectiontype/ph-domain.txt").read().split()),
            "url": set(open("feeds/by-connectiontype/ph-url.txt").read().split()),
        }
    return value in is_sgb_indicator.cache.get(typ, set())
```

## Veri tazeliği (her sistem için)

| Sistem | Önerilen refresh | Yöntem |
|--------|------|----------|
| Falcon, Defender, XSOAR | 1-6 saat | API push (cron / scheduled task) |
| Suricata, Wazuh | 1 saat | curl + reload |
| SOAR | her use'da local cache + 1h TTL | python decorator |

## Manifest doğrulaması

Her sync sonrası `feeds/index.json` güncellenir:

```json
{
  "generated_utc": "...",
  "files": [
    { "path": "stix/sgb-domain.stix2.json", "sha256": "...", "size_bytes": ... }
  ]
}
```

Air-gapped ortamlarda SHA256 ile bundle integrity doğrulaması (BG **3.1.8.4**
"detaylı kayıt + bütünlüğü zaman damgası ile korunmalı" maddesine paralel):

```bash
EXPECTED=$(curl -sf https://.../feeds/index.json | jq -r '.files[] | select(.path=="stix/sgb-domain.stix2.json").sha256')
ACTUAL=$(sha256sum local-sgb-domain.stix2.json | awk '{print $1}')
[ "$EXPECTED" = "$ACTUAL" ] && echo OK || echo MISMATCH
```
