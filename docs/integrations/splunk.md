# Entegrasyon: Splunk Enterprise / Cloud

> **Hedef:** `TA-sgb-threatintel` app'i kurulsun; `src_ip`, `dest_ip`,
> `query`, `url` alanları otomatik zenginleştirilsin; 3 başlangıç alarm
> aktif; dashboard görüntülensin.

**Tüketilen artifact:** `siem/splunk/out/TA-sgb-threatintel.tar.gz`

## BG Rehberi karşılığı

| Madde | Madde adı | Bu entegrasyon nasıl karşılar? |
|-------|-----------|--------------------------------|
| **3.1.8.6** | Merkezi Kayıt Yönetimi | Splunk merkezi log platformudur. |
| **3.1.8.7** ⭐ | Kayıt Analizi Araçları (SIEM) | TA + saved searches = SIEM korelasyon. |
| **3.1.8.8** | SIEM Düzenli Yapılandırma | Saatlik lookup refresh + FP tuning. |
| **3.1.10.4** ⭐ | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB feed → Splunk lookup. |
| **3.1.5.1** | Zararlı Yazılımdan Korunma | Lookup tabanlı zararlı IoC eşleştirme. |

## Ön koşullar

- Splunk Enterprise 8.x / 9.x veya Splunk Cloud (Victoria/Classic)
- Admin yetkisi (`admin` veya `sc_admin` role)
- Search heads + indexer'larda app deploy izni
- Python 3.10+ (builder host'unda)

## Adım 1 — TA paketini üret

```bash
python scripts/sync.py --mode full   # DB doldur (bir kez)
python scripts/build_splunk_ta.py
# Çıktı:
#   siem/splunk/out/TA-sgb-threatintel/         (raw dizin)
#   siem/splunk/out/TA-sgb-threatintel.tar.gz   (deploy artifact)
#   siem/splunk/out/manifest.json
```

Manifest'te lookup count'ları + tarball SHA256 var.

## Adım 2 — Splunk'a yükle

### Enterprise (on-prem)

```bash
# CLI
$SPLUNK_HOME/bin/splunk install app siem/splunk/out/TA-sgb-threatintel.tar.gz \
  -auth admin:****
$SPLUNK_HOME/bin/splunk restart
```

Veya UI: **Apps > Manage Apps > Install app from file** → tarball'ı seç.

### Search Head Cluster (SHC)

Deployer host'una kopyala:

```bash
scp siem/splunk/out/TA-sgb-threatintel.tar.gz deployer:/tmp/
ssh deployer "tar -xzf /tmp/TA-sgb-threatintel.tar.gz -C \$SPLUNK_HOME/etc/shcluster/apps/"
ssh deployer "\$SPLUNK_HOME/bin/splunk apply shcluster-bundle -target https://shc-captain:8089"
```

### Splunk Cloud

UI > **Apps > Browse more apps** → "Install app from file" (private app
upload). ACS API ile programatik upload da mümkün.

## Adım 3 — Lookup yüklemesini doğrula

```spl
| inputlookup sgb_ip_lookup | stats count
| inputlookup sgb_domain_lookup | stats count
| inputlookup sgb_url_lookup | stats count
```

Beklenen: `~14K`, `~450K`, `~7K` (canlı SGB veri büyüklüklerine yakın).

## Adım 4 — Otomatik lookup'ı sına

```spl
sourcetype=dns earliest=-15m
| eval test_query="evilbotnet.example"
| lookup sgb_domain_lookup value AS test_query OUTPUT connectiontype
```

Önlü test: kasıtlı zararlı bir domain (örneğin SGB feed'inden alınmış bir
phishing domain) ile DNS sorgu log'u üretip rule'un tetiklenmesini görmek.

`props.conf [default]` kapsamı geniş; ortamınızda hacim yüksekse sourcetype
özelinde override edin:

```ini
# local/props.conf
[sourcetype::pan:traffic]
LOOKUP-sgb_dest_ip = sgb_ip_lookup value AS dest_ip OUTPUTNEW connectiontype AS sgb_dest_ct ...
# [default] LOOKUP-* satırlarını kaldırın
```

## Adım 5 — Saved search'ler ve dashboard

`Apps > SGB Threat Intel` ana sayfası açılır.

- **Dashboard:** SGB Threat Intel Overview (`sgb_overview.xml`)
- **Saved searches:** Settings > Searches, reports, and alerts → "SGB - UC-*"

Saved search isimleri Use Case ID'leri ile eşleşir:

- `SGB - UC-PH-001 - Phishing DNS query`
- `SGB - UC-BC-001 - Botnet C2 outbound`
- `SGB - UC-AC-001 - APT C2 match`
- vb.

İlk kurulumda alarm gürültü yaparsa `enableSched=0` ile geçici devre dışı:

```bash
# local/savedsearches.conf
[SGB - UC-PH-001 - Phishing DNS query]
enableSched = 0
```

## Adım 6 — Periyodik lookup refresh (restart-suz)

Yalnız lookup CSV'leri değişirse Splunk restart gerekmez:

```bash
python scripts/sync.py --mode delta
python scripts/build_splunk_ta.py
rsync -av siem/splunk/out/TA-sgb-threatintel/lookups/ \
  splunk-sh:$SPLUNK_HOME/etc/apps/TA-sgb-threatintel/lookups/
```

SHC için: deployer'a tüm tarball'ı tekrar push'la (app bundle re-deploy
yapmaz lookup'ı otomatik update etmez).

Cron:

```cron
27 * * * * cd /opt/sgb && python scripts/sync.py --mode delta && \
           python scripts/build_splunk_ta.py && \
           rsync -aq siem/splunk/out/TA-sgb-threatintel/lookups/ \
             splunk-sh:$SPLUNK_HOME/etc/apps/TA-sgb-threatintel/lookups/
```

## Adım 7 — Enterprise Security (ES) entegrasyonu

ES varsa SGB lookup'larını **KV Store collection** olarak yüklemek +
**Threat Intelligence Framework**'e kaydetmek daha güçlü:

```ini
# local/collections.conf
[sgb_ip_intel]
enforceTypes = true

# local/transforms.conf
[sgb_ip_intel_collection]
external_type = kvstore
collection = sgb_ip_intel
fields_list = _key, value, connectiontype, description, criticality_level, source, first_seen_utc

# local/local_ip_intel.conf
[default]
ipv4_address = value
description = description
threat_key = connectiontype
weight = criticality_level
```

CSV → KV Store yükleme:

```spl
| inputlookup sgb_ip_lookup
| outputlookup sgb_ip_intel_collection
```

## Önerilen başlangıç bundle'ı

| UC | Neden bu? | BG madde |
|----|-----------|----------|
| [UC-PH-001](../usecases/UC-PH-001.md) | DNS log + lookup en hızlı POC | 3.1.5.7 |
| [UC-BC-001](../usecases/UC-BC-001.md) | Firewall log + lookup | 3.1.6.4 |
| [UC-AC-001](../usecases/UC-AC-001.md) | Kapsamlı APT kuralı | 3.1.10.4 |

## Troubleshooting

| Belirti | Sebep | Çözüm |
|---------|-------|-------|
| App install hata: invalid tarball | Yanlış dizin yapısı | `tarfile.getnames()` ile doğrula; top-level `TA-sgb-threatintel/` olmalı |
| Lookup hit yok ama search doğru | props.conf yüklenmedi | `btool props list --debug` ile aktif config'i gör |
| Macro `sgb_severity` bulunamadı | App namespace yanlış | Search'i `app=TA-sgb-threatintel` ile sına |
| Lookup index'in dışında çalışmıyor | Lookup permission `private` | `default.meta`'da `export = system` |
| Dashboard boş | Time range dışında | `earliest=-24h` ile sına |
