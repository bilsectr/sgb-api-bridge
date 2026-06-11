# Entegrasyon: Splunk Enterprise / Cloud

> **Hedef:** SGB TAXII koleksiyonları Splunk'a ingest edilsin; `src_ip`,
> `dest_ip`, `query`, `url` alanları otomatik zenginleştirilsin; 3 başlangıç
> alarm aktif.

**Tüketilen servis:** `https://sgb-taxii.bilsec.tr/taxii2/` (anonim, TAXII 2.1)

## BG Rehberi karşılığı

| Madde | Madde adı | Bu entegrasyon nasıl karşılar? |
|-------|-----------|--------------------------------|
| **3.1.8.6** | Merkezi Kayıt Yönetimi | Splunk merkezi log platformudur. |
| **3.1.8.7** ⭐ | Kayıt Analizi Araçları (SIEM) | TAXII feed + correlation search = SIEM korelasyon. |
| **3.1.8.8** | SIEM Düzenli Yapılandırma | Saatlik TAXII polling + FP tuning. |
| **3.1.10.4** ⭐ | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB feed → Splunk Threat Intel Framework. |
| **3.1.5.1** | Zararlı Yazılımdan Korunma | TAXII-tabanlı zararlı IoC eşleştirme. |

## Ön koşullar

Splunk dağıtımına göre üç seçenek:

- **Hazır uygulama paketi (önerilen)** — bu repo'nun ürettiği
  `TA-sgb-threat-intel` + `sgb_usecases` paketleri: TAXII input, lookup'lar,
  24 hazır UC kuralı ve dashboard'lar birlikte gelir → [Yöntem C](#yöntem-c)
- **Splunk Enterprise Security (ES)** — Threat Intelligence Manager (built-in)
- **Splunk Core / Cloud (ES'siz)** — `Splunk Add-on for STIX/TAXII` veya
  `taxii2://` modular input (community/Splunkbase app)

Her iki yol için:

- Splunk 8.x / 9.x veya Splunk Cloud (Victoria/Classic)
- Admin yetkisi
- Search head'lerden `sgb-taxii.bilsec.tr:443` erişimi

## Yöntem A — Splunk Enterprise Security (önerilen)

ES'in **Threat Intelligence Manager**'ı native TAXII 2.0/2.1 destekler.

**Configure → Data Enrichment → Threat Intelligence Management → New**

| Alan | Değer (örnek) |
|------|---------------|
| Type | `taxii2` |
| Name | `SGB-Phishing` |
| Discovery URL | `https://sgb-taxii.bilsec.tr/taxii2/` |
| Collection | `sgb-phishing` |
| Polling interval (sec) | `3600` |
| Username/Password | boş |

Tüm koleksiyonlar için tekrarla (8 feed). ES otomatik olarak STIX
indicator'larını **threat_intel_collection** KV Store'una yazar; tüm
"Threat Intelligence" correlation search'ler bu collection'ı sorgular.

Doğrulama:

```spl
| `threatintel_lookup`
| search threat_match_field IN ("src_ip","dest_ip","query","url")
| where threat_group="SGB-Phishing"
| stats count by threat_match_value, threat_collection
```

## Yöntem B — Splunk Core / Cloud (`taxii2://` modular input)

ES'siz ortamda `Splunk Add-on for STIX/TAXII` (Splunkbase) veya muadili
TAXII2 modular input app'i kullanın.

```ini
# $SPLUNK_HOME/etc/apps/Splunk_TA_stix-taxii/local/inputs.conf
[taxii2://SGB-Phishing]
discovery_url = https://sgb-taxii.bilsec.tr/taxii2/
collection = sgb-phishing
polling_interval = 3600
index = threat_intel
sourcetype = stix:indicator

[taxii2://SGB-Botnet-CC]
discovery_url = https://sgb-taxii.bilsec.tr/taxii2/
collection = sgb-botnet-cc
polling_interval = 3600
index = threat_intel
sourcetype = stix:indicator

# … sgb-apt-cc, sgb-exploit-kit, sgb-malware-download, sgb-mining,
#    sgb-mobile-cc, sgb-other için aynı şablon
```

Restart sonrası `index=threat_intel sourcetype=stix:indicator` ile ingest
doğrulayın.

## Adım — Otomatik enrichment

ES'te Threat Intel Manager indicator'ları otomatik olarak event'lerle
match'ler (Adaptive Response: `threat_match`). Custom search ile:

```spl
sourcetype=dns earliest=-1h
| lookup local_domain_intel domain AS query OUTPUT threat_group, threat_key
| where isnotnull(threat_group) AND threat_group LIKE "SGB-%"
| stats count by src_ip, query, threat_group, threat_key
```

ES'siz ortamda manuel lookup üretimi için STIX indicator'ları
`x_sgb_value` field'ından çıkarın:

```spl
index=threat_intel sourcetype=stix:indicator x_sgb_connectiontype="PH"
| spath x_sgb_value output=value
| spath x_sgb_criticality output=criticality
| outputlookup sgb_phishing_lookup
```

Bu lookup'ı sonra DNS event'larına bağlayın (`lookup sgb_phishing_lookup
value AS query`).

## Yöntem C — Hazır uygulama paketi (TA + App) {#yöntem-c}

Yukarıdaki adımları tek tek yapmak yerine bu repo'daki iki paketi kurun
([apps/splunk/](../../apps/splunk/)):

| Paket | İçerik |
|---|---|
| `TA-sgb-threat-intel` | `sgb_taxii` modular input (8 koleksiyon, saatlik incremental), STIX event ingest, `sgb_domain/ip/url` lookup üretimi |
| `sgb_usecases` | 24 UC saved search (MITRE + BG Rehberi annotation'lı, tier'lara göre disabled gelir) + 3 dashboard (genel bakış, UC aktivitesi, feed sağlığı) |

```bash
python apps/splunk/build.py   # dist/*.tar.gz üretir → Manage Apps → Install from file
```

Kurulum adımları, ES notları ve bilinen sınırlamalar:
[apps/splunk/README.md](../../apps/splunk/README.md). Paketler her PR'da
AppInspect'ten (cloud tag dahil) geçirilir; Splunkbase yayını için hazırdır.

## Önerilen başlangıç bundle'ı

ES tarafında **Use Case Library**'ye 3 correlation search ekleyin
(adlar UC ID'leriyle eşleşir):

| Saved search adı | UC | BG madde |
|------------------|----|----------|
| `SGB - UC-PH-001 - Phishing DNS query` | UC-PH-001 | 3.1.5.7 |
| `SGB - UC-BC-001 - Botnet C2 outbound` | UC-BC-001 | 3.1.6.4 |
| `SGB - UC-AC-001 - APT C2 match` | UC-AC-001 | 3.1.10.4 |

Kanonik SPL örnekleri ilgili [UC dosyalarında](../usecases/).

## Periyodik yenileme

Yenileme **otomatiktir** — TAXII client `added_after` ile saatlik polling
yapar; manuel cron, rsync veya TA rebuild gerekmez. Bayat feed alarmı:

```spl
| rest /servicesNS/-/-/data/inputs/taxii2
| search title="SGB-*"
| eval lag = now() - last_polled
| where lag > 7200
| table title, last_polled, lag
```

## Troubleshooting

| Belirti | Sebep | Çözüm |
|---------|-------|-------|
| Modular input çalışmıyor | App eksik | Splunkbase'den `Splunk Add-on for STIX/TAXII` yükle |
| ES'te indicator count = 0 | KV Store sync pending | Threat Intelligence Manager'da "Force sync" |
| Match yok ama search doğru | `local_*_intel.conf` field map | `threat_match_field` doğru property'ye bağlı mı? |
| Polling 401/403 | (olmamalı, anonim servis) | TAXII URL doğru mu? Trailing slash: `/taxii2/` |
| Indicator duplicate | Aynı koleksiyon iki input'tan çekiliyor | `inputs.conf`'ta tek tanımı bırak |
