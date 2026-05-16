# Entegrasyon: Splunk Enterprise / Cloud

**Hedef:** `TA-sgb-threatintel` app'i kurulsun; src_ip, dest_ip, query, url
alanlari otomatik zenginlestirilsin; 3 baslangic alarm aktif; dashboard goruntulensin.

**Tuketilen artifact:** `siem/splunk/out/TA-sgb-threatintel.tar.gz`

## On kosullar

- Splunk Enterprise 8.x / 9.x veya Splunk Cloud (Victoria/Classic)
- Admin yetkisi (`admin` veya `sc_admin` role)
- Search heads + indexer'larda app deploy izni
- Python 3.10+ (builder host'unda)

## Adim 1 — TA paketini uret

```bash
python scripts/sync.py --mode full   # DB doldur (bir kez)
python scripts/build_splunk_ta.py
# Cikti:
#   siem/splunk/out/TA-sgb-threatintel/         (raw dizin)
#   siem/splunk/out/TA-sgb-threatintel.tar.gz   (deploy artifact)
#   siem/splunk/out/manifest.json
```

Manifest'te lookup count'lari + tarball SHA256 var.

## Adim 2 — Splunk'a yukle

### Enterprise (on-prem)

```bash
# CLI
$SPLUNK_HOME/bin/splunk install app siem/splunk/out/TA-sgb-threatintel.tar.gz \
  -auth admin:****
$SPLUNK_HOME/bin/splunk restart
```

Veya UI: **Apps > Manage Apps > Install app from file** -> tarball'i sec.

### Search Head Cluster (SHC)

Deployer host'una kopyala:

```bash
scp siem/splunk/out/TA-sgb-threatintel.tar.gz deployer:/tmp/
ssh deployer "tar -xzf /tmp/TA-sgb-threatintel.tar.gz -C \$SPLUNK_HOME/etc/shcluster/apps/"
ssh deployer "\$SPLUNK_HOME/bin/splunk apply shcluster-bundle -target https://shc-captain:8089"
```

### Splunk Cloud

UI > **Apps > Browse more apps** -> "Install app from file" (private app upload).
ACS API ile programatik upload da mumkun.

## Adim 3 — Lookup yuklemesini dogrula

```spl
| inputlookup sgb_ip_lookup | stats count
| inputlookup sgb_domain_lookup | stats count
| inputlookup sgb_url_lookup | stats count
```

Beklenen: `~14K`, `~450K`, `~7K` (canli SGB veri buyukluklerine yakin).

## Adim 4 — Otomatik lookup'i sina

```spl
sourcetype=dns earliest=-15m
| eval test_query="evilbotnet.example"
| lookup sgb_domain_lookup value AS test_query OUTPUT connectiontype
```

Onlu test: kasitlu zararlı bir domain (örneğin SGB feed'inden alinmis bir
phishing domain) ile DNS sorgu logu uretip rule'un tetiklenmesini gormek.

`props.conf [default]` kapsami genis; ortaminizda hacim yuksekse sourcetype
ozelinde override edin:

```ini
# local/props.conf
[sourcetype::pan:traffic]
LOOKUP-sgb_dest_ip = sgb_ip_lookup value AS dest_ip OUTPUTNEW connectiontype AS sgb_dest_ct ...
# [default] LOOKUP-* satirlarini kaldirin
```

## Adim 5 — Saved search'ler ve dashboard

`Apps > SGB Threat Intel` ana sayfasi acilir.
- Dashboard: **SGB Threat Intel Overview** (sgb_overview.xml)
- Saved searches: **Settings > Searches, reports, and alerts** -> "SGB - UC-*"

Ilk kurulumda alarm gurultu yaparsa `enableSched=0` ile gecici devre disi:

```bash
# local/savedsearches.conf
[SGB - UC-PH-001 - Phishing DNS query]
enableSched = 0
```

## Adim 6 — Periyodik lookup refresh (restart-suz)

Yalniz lookup CSV'leri degisirse Splunk restart gerekmez:

```bash
python scripts/sync.py --mode delta
python scripts/build_splunk_ta.py
rsync -av siem/splunk/out/TA-sgb-threatintel/lookups/ \
  splunk-sh:$SPLUNK_HOME/etc/apps/TA-sgb-threatintel/lookups/
```

SHC icin: deployer'a tum tarball'i tekrar push'la (app bundle re-deploy yapmaz lookup'i otomatik update etmez).

Cron:

```cron
27 * * * * cd /opt/sgb && python scripts/sync.py --mode delta && \
           python scripts/build_splunk_ta.py && \
           rsync -aq siem/splunk/out/TA-sgb-threatintel/lookups/ \
             splunk-sh:$SPLUNK_HOME/etc/apps/TA-sgb-threatintel/lookups/
```

## Adim 7 — Enterprise Security (ES) entegrasyonu

ES varsa SGB lookup'larini KV Store collection olarak yuklemek + Threat
Intelligence Framework'e kaydetmek daha guclu:

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

CSV → KV Store yukleme:

```spl
| inputlookup sgb_ip_lookup
| outputlookup sgb_ip_intel_collection
```

## Troubleshooting

| Belirti | Sebep | Cozum |
|---------|-------|-------|
| App install hata: invalid tarball | Yanlis dizin yapisi | `tarfile.getnames()` ile dogrula; top-level `TA-sgb-threatintel/` olmali |
| Lookup hit yok ama search dogru | props.conf yuklenmedi | `btool props list --debug` ile aktif config'i gor |
| Macro `sgb_severity` bulunamadi | App namespace yanlis | Search'i `app=TA-sgb-threatintel` ile sina |
| Lookup index'in disinda calismiyor | Lookup permission `private` | `default.meta`'da `export = system` |
| Dashboard bos | Time range disinda | `earliest=-24h` ile sina |
