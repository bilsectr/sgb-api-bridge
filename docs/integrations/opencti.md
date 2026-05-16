# Entegrasyon: OpenCTI

**Hedef:** SGB STIX 2.1 bundle'lari OpenCTI'a External Import Connector
araciligiyla otomatik ingest edilsin.

**Tuketilen artifact:** `feeds/stix/sgb-{type}.stix2.json`

## On kosullar

- OpenCTI 5.x veya 6.x
- Connector deploy yetkisi (docker-compose veya k8s)
- OpenCTI API token

## Yontem A — Generic external-import-file-stix connector (resmi)

OpenCTI'in resmi `external-import-file-stix` connector'i URL'den periyodik
STIX bundle ceker. Buradaki ornek `docker-compose.yml` icindir.

```yaml
# docker-compose.override.yml
services:
  connector-sgb-domain:
    image: opencti/connector-external-import-file-stix:6.4.0
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_TOKEN}
      - CONNECTOR_ID=sgb-domain-stix
      - CONNECTOR_TYPE=EXTERNAL_IMPORT
      - CONNECTOR_NAME=SGB Domain STIX
      - CONNECTOR_SCOPE=identity,indicator,bundle
      - CONNECTOR_CONFIDENCE_LEVEL=70
      - CONNECTOR_LOG_LEVEL=info
      - EXTERNAL_IMPORT_FILE_STIX_URL=https://github.com/bilsectr/sgb-api-bridge/releases/latest/download/sgb-domain.stix2.json
      - EXTERNAL_IMPORT_FILE_STIX_INTERVAL=60   # dakika
    restart: always
  # Ayni sablon: sgb-url, sgb-ip, sgb-ip6, sgb-ip6net
```

5 connector tanimla (her tip icin). Cikis: docker-compose up -d.

## Yontem B — Custom connector (zenginlestirilmis mapping)

Custom Python connector ile SGB-ozel alanlari (`x_sgb_*`) OpenCTI'in
custom attribute'larina map'leyebilirsiniz. Iskelet:

```python
# connectors/sgb/main.py (kendi connector projeniz)
import json, requests, time
from pycti import OpenCTIConnectorHelper, get_config_variable

class SGBConnector:
    def __init__(self):
        config = {...}  # config.yml load
        self.helper = OpenCTIConnectorHelper(config)
        self.url_template = get_config_variable(
            "SGB_URL_TEMPLATE", ["sgb", "url_template"], config)
        self.types = ["domain", "url", "ip", "ip6", "ip6net"]

    def run(self):
        while True:
            for typ in self.types:
                url = self.url_template.format(type=typ)
                r = requests.get(url, timeout=30)
                bundle = r.json()
                # OpenCTI'a aktar
                self.helper.send_stix2_bundle(json.dumps(bundle))
            time.sleep(3600)

if __name__ == "__main__":
    SGBConnector().run()
```

## Adim 1 — Connector'i basla

```bash
cd opencti-deployment
docker-compose pull connector-sgb-domain
docker-compose up -d
docker-compose logs -f connector-sgb-domain
```

## Adim 2 — UI'da dogrula

1. OpenCTI > **Data > Ingestion > Connectors** -> connector status "Running"
2. **Analyses > Reports** veya **Observations > Indicators** -> SGB indicator'lari
3. Identity panelinde: "Siber Guvenlik Baskanligi (SGB)" otomatik olusur
   (STIX bundle'inda identity object var)

## Adim 3 — Default tag / label

OpenCTI 6.x'te connector level'da tag'leyebilirsiniz; alternatif olarak
**Settings > Customization > Labels** -> `sgb`, `sgb:ct:PH`, vb. ekleyin
ve connector'in bundle'larini bu label'larla iliskilendirin.

## Adim 4 — Confidence level

STIX bundle'larimizda `confidence` alani var (source bazli: US/SB=85, IH=40).
OpenCTI bunu otomatik kullanir; UI'da Indicator detayinda gorulur.

`CONNECTOR_CONFIDENCE_LEVEL` env'i de connector-wide override sunar.

## Adim 5 — Lifecycle yonetimi

SGB indicator'lari silindiginde (removed_at_utc damgali) OpenCTI bunu
otomatik bilemez — `valid_until` field'i STIX'te yok cunku SGB silmeyi
event olarak yayinlamiyor. Cozum:

- **Manuel:** Connector full re-sync sirasinda eksik indicator'lari OpenCTI'dan delete
- **Otomatik:** Custom connector ile `x_sgb_removed_at` field'ini takip et
  ve revoked=true set et

Su an basit yaklasim: STIX bundle her sync'te taze export edilir
(`feeds/stix/*` SQLite'tan baselined regenerate), revoked olanlar bundle'a
girmez. OpenCTI'da kalan stale indicator'lar manuel temizlenir.

## Yontem C — TAXII 2.1 server (gelecek)

Bir TAXII 2.1 server (`medallion`, `cti-taxii-server`) ayaga kaldirip
SGB STIX bundle'larini collection olarak yayinlarsak OpenCTI'in native
TAXII connector'u kullanilabilir. **Henuz uygulanmadi**.

## Troubleshooting

| Belirti | Sebep | Cozum |
|---------|-------|-------|
| Connector "Running" ama indicator yok | Bundle parse hatasi | `docker logs connector-sgb-domain` |
| Identity her sync'te yeniden olusturuluyor | UUID determinizmi yok | bundle'lardaki identity_id sabit; OpenCTI tarafinda dedup ayarli mi kontrol |
| Tum indicator confidence=50 | Source field eksik | Bundle'da `confidence` field'inin geldigini dogrula (`jq '.objects[1].confidence'`) |
