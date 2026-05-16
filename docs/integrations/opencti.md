# Entegrasyon: OpenCTI

> **Hedef:** SGB STIX 2.1 bundle'ları OpenCTI'a External Import Connector
> aracılığıyla otomatik ingest edilsin.

**Tüketilen artifact:** `feeds/stix/sgb-{type}.stix2.json`

## BG Rehberi karşılığı

| Madde | Madde adı | Bu entegrasyon nasıl karşılar? |
|-------|-----------|--------------------------------|
| **3.1.10.4** ⭐ | Siber Tehdit Bildirimlerinin Yönetilmesi | OpenCTI = TI hub; SGB feed otomatik akıyor. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | OpenCTI'dan SIEM'e push connector'ları mevcut. |
| **3.1.10.5** | Olay Raporlarının Standardize Edilmesi | OpenCTI'ın "Report" entity'leri standart format. |
| **3.1.10.8** | Olay Puanlama / Önceliklendirme | Confidence + criticality alanları puanlamayı destekler. |

OpenCTI MISP'e alternatif (graph-tabanlı, STIX-native) bir TI platformudur.
Görselleştirme, entity ilişkileri ve playbook otomasyonu için tercih
edilir.

## Ön koşullar

- OpenCTI 5.x veya 6.x
- Connector deploy yetkisi (docker-compose veya k8s)
- OpenCTI API token

## Yöntem A — Generic external-import-file-stix connector (resmi)

OpenCTI'ın resmi `external-import-file-stix` connector'u URL'den periyodik
STIX bundle çeker. Buradaki örnek `docker-compose.yml` içindir.

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
      - EXTERNAL_IMPORT_FILE_STIX_URL=https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-domain.stix2.json
      - EXTERNAL_IMPORT_FILE_STIX_INTERVAL=60   # dakika
    restart: always
  # Aynı şablon: sgb-url, sgb-ip, sgb-ip6, sgb-ip6net
```

5 connector tanımla (her tip için). Çıkış: `docker-compose up -d`.

## Yöntem B — Custom connector (zenginleştirilmiş mapping)

Custom Python connector ile SGB-özel alanları (`x_sgb_*`) OpenCTI'ın
custom attribute'larına map'leyebilirsiniz. İskelet:

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
                self.helper.send_stix2_bundle(json.dumps(bundle))
            time.sleep(3600)

if __name__ == "__main__":
    SGBConnector().run()
```

## Adım 1 — Connector'ı başlat

```bash
cd opencti-deployment
docker-compose pull connector-sgb-domain
docker-compose up -d
docker-compose logs -f connector-sgb-domain
```

## Adım 2 — UI'da doğrula

1. OpenCTI > **Data > Ingestion > Connectors** → connector status "Running"
2. **Analyses > Reports** veya **Observations > Indicators** → SGB
   indicator'ları
3. Identity panelinde: "Siber Güvenlik Başkanlığı (SGB)" otomatik oluşur
   (STIX bundle'ında identity object var)

## Adım 3 — Default tag / label

OpenCTI 6.x'te connector level'da tag'leyebilirsiniz; alternatif olarak
**Settings > Customization > Labels** → `sgb`, `sgb:ct:PH`, vb. ekleyin
ve connector'ın bundle'larını bu label'larla ilişkilendirin.

## Adım 4 — Confidence level

STIX bundle'larımızda `confidence` alanı var (source bazlı: US/SB=85, IH=40).
OpenCTI bunu otomatik kullanır; UI'da Indicator detayında görülür.

`CONNECTOR_CONFIDENCE_LEVEL` env'i de connector-wide override sunar.

## Adım 5 — Lifecycle yönetimi

SGB indicator'ları silindiğinde (`removed_at_utc` damgalı) OpenCTI bunu
otomatik bilemez — `valid_until` field'ı STIX'te yok çünkü SGB silmeyi
event olarak yayınlamıyor. Çözüm:

- **Manuel:** Connector full re-sync sırasında eksik indicator'ları OpenCTI'dan delete
- **Otomatik:** Custom connector ile `x_sgb_removed_at` field'ını takip et
  ve `revoked=true` set et

Şu an basit yaklaşım: STIX bundle her sync'te taze export edilir
(`feeds/stix/*` SQLite'tan baselined regenerate), revoked olanlar
bundle'a girmez. OpenCTI'da kalan stale indicator'lar manuel temizlenir.

## Yöntem C — TAXII 2.1 server (gelecek)

Bir TAXII 2.1 server (`medallion`, `cti-taxii-server`) ayağa kaldırıp
SGB STIX bundle'larını collection olarak yayınlarsak OpenCTI'ın native
TAXII connector'u kullanılabilir. **Henüz uygulanmadı**.

## BG raporlama için kullanım

OpenCTI üzerinden SGB indicator'larını **Threat actor**, **Campaign**,
**Malware**, **Attack pattern** entity'leri ile ilişkilendirebilirsiniz.
BG **3.1.10.5** kapsamında üretilecek siber olay raporları için zengin
bağlamsal bilgi sağlar:

- Hangi indicator hangi MITRE ATT&CK tekniğine bağlı
- Hangi tehdit aktörünün TTP'sine uyuyor
- Olay zaman çizelgesi otomatik üretilir

## Troubleshooting

| Belirti | Sebep | Çözüm |
|---------|-------|-------|
| Connector "Running" ama indicator yok | Bundle parse hatası | `docker logs connector-sgb-domain` |
| Identity her sync'te yeniden oluşturuluyor | UUID determinizmi yok | bundle'lardaki `identity_id` sabit; OpenCTI tarafında dedup ayarlı mı kontrol |
| Tüm indicator confidence=50 | Source field eksik | Bundle'da `confidence` field'inin geldiğini doğrula (`jq '.objects[1].confidence'`) |
