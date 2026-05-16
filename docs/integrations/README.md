# SGB → Threat Intel Platform / SIEM Integrations

SGB indicator feed'inizi tuketmek isteyen sistemler icin "5 dakikada calistir"
adim-adim rehberler. Her doküman:

- Hangi artifact'i (feed/STIX/lookup/reference set) tukettigini
- Kurulum komutlarini / config snippet'lerini
- Dogrulama adimlarini
- Yenileme stratejisini
- Onerilen rule'lara nasil baglandigini

acikca anlatir.

## Index

| Hedef sistem | Doküman | Tukettigi artifact | Kurulum hizi |
|--------------|---------|----------------------|-----------|
| QRadar       | [qradar.md](qradar.md)       | Reference set + map  | 15 dk |
| Splunk       | [splunk.md](splunk.md)       | TA-sgb-threatintel   | 10 dk |
| MISP         | [misp.md](misp.md)           | STIX 2.1 bundle      | 10 dk |
| OpenCTI      | [opencti.md](opencti.md)     | STIX 2.1 bundle      | 15 dk |
| Microsoft Sentinel | [sentinel.md](sentinel.md) | STIX 2.1 bundle (Logic App) | 20 dk |
| Generic (Falcon, Defender XDR, Cortex XSOAR vb.) | [generic-stix.md](generic-stix.md) | STIX 2.1 + master CSV/JSONL | degisken |

## Artifact'lara hizli erisim

**Lokal build** (her sync sonrasi):

```
feeds/sgb-master.csv                       # kanonik tablo
feeds/sgb-master.jsonl                     # JSON Lines
feeds/stix/sgb-{type}.stix2.json           # STIX 2.1 bundle (per-type)
feeds/by-connectiontype/*.txt              # CT bazli text slice'lar
feeds/index.json                           # tum dosyalarin manifest'i (sha256 + size)
siem/qradar/out/                           # QRadar bootstrap CSV'leri (build_pack.py)
siem/splunk/out/TA-sgb-threatintel.tar.gz  # Splunk TA paketi
```

**Iki kalici URL kanali** — ihtiyaca gore secin:

| Kanal | URL formati | Yenilenme | Kullanim |
|-------|-------------|-----------|----------|
| **Rolling** (SIEM ingest icin onerilen) | `releases/download/feeds-latest/<file>` | **Saatlik** (her delta sync sonrasi) | Sentinel/MISP/Splunk/QRadar pipeline'i hep taze veri ister |
| **Stable snapshot** | `releases/latest/download/<file>` | Manuel `v*X.Y.Z` tag push'unda | Versiyon audit gerektigi, "bu pack'i deploy ettik" denmesi gereken durumlar |
| **Versiyon kilitli** | `releases/download/v<X.Y.Z>/<file>` | Sabit | Spesifik snapshot'a kilitlemek istersen |

Rolling URL'ler (her saat yeniden uretilir, URL'ler ayni kalir):

```
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-feeds.tar.gz
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-qradar-pack.tar.gz
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/TA-sgb-threatintel.tar.gz
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-domain.stix2.json
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-url.stix2.json
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-ip.stix2.json
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/SHA256SUMS
```

Stabil snapshot kanali ayni dosya isimleri, `latest` ya da `v<X.Y.Z>`
yolundan. Actions artifact'lari (workflow run > Artifacts, 30 gun, auth'lu)
tek seferlik manuel indirme icin.

## Hangi entegrasyon kim icin?

- **Sadece engelleme istiyorum (firewall/proxy)** → `docs/index.html` ana sayfa
  (Fortinet, Palo Alto, pfSense, Pi-hole, vb.)
- **SIEM kurallari + alarm istiyorum** → QRadar / Splunk
- **Threat intel platformu / korelasyon hub'i** → MISP veya OpenCTI
- **Cloud SOC (Azure)** → Sentinel
- **EDR / XDR'a IoC besle** → generic-stix.md (Falcon, Defender XDR, vb.)
