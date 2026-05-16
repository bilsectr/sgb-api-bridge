# SGB → Tehdit İstihbaratı Platformu / SIEM Entegrasyonları

SGB indicator feed'inizi tüketmek isteyen sistemler için adım-adım kurulum
rehberleri. Hepsi Türkçe, detaylı anlatımlı ve **Bilgi ve İletişim Güvenliği
Rehberi** maddeleri ile eşleştirilmiştir.

## BG Rehberi karşılığı (özet)

| Entegrasyon | Doğrudan karşıladığı BG maddeleri |
|-------------|------------------------------------|
| QRadar, Splunk, Sentinel | **3.1.8.6** (Merkezi Kayıt Yönetimi), **3.1.8.7** (Kayıt Analizi Araçları/SIEM), **3.1.8.8** (SIEM düzenli yapılandırma), **3.1.10.4** (Siber Tehdit Bildirimlerinin Yönetilmesi) |
| MISP, OpenCTI | **3.1.10.4** (TI hub fonksiyonu) |
| Generic STIX (EDR/XDR) | **3.1.10.4** + **3.1.5.1** (EDR'a IoC besleme) |
| Firewall / proxy (ana sayfa) | **3.1.6.4** (Kara Liste Kullanımı), **3.1.6.5** (İzin Verilmeyen Trafik), **3.1.6.20** (URL Filtreleri) |

> Detaylı eşleştirme için: [../bg-rehber-mapping.md](../bg-rehber-mapping.md)

Her doküman aşağıdaki bölümleri içerir:

1. **Hedef** — Entegrasyon sonunda elde edilecek durum
2. **BG Rehberi karşılığı** — Hangi tedbiri karşıladığı
3. **Ön koşullar** — Sürüm, yetki, ağ erişimi
4. **Adım-adım kurulum** — Komutlar + UI talimatları
5. **Doğrulama** — Çalıştığını kanıtlama yolu
6. **Yenileme stratejisi** — Verinin nasıl güncel kalacağı
7. **Önerilen kurallarla bağlantı** — Hangi UC'leri devreye alınabilir
8. **Troubleshooting** — Sık karşılaşılan sorunlar

## Index

| Hedef sistem | Doküman | Tükettiği artifact | Kurulum hızı | Birincil BG madde |
|--------------|---------|---------------------|--------------|-------------------|
| **IBM QRadar** | [qradar.md](qradar.md) | Reference set + map | 15 dk | 3.1.8.7 |
| **Splunk Enterprise/Cloud** | [splunk.md](splunk.md) | TA-sgb-threatintel app | 10 dk | 3.1.8.7 |
| **MISP** | [misp.md](misp.md) | STIX 2.1 bundle | 10 dk | 3.1.10.4 |
| **OpenCTI** | [opencti.md](opencti.md) | STIX 2.1 bundle | 15 dk | 3.1.10.4 |
| **Microsoft Sentinel** | [sentinel.md](sentinel.md) | STIX 2.1 bundle (Logic App) | 20 dk | 3.1.8.7 + 4.3 (bulut) |
| **Generic** (Falcon, Defender XDR, Cortex XSOAR vb.) | [generic-stix.md](generic-stix.md) | STIX 2.1 + master CSV/JSONL | değişken | 3.1.5.1 + 3.1.10.4 |

## Artifact'lara hızlı erişim

**Lokal build** (her sync sonrası):

```
feeds/sgb-master.csv                       # kanonik tablo
feeds/sgb-master.jsonl                     # JSON Lines
feeds/stix/sgb-{type}.stix2.json           # STIX 2.1 bundle (tip bazlı)
feeds/by-connectiontype/*.txt              # CT bazlı text slice'lar
feeds/index.json                           # tüm dosyaların manifest'i (sha256 + size)
siem/qradar/out/                           # QRadar bootstrap CSV'leri (build_pack.py)
siem/splunk/out/TA-sgb-threatintel.tar.gz  # Splunk TA paketi
```

**İki kalıcı URL kanalı** — ihtiyaca göre seçin:

| Kanal | URL formatı | Yenilenme | Kullanım |
|-------|-------------|-----------|----------|
| **Rolling** (SIEM ingest için **önerilen**) | `releases/download/feeds-latest/<file>` | **Saatlik** (her delta sync sonrası) | Sentinel/MISP/Splunk/QRadar pipeline'ı hep taze veri ister |
| **Stable snapshot** | `releases/latest/download/<file>` | Manuel `v*X.Y.Z` tag push'unda | Versiyon audit gerektiğinde, "bu pack'i deploy ettik" denmesi gereken durumlar |
| **Versiyon kilitli** | `releases/download/v<X.Y.Z>/<file>` | Sabit | Spesifik snapshot'a kilitlemek istersen |

Rolling URL'ler (her saat yeniden üretilir, URL'ler aynı kalır):

```
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-feeds.tar.gz
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-qradar-pack.tar.gz
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/TA-sgb-threatintel.tar.gz
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-domain.stix2.json
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-url.stix2.json
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/sgb-ip.stix2.json
https://github.com/bilsectr/sgb-api-bridge/releases/download/feeds-latest/SHA256SUMS
```

Stabil snapshot kanalı aynı dosya isimleri, `latest` ya da `v<X.Y.Z>`
yolundan. Actions artifact'ları (workflow run > Artifacts, 30 gün, auth'lu)
tek seferlik manuel indirme için.

## Hangi entegrasyon kim için?

- **Sadece engelleme istiyorum (firewall/proxy)** → `docs/index.html` ana
  sayfa (Fortinet, Palo Alto, pfSense, Pi-hole, vb.) —
  BG **3.1.6.4 / 3.1.6.5 / 3.1.6.20** karşılığı.
- **SIEM kuralları + alarm istiyorum** → QRadar / Splunk —
  BG **3.1.8.7 + 3.1.10.4** karşılığı.
- **Threat intel platformu / korelasyon hub'ı** → MISP veya OpenCTI —
  BG **3.1.10.4** karşılığı.
- **Cloud SOC (Azure)** → Sentinel — BG **3.1.8.7 + 4.3 (Bulut Bilişim)**.
- **EDR / XDR'a IoC besle** → generic-stix.md (Falcon, Defender XDR vb.) —
  BG **3.1.5.1** karşılığı.

## Veri tazeliği (her entegrasyon için)

| Sistem | Önerilen refresh | Yöntem |
|--------|------|----------|
| QRadar | 1 saat | `push_to_qradar.py` cron |
| Splunk | 1 saat | rsync lookup dosyaları (restart gerekmez) |
| MISP | 1 saat | Feed scheduler (önceden 24 saat default'tu) |
| OpenCTI | 1 saat | Connector `INTERVAL=60` |
| Sentinel | 1 saat | Logic App schedule |
| Falcon / Defender / XSOAR | 1-6 saat | API push (cron / scheduled task) |
| Suricata / Wazuh | 1 saat | curl + reload |

> **Neden 1 saat?** SGB API delta sync cadence'imiz saatliktir; entegrasyon
> bu tempoyu eşlerse tazelik kaybı olmaz. **3.1.5.1**'in "imza/IoC veri
> tabanı güncel olmalı" ifadesinin somut karşılığıdır.
