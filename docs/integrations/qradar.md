# Entegrasyon: IBM QRadar

> **Hedef:** SGB TAXII koleksiyonları QRadar Threat Intelligence'a ingest
> edilsin, indicator match rule'lar tetiklensin, 1 günlük rapor çalışsın.

**Tüketilen servis:** `https://sgb-taxii.bilsec.tr/taxii2/` (anonim, TAXII 2.1)

## BG Rehberi karşılığı

| Madde | Madde adı | Bu entegrasyon nasıl karşılar? |
|-------|-----------|--------------------------------|
| **3.1.8.6** | Merkezi Kayıt Yönetimi | QRadar = merkezi log yönetim sistemi. SGB enrichment merkezi kaydı zenginleştirir. |
| **3.1.8.7** ⭐ | Kayıt Analizi Araçları Kullanımı (SIEM) | Bu entegrasyonun tam karşılığı. TAXII feed + indicator match rule = "korelasyon kuralları doğrultusunda tespit". |
| **3.1.8.8** | SIEM Düzenli Yapılandırma | Saatlik TAXII polling + UC'lerdeki FP tuning bölümleri. |
| **3.1.10.4** ⭐ | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB TAXII feed'i otomatik QRadar'a iniyor — maddenin teknik karşılığı. |
| **3.1.5.6** | Tespitlerin Merkezi Tutulması | UC sonucu offense'lar merkezde tutulur. |
| **3.1.10.5** | Olay Raporlarının Standardize Edilmesi | Günlük SGB özet raporu standardize çıktıdır. |

## Ön koşullar

- QRadar v7.5+ (Threat Intelligence app içerir, TAXII 2.1 destekler)
  - v7.4 → Threat Intelligence app'i App Exchange'den yüklenmeli
- Admin yetkisi (Threat Intelligence + Rules + Reference Data)
- Ağ erişimi: QRadar Console → `sgb-taxii.bilsec.tr:443` (HTTPS, dış internet)
  - Air-gapped ortamda: kendi TAXII servisinizi self-host edin
    ([setup-docker.md](../setup-docker.md), [setup-k8s.md](../setup-k8s.md))

> **Otomasyon ve hazır içerik:** Aşağıdaki Adım 1'i (8 feed) ve UC
> kurallarının kullandığı reference set'leri tek komutla kuran script ile
> kuralların content extension olarak paketlenme akışı için:
> [apps/qradar/](../../apps/qradar/) (`setup_feeds.py`, `rule-sheet.md`).

## Adım 1 — TAXII Feed'i ekle

UI: **Admin → Threat Intelligence → Add TAXII Feed**

| Alan | Değer (örnek: phishing) |
|------|-------------------------|
| Name | `SGB-Phishing` |
| Server URL | `https://sgb-taxii.bilsec.tr/taxii2/` |
| API Root | `https://sgb-taxii.bilsec.tr/api/` |
| Collection | `sgb-phishing` |
| Authentication | None |
| Poll interval | 1 hour |
| Confidence threshold | 0 (tümü) — kendi eşiğinizi belirleyebilirsiniz |

Aynı adımı her UC için tekrarlayın (8 koleksiyon → 8 feed):

| Feed adı | Collection alias | UC prefix |
|----------|------------------|-----------|
| `SGB-Phishing` | `sgb-phishing` | UC-PH-* |
| `SGB-Botnet-CC` | `sgb-botnet-cc` | UC-BC-* |
| `SGB-APT-CC` | `sgb-apt-cc` | UC-AC-* |
| `SGB-Exploit-Kit` | `sgb-exploit-kit` | UC-EK-* |
| `SGB-Malware-Download` | `sgb-malware-download` | UC-MF-* |
| `SGB-Mining` | `sgb-mining` | UC-MM-* |
| `SGB-Mobile-CC` | `sgb-mobile-cc` | UC-MC-* |
| `SGB-Other` | `sgb-other` | UC-OT-* |

REST API ile programatik ekleme (otomasyon):

```bash
curl -sk -X POST "https://$QRADAR_HOST/api/threat_intelligence/feeds" \
  -H "SEC: $QRADAR_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "name": "SGB-Phishing",
    "type": "TAXII_2_1",
    "discovery_url": "https://sgb-taxii.bilsec.tr/taxii2/",
    "collection_id": "sgb-phishing",
    "poll_interval_minutes": 60
  }'
```

## Adım 2 — Doğrula

1. **Admin → Threat Intelligence → Feeds** → SGB-* feed'leri "Connected"
2. Her birinin "Last poll" zamanı son 1 saat içinde olmalı
3. Indicator count'a bakın (SGB API çıktı volumeüne yakın):
   - `sgb-phishing` ~50K+, `sgb-apt-cc` ~300, `sgb-other` ~10K …

QRadar otomatik olarak indicator'ları **Threat Intelligence indicator
store**'una yerleştirir. Reference set çevirisi gerekmez — `Indicator
Match` rule property'si tüm TI store'unu sorgular.

## Adım 3 — Use case rule'larını kur

Kanonik tanımlar [docs/usecases/](../usecases/) altında. Başlangıç için
en yüksek değer/risk oranı olan üçü:

- [UC-PH-001](../usecases/UC-PH-001.md) — DNS phishing tespiti
- [UC-BC-001](../usecases/UC-BC-001.md) — Botnet C&C outbound
- [UC-AC-001](../usecases/UC-AC-001.md) — APT C&C (herhangi eşleşme)

Genel rule iskeleti (UC-PH-001 örneği):

```
Apply on events that include:
  when the event QID is one of the following: DNS Query QIDs
  AND when any of these event properties (URL/Hostname)
      MATCHES a TAXII Feed indicator from feed SGB-Phishing
  AND when the destination network is one of the following: Trusted
Response:
  Dispatch new event named "SGB Phishing DNS"
  Set severity = 5 (criticality modifier ile yükselir)
  Annotate offense: "SGB phishing match — UC-PH-001"
```

Severity formülü: [usecases/README.md#severity](../usecases/README.md#severity).

## Adım 4 — AQL ile doğrulama

```aql
-- Son 1 saatte SGB phishing indicator'larına hit alan kaç event var?
SELECT COUNT(*) AS hits
FROM events
WHERE THREATINDICATORMATCHED('SGB-Phishing') = TRUE
  AND starttime > NOW() - INTERVAL '1' HOUR
```

QRadar v7.5+ `THREATINDICATORMATCHED()` AQL fonksiyonu TAXII feed
indicator'larını sorgular. Pratik: her UC için bir AQL test query yazıp
"hit yok ama gelmeli" durumunu erken yakalayın.

## Adım 5 — Periyodik yenileme

Yenileme **otomatiktir** — QRadar TAXII client'ı her saat `added_after`
filtresiyle polling yapar; manuel cron, push script veya artifact rebuild
gerekmez. Bayat feed alarmı için:

```aql
-- Son 2 saatte yeni indicator gelmediyse uyar
SELECT name, MAX(last_poll) AS last
FROM threat_intelligence.feeds
WHERE name STARTSWITH 'SGB-'
GROUP BY name
HAVING last < NOW() - INTERVAL '2' HOUR
```

## Önerilen başlangıç use case bundle'ı

İlk hafta için minimum aktif kural seti:

| UC | Neden bu? | BG madde |
|----|-----------|----------|
| [UC-PH-001](../usecases/UC-PH-001.md) | DNS log her kurumda var; başlangıç için en kolay | 3.1.5.7, 3.1.6.20 |
| [UC-BC-001](../usecases/UC-BC-001.md) | Firewall log her kurumda var; yüksek severity | 3.1.6.4 |
| [UC-AC-001](../usecases/UC-AC-001.md) | APT — nadir ama kritik | 3.1.10.4, 3.1.10.5 |

İkinci hafta ekleyin: UC-EK-001, UC-MF-001, UC-XX-001 (meta).
Üçüncü hafta: kalan tümü.

## Troubleshooting

| Belirti | Sebep | Çözüm |
|---------|-------|-------|
| Feed "Disconnected" | DNS / proxy / TLS | `curl -v https://sgb-taxii.bilsec.tr/taxii2/` ile console host'tan test |
| "Last poll" güncel ama indicator count = 0 | Yeni koleksiyon, henüz veri yok (örn. `sgb-mining`) | Beklenen davranış — SGB feed boşaldığında koleksiyon boş kalır |
| Rule hiç tetiklenmiyor | Log source property mapping eksik | DSM Editor'da DNS Query / URL property'lerini map'le |
| Aynı indicator iki feed'de | Beklenen — bazı IoC çapraz CT'lerde olabilir | UC tarafında dedup; offense magnitude tek seferlik artar |
| 401/403 | (olmamalı, anonim servis) | TAXII URL'i doğru mu? Trailing slash önemli: `/taxii2/` |
