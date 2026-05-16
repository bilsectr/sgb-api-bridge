# Entegrasyon: IBM QRadar

> **Hedef:** SGB indicator'ları QRadar reference set + map olarak yüklensin,
> 3 başlangıç use case rule'u aktifleşsin, 1 günlük rapor çalışsın.

**Tüketilen artifact:** `siem/qradar/out/` (`build_pack.py` üretir)

## BG Rehberi karşılığı

| Madde | Madde adı | Bu entegrasyon nasıl karşılar? |
|-------|-----------|--------------------------------|
| **3.1.8.6** | Merkezi Kayıt Yönetimi | QRadar = merkezi log yönetim sistemi. SGB enrichment merkezi kaydı zenginleştirir. |
| **3.1.8.7** ⭐ | Kayıt Analizi Araçları Kullanımı (SIEM) | Bu entegrasyonun tam karşılığı. Reference set + rule = "korelasyon kuralları doğrultusunda tespit". |
| **3.1.8.8** | SIEM Düzenli Yapılandırma | Saatlik refresh + UC'lerdeki FP tuning bölümleri. |
| **3.1.10.4** ⭐ | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB feed'i otomatik QRadar'a iniyor — maddenin teknik karşılığı. |
| **3.1.5.6** | Tespitlerin Merkezi Tutulması | UC sonucu offense'lar merkezde tutulur. |
| **3.1.10.5** | Olay Raporlarının Standardize Edilmesi | Günlük SGB özet raporu standardize çıktıdır. |

## Ön koşullar

- QRadar v7.4+ (REST API v15.0 minimum)
- Authorized service token (Admin > Authorized Services > Add Token)
  - Yetki: `Admin` veya en az `Reference Sets` + `Maps` yazma izni
- Ağ erişimi: builder (sizin host) → QRadar Console TCP 443
- Python 3.10+ + `requests`

## Adım 1 — Pack'i üret

```bash
# DB hazırsa (sync.py --mode full bir kez çalıştı)
python scripts/build_pack.py
# Çıktı: siem/qradar/out/
#   reference_sets/SGB_<CT>_<TYPE>.csv  (PH, BC, AC, EK, MF, MM, MC, OT)
#   reference_maps/SGB_<TYPE>_MAP.csv   (IP, Domain, URL, IP6, IP6NET)
#   manifest.json
```

Manifest'i kontrol edin (set/map sayıları beklediğiniz gibi mi?):

```bash
python -c "import json; m=json.load(open('siem/qradar/out/manifest.json')); \
  print('sets:', len(m['reference_sets']), 'maps:', len(m['reference_maps']))"
```

## Adım 2 — QRadar'a push

```bash
export SGB_QRADAR_HOST=qradar.kurum.local
export SGB_QRADAR_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# İlk olarak tek bir set ile sınayın (lab/üretim ayrımı)
python scripts/push_to_qradar.py --pack siem/qradar/out --only SGB_PH_DOMAIN

# Tüm pack'i push'la
python scripts/push_to_qradar.py --pack siem/qradar/out

# (Lab: self-signed sertifika)
python scripts/push_to_qradar.py --pack siem/qradar/out --insecure
```

Push script idempotent'tir: set/map mevcut ise atlar (HTTP 409),
`bulk_load` merge yapar.

## Adım 3 — Set/map'leri UI'da doğrula

1. Admin > Reference Set Management
2. Filter: `SGB_` → beklediğiniz tüm set/map'leri görmelisiniz
3. Birine çift tıkla → entry count + TTL = 25 saat

Veya REST ile:

```bash
curl -s -k -H "SEC: $SGB_QRADAR_TOKEN" \
  "https://$SGB_QRADAR_HOST/api/reference_data/sets?filter=name+startswith+'SGB_'" \
  | jq '.[] | {name, element_type, number_of_elements}'
```

## Adım 4 — Use case rule'larını kur

Kanonik tanımlar [docs/usecases/](../usecases/) altında. Başlangıç için
en yüksek değer/risk oranı olan üçü:

- [UC-PH-001](../usecases/UC-PH-001.md) — DNS phishing tespiti
- [UC-BC-001](../usecases/UC-BC-001.md) — Botnet C&C outbound
- [UC-AC-001](../usecases/UC-AC-001.md) — APT C&C (herhangi eşleşme)

Her use case'in markdown'ında **QRadar** bölümünde rule tanımı adım-adım
verilmiştir. UI'dan kurulum:

1. Offenses > Rules > Actions > New Event Rule
2. Use case markdown'ındaki "QRadar Rule" bloğuna göre test bloklarını seç
3. Reference set/map adlarını birebir kopyala (ör. `SGB_PH_DOMAIN`)
4. Severity formülü için
   [severity-matrix.md](../../siem/qradar/severity-matrix.md)

## Adım 5 — AQL ile doğrulama

```aql
-- Son 1 saatte SGB_PH_DOMAIN'a hit alan kaç event var?
SELECT COUNT(*) AS hits
FROM events
WHERE REFERENCESETCONTAINS('SGB_PH_DOMAIN', "URL") = TRUE
  AND starttime > NOW() - INTERVAL '1' HOUR
```

Hazır AQL'ler: [siem/qradar/aql/](../../siem/qradar/aql/)

- `uc-ph-001-test.aql`
- `uc-bc-001-test.aql`
- `report-daily-sgb-summary.aql` — günlük SGB özet raporu (BG 3.1.10.5
  için standart çıktı)

## Adım 6 — Periyodik yenileme

```bash
# Saatlik delta sonrası:
python scripts/sync.py --mode delta
python scripts/build_pack.py
python scripts/push_to_qradar.py --pack siem/qradar/out
```

Push yapılmazsa entry'ler 25 saatte TTL ile düşüp rule'lar sessize gömülür
(bu kasıtlıdır — durmuş pipeline'ı fark etmek için healthcheck).

Önerilen cron (Linux):

```cron
17 * * * * cd /opt/sgb && python scripts/sync.py --mode delta && \
           python scripts/build_pack.py && \
           python scripts/push_to_qradar.py --pack siem/qradar/out >> /var/log/sgb-push.log 2>&1
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
| Push HTTP 401 | Token geçersiz/expire | Yeni token üret |
| Push HTTP 422 | Element type uyumsuz | Set'i sil ve yeniden oluştur (rule referanslarını koru) |
| Set count beklenenden az | Bulk_load body limit | `--only` ile chunk'la push, veya QRadar config'ten `max_request_size` artır |
| Rule hiç tetiklenmiyor | Log source property mapping eksik | DSM Editor'da DNS Query / URL property'lerini map'le |
| TTL sonrası entry'ler düştü, push açık | Cron çalışmıyor | systemd timer / GitHub Actions log'ları kontrol |
