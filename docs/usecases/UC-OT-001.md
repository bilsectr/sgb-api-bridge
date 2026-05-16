# UC-OT-001 — Herhangi SGB "Other (OT)" Eşleşmesi (Bilgilendirme Baseline)

> **TL;DR:** SGB'nin sınıfı tam belli olmayan ("Other") indicator'larına
> herhangi bir eşleşme bilgilendirme amaçlı kaydedilir. **Offense
> açılmaz** — sadece log atılır ve sayaç tutulur. Trend bir asset veya
> CT'ye kayarsa ayrı review kuralı tetiklenir.

## Bu use case nedir? (Basit anlatım)

SGB feed'inde bazı indicator'lar henüz spesifik bir CT'ye (PH/BC/AC...)
sınıflandırılmamış olabilir; "Other" (OT) bucket'ına düşerler. Bu UC:
- Her OT match'i loglar.
- 24 saatlik counter'da `SGB_OT_OBSERVED` set'inde tutar.
- Saatlik trend > 100 hit olursa anomaly review alarmı tetikler.

Bu pattern emerging threat'leri (yeni kampanya başlangıcı) erken görür.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **4.5.2** Enerji EKS / **4.5.3** Elektronik Haberleşme | Spesifik EKS/OT trafiği için baseline görünürlük. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB OT feed'ini de değerlendirme zorunluluğu. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Anomaly threshold kuralı. |
| **3.1.10.8** | Olay Puanlama ve Önceliklendirme | Düşük baseline (3) + trend alarm. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-OT-001 |
| MITRE | (kategori belirsiz) |
| Connectiontype | OT |
| Severity (base) | 3 (offense açılmaz, log only) |
| Veri kaynakları | Tüm kaynaklar (geniş kapsam) |
| Reference / lookup | `SGB_OT_IP`, `SGB_OT_DOMAIN`, `SGB_OT_URL` |

## Tespit mantığı

```text
when herhangi event'te SGB_OT_* match
then magnitude=1 (offense açma) + add to SGB_OT_OBSERVED (TTL 24h)

anomaly trigger:
when count(SGB_OT match) > 100 in 1 hour
then SOC review alarmı
```

## QRadar uygulaması

```
when SGB_OT_* match → Magnitude = 1 (do NOT create offense)
```

**Response:** log only + add to `SGB_OT_OBSERVED` (24h TTL).

Ayrı saatlik scheduled search: `count(SGB_OT match) > 100 / hour` → alarm.

## Splunk uygulaması

**Saved search:** `SGB - UC-OT-001 - OT baseline (info)`

```spl
`sgb_all_indexes`
| lookup sgb_ip_lookup     value AS dest_ip OUTPUT connectiontype AS ct_ip
| lookup sgb_domain_lookup value AS query   OUTPUT connectiontype AS ct_dom
| where ct_ip="OT" OR ct_dom="OT"
| stats count AS hits by date_hour
| where hits > 100
```

`enableSched=1`, `alert_type=number of events > 100 / hour`.

## Yanlış pozitif notları

- Bu kategoride FP kavramı **yoktur** — bilgilendirme.
- Tehlike: feed'in OT bucket'ı büyürse alarm gürültüsü artar → threshold
  ayarını SGB delta'lar sonrası haftalık incele.

## Olay müdahale

- Otomatik response **yok**.
- Haftalık SOC review: hangi OT indicator'ları sürekli görülüyor?
  Spesifik CT'ye sınıflandırılıp yeni reference set'e taşınabilir mi?
- SGB ile geri bildirim: SOC tarafında sınıflandırma önerisi varsa
  SGB'ye iletilebilir.
