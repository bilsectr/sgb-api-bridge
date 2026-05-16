# UC-XX-003 — Organizasyon Geneli Kritiklik Spike (Saatlik avg criticality > 7)

> **TL;DR:** Saatlik penceredeki TÜM SGB match'lerinin ortalama
> `criticality_level`'i 7'yi aşarsa: kurum, yüksek kritiklikli bir
> dalganın altında demek. Genelde SGB'de yeni kampanya yayını (yaygın
> oltalama dalgası vb.) ile korelasyonludur. SOC manager için saatlik
> dashboard refresh.

## Bu use case nedir? (Basit anlatım)

Bireysel use case'ler tek tek olayları yakalar. Bu meta-kural ise
**kurum genelinde dalga var mı?** sorusunu cevaplar. SGB feed'inde
yeni bir kampanya yayınlandığında (örn. ulusal çapta phishing
kampanyası) match sayısı patlar ve kritiklik ortalaması yükselir.

Severity dinamiktir:
- avg criticality 7-8 → severity 7
- avg 8-9 → severity 8
- avg > 9 → severity 10

Bu sinyal SOC manager'a "Dikkat, kurum hedeflenmiş olabilir, ekstra
göz at" demektir.

## Senaryo (Hikâye)

- 14:00-15:00 — Saatlik pencere: 87 SGB match, ortalama criticality 8.2.
- 15:00:30 — UC-XX-003 koşulu sağlandı: avg=8.2 > 7, count=87 > 50.
- 15:00:31 — Severity 8 alarm SOC manager dashboard'una.
- Aksiyon: SGB API'ye manuel kontrol, yeni kampanya duyurusu var mı?

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Anomaly detection kuralı. |
| **3.1.10.5** | Siber Olay Raporlarının Standardize Edilmesi | Dalga durumu raporu için input. |
| **3.1.10.8** | Siber Olay Puanlama ve Önceliklendirme | Dinamik puanlama örneği. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-XX-003 |
| MITRE | (cross — emergent campaign indicator) |
| Connectiontype | XX (meta) |
| Severity (base) | dinamik (7-10) |
| Veri kaynakları | Tüm SGB notable event'ları |
| Reference / lookup | `SGB_*_MAP` (criticality alanı) |

## Tespit mantığı

```text
window = 1 saat
trigger:
  avg(criticality_level) > 7 AND count(matches) > 50
severity_out = ceil(avg(criticality)) capped at 10
```

## QRadar uygulaması

Anomaly Detection rule on custom property "SGB Criticality";
AQL search scheduled / 1h, threshold action.

## Splunk uygulaması

```spl
`sgb_notable_index` earliest=-1h
| stats avg(criticality_level) AS avg_crit count by date_hour
| where avg_crit > 7 AND count > 50
| eval severity=min(10, ceil(avg_crit))
```

## Yanlış pozitif notları

- **Yeni rule deployment** ilk gün gürültü yapar → 24 saatlik grace
  window.
- **SGB feed quality issue** (yanlışlıkla tüm kayıtlar crit=9
  işaretlendi) → SGB API audit script (`scripts/sync.py` log'larında
  doğrula).
- **Holiday traffic spike'ları** → mevsimsel ayarlama.

## Olay müdahale

**Otomatik:**
1. SOC manager dashboard → kırmızı uyarı.
2. Slack / Teams kanalına "Wave detected" bildirimi.

**Manuel:**
1. SGB resmi duyurularını kontrol et — yeni kampanya var mı?
2. En çok hit yapan CT'ler hangileri? Hedeflenen sektör/kurum?
3. SGB raporlaması (3.1.10.5) ek bilgi olarak: kurum içi etki tahmini.
4. Ek önlem: WAF/proxy block list'i daha agresif moda geç.
