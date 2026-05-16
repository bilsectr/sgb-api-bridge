# UC-XX-NNN — <Kısa Türkçe Başlık>

> **TL;DR:** 1-2 cümlelik özet. Bu use case neyi yakalar, kim için değerli?

## Bu use case nedir? (Basit anlatım)

(2-4 paragraf, teknik olmayan da anlasın. Hangi senaryo, hangi log
kaynağında, hangi SGB feed alanı, nasıl korelasyon.)

## Senaryo (Hikâye)

(Zaman çizelgeli somut bir örnek olay. 4-6 satır. Saatler kullan.)

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.x.y.z** | ... | ... |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB feed kullanımı (her UC ortak). |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | SIEM korelasyon (her UC ortak). |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-XX-NNN |
| MITRE ATT&CK | TAxxxx / Txxxx |
| Connectiontype | PH/BC/AC/EK/MF/MM/MC/OT/XX |
| Severity (base) | 1-10 (severity-matrix.md formülü) |
| Veri kaynakları | (DNS, Proxy, Firewall, EDR, Email, MDM, ...) |
| Reference / lookup | `SGB_<CT>_<TYPE>`, `SGB_<TYPE>_MAP` |
| Response | PB-XX-NNN (varsa) |

## Tespit mantığı (vendor-bağımsız)

```text
when <event geldi>
  AND <SGB lookup eşleşti>
  AND <ek filter>
then <aksiyon>
```

## QRadar uygulaması

- Reference set/map: `SGB_*`
- Rule türü: Event Rule / Flow Rule / Common Rule
- AQL test: [siem/qradar/aql/uc-xx-nnn-test.aql](../../siem/qradar/aql/)

```
when ...
```

## Splunk uygulaması

- Saved search: `SGB - UC-XX-NNN - <title>`
- Macro: `sgb_<name>_search`
- Lookup: `sgb_<ip|domain|url>.csv`

```spl
...
```

## Yanlış pozitif (False Positive) notları

- Bilinen FP kaynakları + suppress/exception önerileri
- `source=IH` için güvenirlik düşürme stratejisi

## Olay müdahale (Response playbook)

**Otomatik adımlar:**
1. ...

**Manuel triage adımları:**
1. ...

**SGB raporlama etkisi (3.1.10.5):** (varsa)
