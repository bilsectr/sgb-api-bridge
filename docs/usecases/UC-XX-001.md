# UC-XX-001 — Aynı Asset 24 Saat İçinde 2+ Farklı Connectiontype'a Hit Etti

> **TL;DR:** Tek bir host 24 saat içinde birden fazla farklı SGB CT'sine
> hit ettiyse (örn. PH + MF + BC) **çok aşamalı (multi-stage) compromise**
> sinyali. Severity 8 — tek bir CT'nin baseline severity'lerini override
> eder.

## Bu use case nedir? (Basit anlatım)

Saldırılar genelde tek tip log üretmez:
- **PH** (phishing tıklama)
- → **MF** (malware download)
- → **BC** (botnet C&C bağlantısı)

= klasik 3-aşamalı saldırı zinciri. Tek tek bakıldığında her biri kendi
severity'sinde alarm verir. Bu meta-kural, **aynı kaynak host'tan 2+
farklı CT** ardışık olarak çıkarsa "compromise zinciri ilerliyor" deyip
escalate eder.

Pattern multi-source korelasyonun klasik örneğidir; BG Rehberi 3.1.8.7
"korelasyon kuralları doğrultusunda tespit" maddesinin önemli bir
parçasıdır.

## Senaryo (Hikâye)

- 09:00 — `WIN-FIN-22` UC-PH-001 tetikledi (DNS sorgusu phishing
  domain'e).
- 09:30 — Aynı host UC-MF-001 tetikledi (proxy'den malware indirdi).
- 11:00 — Aynı host UC-BC-001 tetikledi (botnet C&C bağlantısı).
- 11:00:01 — Distinct CT count = 3 (>2) → UC-XX-001 severity 8 alarm.
  Multi-stage compromise.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Korelasyon kuralı tam karşılığı. |
| **3.1.8.8** | SIEM Düzenli Yapılandırma | Meta-rule akıllı yapılandırma örneği. |
| **3.1.10.8** | Siber Olay Puanlama ve Önceliklendirme | Tek match'leri override eden risk modelleme. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-XX-001 |
| MITRE | TA0011 + multi-stage |
| Connectiontype | XX (meta) |
| Severity (base) | 8 (tek CT severity'lerini override) |
| Veri kaynakları | UC-PH/BC/AC/EK/MF/MM/MC çıktıları aggregate |
| Reference / lookup | `SGB_*_MAP` (CT bilgisi) |

## Tespit mantığı

```text
window = 24 saat
group_by = src_asset
distinct_count(SGB connectiontype) >= 2
=> escalate, severity=8, offense category "Multi-Stage Compromise"
```

## QRadar uygulaması

**Aggregator:** UC-PH-* OR UC-BC-* OR UC-AC-* OR UC-EK-* OR UC-MF-* OR
UC-MM-* OR UC-MC-* match'lerini source IP bazında topla, distinct count
"SGB_CT" custom property >=2.

## Splunk uygulaması

```spl
`sgb_notable_index` earliest=-24h
| stats dc(sgb_ct) AS n_cts values(sgb_ct) AS ct_list count AS hits by src_ip
| where n_cts >= 2
```

## Yanlış pozitif notları

- **Threat hunting / SOC analyst workstation** çoklu CT'ye dokunabilir →
  exception listesi.
- **NAT gateway'ler** tüm kullanıcıyı tek IP'de toplar → NAT subnet
  exception listesi şart.

## Olay müdahale

**Otomatik:**
1. Severity 8 → SOAR P2 ticket.
2. Aynı asset'in son 24h tüm log'larını "compromise timeline" raporuna
   topla.

**Manuel:**
1. CT sırası saldırı zincirinin hangi aşamalarını gösteriyor?
   (PH→MF→BC veya BC→AC eskalasyonu vb.)
2. Host izole edilmeli mi? Asset criticality'ye göre karar.
3. SGB raporlama input'u (3.1.10.5).
