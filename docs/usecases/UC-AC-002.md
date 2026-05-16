# UC-AC-002 — Aynı Asset Üzerinde 30 Dakika İçinde 3+ Farklı APT C&C Eşleşmesi

> **TL;DR:** UC-AC-001 her tek eşleşmede alarm verir. Bu meta-kural ise
> **aynı host 30 dakika içinde 3 veya daha fazla FARKLI APT indicator'una**
> hit ederse tetiklenir. Tek match yanlış pozitif olabilir; 3+ ardışık
> match neredeyse kesin compromise demektir → otomatik host izolasyonu.

## Bu use case nedir? (Basit anlatım)

APT saldırıları multi-stage'tir: phishing → initial access → C&C bağlantısı
→ lateral hareket → exfiltration. Bir host aynı kısa pencere içinde birden
çok APT indicator'ına dokunuyorsa, saldırının birden fazla aşamasına
katıldığını gösterir.

Eşik 3 olmak üzere ayarlandı çünkü:
- 1 match: olabilir (UC-AC-001 zaten yakalar).
- 2 match: şüpheli ama belki tesadüf veya threat hunting.
- 3+ match: artık tesadüf değildir, **immediate host isolation**.

## Senaryo (Hikâye)

- 13:01 — `WIN-HR-09` SGB AC IP `92.X.X.X`'e DNS sorgusu yapar (1. hit).
- 13:08 — Aynı host SGB AC URL `https://updateserv.example/agent` indirir
  (2. hit).
- 13:15 — Aynı host SGB AC domain `c2.evilapt.example`'a bağlanır (3. hit).
- 13:15:01 — UC-AC-002 koşulu doluyor (3 distinct match / 30 dk / aynı asset).
- 13:15:02 — Severity 10 sabit + otomatik host isolation playbook.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Multi-source korelasyonun klasik örneği. |
| **3.1.10.4** ⭐ | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB AC feed'inden çoklu sinyal birleştirme. |
| **3.1.10.5** | Siber Olay Raporlarının Standardize Edilmesi | Bu seviye olay zorunlu SGB raporlaması içerir. |
| **3.1.10.8** | Siber Olay Puanlama ve Önceliklendirme | Çoklu match = en yüksek öncelik (P1+). |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-AC-002 |
| MITRE | TA0011, TA0001 (initial access/C2 onayı) |
| Connectiontype | AC (aggregate) |
| Severity (base) | 10 (sabit, lockdown trigger) |
| Veri kaynakları | UC-AC-001'in alt setiyle aynı (tüm log sourceları) |
| Reference / lookup | `SGB_AC_IP`, `SGB_AC_DOMAIN`, `SGB_AC_URL` |
| Response | PB-AC-002 (immediate host isolation, no manual approval) |

## Tespit mantığı

```text
window = 30 dakika
group_by = source_asset
distinct_count(SGB_AC_indicator_value) >= 3
=> escalate, severity=10, AUTO host isolate
```

## QRadar uygulaması

**Kural tipi:** Common Rule (aggregator)

```
when these rules match: UC-AC-001
THEN match must occur at least 3 times in 30 minutes
     with the same source IP
     AND with different "SGB Indicator Value"
```

**Response:**
- Severity 10
- Dispatch "SGB APT Confirmed — multi-match"
- SOAR host isolation playbook (ön onay BYPASS — AC seviyesinde otomatik)

## Splunk uygulaması

**Saved search:** `SGB - UC-AC-002 - APT confirmed (3+ matches)`

```spl
`sgb_notable_index` (sgb_ct="AC") earliest=-30m
| stats dc(sgb_indicator_value) AS distinct_matches
        values(sgb_indicator_value) AS matched_values by src_ip
| where distinct_matches >= 3
```

## Yanlış pozitif notları

- **SOC sandbox / malware analysis host'ları:** kasten AC indicator'larıyla
  konuşurlar → dedicated source asset group olarak `SGB_AC_EXEMPT_ASSETS`
  set'ine ekleyin.
- **Vulnerability scanner outbound trafiği:** ağ tarama amaçlı geniş
  bağlantılar → exception (scanner asset listesi).
- **Threat hunting sırasında manuel sorgular** → temporary exception
  flag (analyst kullanıcı = src bilgisiyle).

## Olay müdahale (PB-AC-002)

**Otomatik (saniyeler):**
1. EDR host isolate — onay aranmaz, AC seviyesinde otomatik.
2. Firewall: src_ip için tüm dış trafik bloke.
3. P1 ticket + SOC manager + CSO pager.
4. Tüm matched indicator'lar packet capture filtresine eklenir.

**Manuel (15 dakika):**
1. CSIRT etkinleşir.
2. Asset risk değerlendirmesi.
3. Geniş hunt: aynı 3+ indicator'a hit eden başka asset var mı?
4. SGB raporlaması: vakanın özeti + indicator hash + zaman çizelgesi.

**Sonraki adımlar:**
- IR ekibi tarafından host imaj ı + memory dump.
- 90 günlük geçmiş logları aynı indicator'lar için geri tara.
- CSIRT raporu kuruma içi + Sektörel SOME'ye.
