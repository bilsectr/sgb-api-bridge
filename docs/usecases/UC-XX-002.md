# UC-XX-002 — Aynı Indicator 7 Gün İçinde Aynı Asset'te 2x Tekrar Etti

> **TL;DR:** 7 günlük pencerede aynı asset, aynı SGB indicator değerine
> yeniden hit ettiyse: ya önceki IR remediation eksik kaldı, ya yeni
> infeksiyon aynı altyapıya bağlandı (persistence mechanism var).
> Severity 7. SOC operasyon metriği olarak da kullanılır
> (re-infection rate).

## Bu use case nedir? (Basit anlatım)

Bir asset'in compromise olup temizlendiği varsayalım. Eğer 7 gün içinde
aynı indicator'a (aynı IP/domain/URL değerine) yeniden hit ediyorsa:

1. Temizleme eksik kaldı (persistence binary hala disk'te).
2. Veya aynı kullanıcı aynı phishing maili tekrar tıkladı.
3. Veya saldırgan yeniden geldi (bookmark, başka mail, vb.).

Bu durum SOC operasyonunun **kalitesi**nin metriğidir — re-infection
rate düşük olmalı.

## Senaryo (Hikâye)

- Salı 14:00 — `WIN-LAB-31` `evil-domain.example`'a hit etti, IR kapatıldı.
- Cuma 09:00 — Aynı host aynı `evil-domain.example`'a tekrar hit.
- 09:00:01 — `SGB_ASSET_HIT_HISTORY` lookup'ı "var" diyor → UC-XX-002
  severity 7 alarm. IR'a "re-infection — remediation kontrol et" notu.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Tarihsel korelasyon. |
| **3.1.10.8** | Siber Olay Puanlama ve Önceliklendirme | Re-infection = öncelik artırılması gerek. |
| **3.5.2** Eğitim ve Farkındalık | Aynı kullanıcı tekrar tıkladıysa farkındalık gap'i. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-XX-002 |
| MITRE | TA0003 Persistence — IR ineffectiveness signal |
| Connectiontype | XX (meta) |
| Severity (base) | 7 |
| Veri kaynakları | Tüm SGB notable event'lar (kendi geçmişimiz) |
| Reference / lookup | `SGB_ASSET_HIT_HISTORY` (key=asset|indicator, value=last_seen, TTL 7d) |

## Tespit mantığı

```text
when herhangi SGB_* match
  AND aynı (asset + indicator) son 7 günde daha önce hit oldu
then alarm, severity=7, "re-infection"
```

## QRadar uygulaması

Reference Map `SGB_ASSET_HIT_HISTORY` (key=asset|indicator, value=last_seen).
Rule: SGB match → lookup → varsa escalate.

## Splunk uygulaması

```spl
`sgb_notable_index` earliest=-7d
| stats dc(_time) AS hits count AS total values(sgb_ct) AS ct
        by src_ip, sgb_indicator_value
| where hits >= 2
```

## Yanlış pozitif notları

- **Cron-based scanner / monitoring** tekrarlı request → exception by
  source asset role.
- **Kullanıcı bookmark'ında** kaydedilmiş phishing link tekrar tıklanıyor
  → kullanıcı farkındalık eğitimi + browser plugin uyarısı.

## Olay müdahale

**Manuel:**
1. Önceki IR ticket'ı bul, kapatma notlarını incele.
2. Remediation steps tamamlandı mı? (EDR scan, parola değişimi, vs.)
3. Persistence kontrol (autoruns, scheduled tasks, services).
4. Aynı kullanıcı için farkındalık eğitimi.
