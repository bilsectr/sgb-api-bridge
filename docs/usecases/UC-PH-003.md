# UC-PH-003 — Gelen E-postanın Body'sinde SGB Phishing Domain/URL Linki

> **TL;DR:** Mail gateway, gelen e-postaların gövdesindeki linkleri tek tek
> kontrol eder. Eğer link SGB phishing listesinde bir yere işaret ediyorsa,
> **kullanıcı henüz maili açmadan / link'e tıklamadan** alarm üretir.
> Erken uyarı katmanıdır.

## Bu use case nedir? (Basit anlatım)

Kurumunuza e-posta Proofpoint / Mimecast / Cisco ESA / Microsoft 365 ATP
gibi bir Secure Email Gateway (SEG) üzerinden girer. SEG her mailin
body'sini parse eder ve içindeki URL'leri log'lar.

SGB phishing domain ve URL listeleri (`SGB_PH_DOMAIN`, `SGB_PH_URL`) ile
karşılaştırma yapan SIEM kuralı: bir mail gönderildi mi, link içeriyor mu,
link zararlı liste içinde mi? Cevap "evet" ise:

- UC-PH-001 / UC-PH-002 tıklandığında tetiklenir (geç uyarı).
- UC-PH-003 **mail teslim aşamasında** tetiklenir (erken uyarı).

Bu sayede SOC: "Bu kullanıcıya phishing maili geldi, henüz tıklamadı, mail
silindi/karantinaya alındı" diyebilir.

## Senaryo (Hikâye)

- 08:30 — Saldırgan, `IT-Helpdesk@example` adında sahte göndericiyle 200
  kişiye mail atar; mail body: "Parolanız sıfırlanacak, buradan onaylayın
  → https://yenisifre.example/reset".
- 08:30:15 — Proofpoint mail'i alır, SPF/DKIM bayrakları işler.
- 08:30:16 — Proofpoint body URL'sini parse eder, gateway log'una düşer.
- 08:30:18 — SIEM `yenisifre.example` adresinin `SGB_PH_DOMAIN`'de
  olduğunu görür → severity 6 alarm (delivered durum baseline 5'den +1).
- 08:30:20 — SOC SOAR akışı: mail'i tüm 200 alıcının inbox'undan
  graph API/EWS ile çek (recall); kullanıcılara bilgilendirme gönder.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.4.10** | E-Posta Hizmetleri / Zararlı Yazılımdan Korunma | Doğrudan karşılık. Mail body link'leri için "zararlı içerik kontrolü". |
| **3.1.5.1** | Zararlı Yazılımdan Korunma Uygulamaları + Merkezi Yönetim | SGB feed'i merkezi yönetilen IoC kaynağıdır. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Mail gateway log'unu SIEM'de korelasyona sokar. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB bildirimi → mail seviyesinde önlem. |
| **3.5.2** Eğitim ve Farkındalık | Aday alıcı listesi farkındalık eğitimi için input olur. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-PH-003 |
| MITRE | TA0001 / T1566.002 |
| Connectiontype | PH |
| Severity (base) | 6 (mail teslim edilmiş — exposure aşaması; PH-001'den 1 yüksek) |
| Veri kaynakları | Mail gateway / SEG (Proofpoint, Mimecast, Cisco ESA, M365 ATP) |
| Reference / lookup | `SGB_PH_DOMAIN`, `SGB_PH_URL` |
| Response | PB-PH-003 (mail recall + kullanıcı bilgilendirme + asset takip) |

## Tespit mantığı

```text
when mail gateway event geldi
  AND parse edilen body_url alanı SGB_PH_DOMAIN veya SGB_PH_URL set'inde
  AND mail "Delivered" durumda (yani karantinaya alınmadıysa)
then offense aç, severity=6
     ve recipient'i SGB_PHISH_TARGETS set'ine ekle (TTL 30 gün)
```

## QRadar uygulaması

**Kural tipi:** Event Rule (mail log source type filtresi şart)

**Custom property:** `Body URL`, `Embedded URL` — parser bunları çıkarmalı.

```
when log source group is "Mail Gateways"
  AND when any of (Body URL, Embedded URL) is in (SGB_PH_DOMAIN, SGB_PH_URL)
  AND when delivery status is one of: "Delivered", "Inbox"
```

**Response:**
- Notify ITSec + add recipient to `SGB_PHISH_TARGETS` (TTL 30d)
- Trigger SOAR mail recall playbook (M365 Graph API / EWS)

## Splunk uygulaması

**Saved search:** `SGB - UC-PH-003 - Email phishing link delivered`

```spl
`sgb_mail_index` action=delivered
| rex field=body "https?://(?<body_domain>[^/\"\s]+)"
| lookup sgb_domain_lookup value AS body_domain OUTPUT connectiontype
| where connectiontype="PH"
| stats values(recipient) AS recipients count by sender, body_domain
```

## Yanlış pozitif notları

- **Phishing simülasyon eğitim platformları** (KnowBe4, Cofense PhishMe)
  bilerek phishing benzeri mail gönderir → simulation domain'leri için
  beyaz liste (`SGB_PHISH_SIM_DOMAINS`).
- **News/legitimate site** maillerindeki linkler bazen yanlışlıkla SGB
  listesinde olabilir (özellikle paylaşımlı hosting'de) → SOC weekly
  whitelist review.
- **External tag'li mailler** + zaten kullanıcı bilgilendirme akışı varsa
  alarm gürültüsü artar; threshold "delivered AND no-prior-notice" filtrele.

## Olay müdahale (PB-PH-003)

**Otomatik:**
1. Mail'i tüm alıcıların inbox'undan recall (M365 Graph API).
2. Recipient(lar)ı `SGB_PHISH_TARGETS` set'ine ekle.
3. Mail gateway block listesine sender domain ve URL ekle.

**Manuel:**
1. Aynı kampanyadan başka mail var mı? Sender ve subject pattern ile arama.
2. Hangi kullanıcılar tıkladı? UC-PH-001 / UC-PH-002 ile cross-reference.
3. Tıklayan + form doldurmuş ihtimali → IAM ekibine eskalat (parola
   sıfırlama, MFA challenge).
4. SGB raporlaması: kampanya bilgisini SGB'ye geri bildir (3.1.10.5).
