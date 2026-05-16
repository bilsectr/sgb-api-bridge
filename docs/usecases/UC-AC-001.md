# UC-AC-001 — Herhangi Bir Yönden / Herhangi Bir Log Kaynağında SGB APT C&C Eşleşmesi

> **TL;DR:** SGB'nin "APT (Advanced Persistent Threat) C&C" olarak
> işaretlediği bir indicator herhangi bir log'da herhangi bir alanda
> görülürse — IP, domain, URL, file hash, mail, DNS — anında P1 (kritik
> seviye) olay açılır. **AC eşleşmeleri nadirdir ve her birine
> tek tek manuel triage uygulanır.**

## Bu use case nedir? (Basit anlatım)

APT (Gelişmiş Sürekli Tehdit) = devlet destekli veya çok organize
saldırı grupları (örn. Lazarus, APT28, APT41). SGB'nin AC feed'i
bu grupların kullandığı **bilinen C&C alt yapısını** içerir.

Botnet (BC) genelde "yağmurda 100 makineyi sırf spam için kapsayan"
saldırılarken APT (AC) **hedefli ve sessiz**dir; tek bir match bile
ciddiye alınır. Bu yüzden UC-AC-001'in eşik (threshold)'u **1'dir** —
tek eşleşme yetiyor.

UC-AC-001 her tip log kaynağında, her tip indicator alanında çalışır.
Geniş kapsamlı bir "guard rail" kuralıdır.

## Senaryo (Hikâye)

- 04:17 — `LIN-MAIL-02` mail sunucusundan tek bir SMTP bağlantısı
  Lazarus tarafından kullanıldığı bilinen `92.X.X.X` IP'sine giriyor.
- 04:17:01 — SIEM AC reference set'inde IP'yi görür.
- 04:17:01 — Severity 10 sabit P1 alarm — SOC manager telefonundan
  ses + e-posta + SMS.
- 04:17:30 — Otomatik response: host izole, packet capture başlat,
  diğer host'lardan aynı IP'ye trafik var mı diye geniş arama.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.10.4** ⭐ | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB APT feed'i operasyonel kullanım — bu UC tam karşılığıdır. |
| **3.1.10.5** | Siber Olay Raporlarının Standardize Edilmesi ve Yayınlanması | AC seviyeli olay → SGB ve Sektörel SOME'ye anında rapor zorunluluğu. |
| **3.1.10.8** | Siber Olay Puanlama ve Önceliklendirme | AC = sabit 10 = en yüksek puan. |
| **3.1.5.6** | Zararlı Yazılım Tespitlerinin Merkezi Tutulması | AC alarm offense merkezde tutulur. |
| **3.1.8.6** | Merkezi Kayıt Yönetimi | Aynı. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Bu UC kapsamlı SIEM korelasyonudur. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-AC-001 |
| MITRE | TA0011 / T1071 + TA0001 Initial Access (genel) |
| Connectiontype | AC |
| Severity | **10 (sabit)** — criticality bile etkilemez |
| Veri kaynakları | TÜM log source'lar (firewall, proxy, DNS, EDR, mail, IDS, OS) |
| Reference / lookup | `SGB_AC_IP`, `SGB_AC_DOMAIN`, `SGB_AC_URL` |
| Response | PB-AC-001 (P1 incident, CSIRT/SOC manager paging, lockdown) |

## Tespit mantığı

```text
when herhangi log event geldi
  AND any of (source_ip, dest_ip, url, hostname, dns_query,
              file_hash, mail_from, mail_to) IN
              (SGB_AC_IP, SGB_AC_DOMAIN, SGB_AC_URL)
then offense aç, severity=10 sabit
     SOC manager paging + SOAR P1 playbook
```

## QRadar uygulaması

**Kural tipi:** Generic high-priority rule.

```
when any of these properties:
  Source IP, Destination IP, URL, Hostname, DNS Query,
  File Hash, Email From, Email To
is contained in any of these reference sets:
  SGB_AC_IP, SGB_AC_DOMAIN, SGB_AC_URL
```

**Response:**
- Magnitude severity: **10 (sabit)**
- Dispatch event: "SGB APT C2 Match — <hostname/ip>"
- Annotate offense + auto-assign to "APT" offense category
- Add source asset to `SGB_AC_TARGETS` (kalıcı, TTL yok)
- SOAR webhook + SMS + email pager
- (Opsiyonel) Firewall block list'e otomatik push — sadece source IH
  değilse ve otomasyon ön onayı varsa.

## Splunk uygulaması

**Saved search:** `SGB - UC-AC-001 - APT C2 match`

```spl
(`sgb_all_indexes`)
| eval test_values=mvappend(src_ip, dest_ip, url, query, hostname, file_hash, sender, recipient)
| mvexpand test_values
| lookup sgb_ip_lookup    value AS test_values OUTPUT connectiontype AS ct_ip
| lookup sgb_domain_lookup value AS test_values OUTPUT connectiontype AS ct_dom
| lookup sgb_url_lookup    value AS test_values OUTPUT connectiontype AS ct_url
| where ct_ip="AC" OR ct_dom="AC" OR ct_url="AC"
| eval severity=10
```

## Yanlış pozitif notları / Tuning

- **AC eşleşmeleri nadirdir;** ama threat hunting / sandbox host'ları AC
  IP'leriyle bilerek konuşur → mutlaka exception listesi.
- **Source = IH (ihbar) kayıtları:** AC'de bile yanlış olabilir, ama
  güvenlik tarafında abartmak iyidir — alarm aç, ama otomatik block
  yapma; manuel onay iste.
- **Aynı host 30 dk içinde 3+ AC match ederse** ayrı meta-rule
  [UC-AC-002](UC-AC-002.md) tetiklenir = "kesin compromise".

## Olay müdahale (PB-AC-001 — P1 playbook)

**Otomatik (saniyeler içinde):**
1. SOC manager + IR yöneticisi pager (SMS + telefon).
2. EDR host isolate (sadece IR uzmanları bağlanabilir).
3. Full packet capture başlat (host + dış trafik mirror).
4. SOAR'da P1 ticket aç.

**Manuel (1 saat içinde):**
1. Asset criticality değerlendirmesi: bu host kritik veri mi tutar?
2. CSIRT toplantısı (kurum içi + ihtiyaç hâlinde Sektörel SOME).
3. SGB raporlaması (3.1.10.5): standart formatta vaka raporu, 24
   saat içinde SGB'ye iletilir.
4. Forensic adımlar: disk imaging, memory dump, log toplama.
5. Eş zamanlı: aynı C&C indicator'ına başka host'tan trafik var mı?
   (UC-AC-002 ile cross-reference)

**Kalıcı önlemler:**
- AC indicator'ı kalıcı firewall block listesine geç.
- Asset için "post-incident monitoring" 30 gün.
