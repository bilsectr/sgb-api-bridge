# UC-PH-001 — Kurum İçinden SGB Phishing Domain'ine DNS Sorgusu

> **TL;DR:** Bir kurum bilgisayarı, SGB'nin "oltalama (phishing)" olarak
> işaretlediği bir alan adına DNS sorgusu yaptığında alarm üretir. Yani
> kullanıcı henüz tıklamadan, sadece sayfa açılmaya çalışılırken yakalanır.

## Bu use case nedir? (Basit anlatım)

Bir kullanıcı bilgisayarında web sayfası açmaya çalışınca önce **DNS sorgusu**
yapılır: "evilbank-login.example sitesinin IP adresi neymiş?" Bu sorgu kurum
DNS sunucusundan (BIND, Windows DNS, Infoblox, Cisco Umbrella vb.) geçer ve
log'a düşer.

SGB API'sinden çektiğimiz **phishing alan adı listesi** SIEM'e
`SGB_PH_DOMAIN` reference set / lookup olarak yüklenmiştir. SIEM, her DNS
log'unu bu listeyle karşılaştırır. Eşleşme olursa — yani sorgu yapılan
alan adı SGB'nin oltalama listesinde varsa — alarm üretir.

## Senaryo (Hikâye)

- 09:47 — Kullanıcı `ahmet.yilmaz` Outlook'tan gelen bir maildeki
  "Güvenlik Bildirimi" linkine tıklar.
- 09:47:01 — Cihazı `bankaresmi-tr.example` için DNS sorgusu yapar.
- 09:47:01 — Kurum DNS sunucusu log üretir; SIEM bu log'u aynı saniye alır.
- 09:47:02 — SIEM, `bankaresmi-tr.example` adını `SGB_PH_DOMAIN` set'inde
  bulur (SGB'nin oltalama listesinde).
- 09:47:02 — Severity 5 (criticality modifier ile 6-8'e kadar çıkabilir)
  alarm açılır. SOC ekrandan görür; SOAR otomatik olarak browser'a uyarı
  pop-up'ı düşürür ve URL'yi proxy'de bloklar.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.5.1** | Zararlı Yazılımdan Korunma Uygulamalarının Kullanılması ve Merkezi Yönetimi | SGB phishing domain veri tabanını "güncel imza/IoC kaynağı" olarak DNS savunmasına entegre eder. |
| **3.1.5.7** | DNS Sorgularının Kayıtlarının Tutulması | DNS log'larının **anlamlandırılmasını** sağlar (sadece kayıt değil, "zararlı mı?" cevabı). |
| **3.1.6.20** | A Tabanlı URL Filtreleri Kullanımı | DNS katmanında ön filtrelemenin delili. URL filtreleme tek başına yetersizdir; DNS de filtrelenmeli. |
| **3.1.4.10** | E-Posta Hizmetleri Zararlı Yazılımdan Korunma | Phishing kaynaklı maillerin tıklanması sonucu üretilen DNS hit'i bu tedbirin uçtan uca işlediğinin kanıtıdır. |
| **3.1.8.6** | Merkezi Kayıt Yönetimi | Üretilen alarm SIEM offense'ı olarak merkezde tutulur. |
| **3.1.8.7** | Kayıt Analizi Araçları Kullanımı (SIEM) | Bu use case'in kendisi maddenin operasyonel karşılığıdır. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB'den gelen bildirimin "gerekli önleme" dönüştürüldüğünün somut delili. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-PH-001 |
| MITRE ATT&CK | TA0001 Initial Access / T1566.002 Spearphishing Link |
| Connectiontype | PH |
| Severity (base) | 5 (kritiklik modifier ile yükselir) |
| Veri kaynakları | DNS query log (BIND, Windows DNS, Infoblox, Cisco Umbrella, Pi-hole) |
| Reference set / lookup | `SGB_PH_DOMAIN` + `SGB_DOMAIN_MAP` (zenginleştirme için) |
| Response playbook | PB-PH-001 (kullanıcı uyarısı + URL blok + EDR taraması) |

## Tespit mantığı (vendor-bağımsız)

```text
when DNS query event geldi
  AND query alanı SGB_PH_DOMAIN set'inde
  AND kaynak ağ "Trusted" (kurum içi)
then offense aç (severity=5 + criticality)
     ve kaynak IP'yi SGB_SUSPECTED_HOSTS set'ine ekle (TTL 7 gün)
```

## QRadar uygulaması

**Kural tipi:** Event Rule

**Test bloğu:**
```
when the event QID is one of the following: DNS Query QIDs
  AND when any of these event properties (URL/Hostname) is contained in
      any of these reference set(s): SGB_PH_DOMAIN
  AND when the destination network is one of the following: Trusted
```

**Response bloğu:**
- Dispatch new event named **"SGB Phishing DNS"**
- Magnitude severity: 5 (criticality modifier rule action ile uygulanır;
  bkz. [severity-matrix.md](../../siem/qradar/severity-matrix.md))
- Annotate offense: "SGB phishing domain match — bkz. UC-PH-001"
- Reference set: add source IP to `SGB_SUSPECTED_HOSTS`
- (Opsiyonel) Email notification + SOAR webhook

AQL test sorgusu: [siem/qradar/aql/uc-ph-001-test.aql](../../siem/qradar/aql/)

## Splunk uygulaması

**Saved search adı:** `SGB - UC-PH-001 - Phishing DNS query`

**Macro:** `sgb_dns_phishing_search`

**SPL özeti:**
```spl
`sgb_dns_index`
| lookup sgb_domain_lookup value AS query OUTPUT connectiontype, criticality_level, source
| where connectiontype="PH"
| eval severity=5 + criticality_level
| stats count by src_ip, query, source, severity
```

Bkz. [siem/splunk/TA-sgb-threatintel/default/savedsearches.conf](../../siem/splunk/TA-sgb-threatintel/)

## Yanlış pozitif (False Positive) notları

- **SGB IH (ihbar) kaynaklı domain'ler** daha yüksek FP'lidir. İki seçenek:
  - `source=IH` kayıtları ayrı bir reference set'e koy (`SGB_PH_DOMAIN_IH`)
    ve kural buna severity=3 ile dokunsun.
  - Veya tek set'te tut ama rule action içinde `SGB_SRC != "IH"` filtresi ekle.
- **Threat intel araştırma yapan asset'ler** (SOC analyst workstation,
  sandbox host, VirusTotal proxy) doğal olarak phishing domain'lere DNS
  sorgusu yapar → bu host'ları **exception listesine** ekleyin
  (örn. `SGB_PH_EXEMPT_ASSETS`).
- **Email gateway URL rewriting** (Proofpoint, Mimecast, M365 Safe Links)
  orijinal URL'yi gizleyebilir; rewriting'i decode eden parser kuralı şart.

## Olay müdahale (Response playbook PB-PH-001)

**Otomatik adımlar:**
1. Source IP'yi `SGB_SUSPECTED_HOSTS` set'ine ekle (TTL 7 gün).
2. SOAR ticket aç (severity ile orantılı queue).
3. Browser ekran uyarısı + URL'yi proxy'de blok (ön onay olduysa otomatik).

**Manuel triage adımları:**
1. SOC analyst: kullanıcıyı ara, "Mailden link tıkladınız mı?" sor.
2. Tıkladıysa: EDR full scan başlat, browser history / download history al.
3. Mail kaynağını analiz et — aynı maildeki diğer alıcılara da gönderildi mi?
   (UC-PH-003 ile cross-reference)
4. Olay kapanışı: kullanıcıya farkındalık eğitimi linki gönder.

**SGB raporlamasına etkisi (3.1.10.5):** AC değil PH olduğu için P1
raporlama gerekmez; haftalık özet raporda yer alır.
