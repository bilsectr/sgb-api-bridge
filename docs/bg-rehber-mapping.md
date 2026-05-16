# SGB API → SIEM/CTI Akışı ile Bilgi ve İletişim Güvenliği Rehberi (BG Rehberi) Uyum Eşleştirmesi

> **Bu dokümanın amacı:** Cumhurbaşkanlığı Dijital Dönüşüm Ofisi tarafından
> yayımlanan **Bilgi ve İletişim Güvenliği Rehberi**'nde (BG Rehberi, Temmuz 2020
> / güncel sürüm) yer alan tedbir maddelerinin, **SGB (Siber Güvenlik Başkanlığı)
> API'sinden çekilen tehdit istihbaratı (IoC: zararlı IP, alan adı, URL)** verisinin
> bir SIEM veya CTI platformuna akıtılması ile **somut, ölçülebilir ve denetlenebilir
> şekilde** nasıl karşılandığını göstermektir.
>
> Kısaca: "Bu projenin ürettiği veri akışı + use case kütüphanesi + entegrasyon
> kılavuzları kullanılarak, BG Rehberi'nin aşağıdaki maddelerinin uyum süreci için
> üretilmesi gereken **delil, kayıt, alarm ve raporlama** çıktılarının önemli bir
> kısmı üretilebilir."

---

## 1. Vizyon — Tek cümleyle ne yapıyoruz?

SGB, Türkiye'de gözlenen **zararlı IP / alan adı / URL** verisini bir REST API
üzerinden yayınlar. Bu proje (sgb-api-bridge), o API'yi düzenli olarak çeker,
verileri SIEM'lerin (QRadar, Splunk, Microsoft Sentinel) ve CTI platformlarının
(MISP, OpenCTI) anlayabileceği formatlara (reference set / lookup CSV /
STIX 2.1) dönüştürür ve her zaman aynı URL'den taze olarak indirilebilir hâlde
yayınlar. Üzerine vendor-bağımsız **use case** (alarm kuralı) kütüphanesi inşa
edilir.

Bu zincir, BG Rehberi'nin **3.1.10.4 Siber Tehdit Bildirimlerinin Yönetilmesi**
maddesinde geçen şu cümlenin **doğrudan teknik karşılığıdır**:

> "Kurumlar siber olayların tespiti için gerekli altyapıları kurmalı, **SGB ve
> olası diğer siber tehdit istihbarat kaynaklarından alınan bildirimler
> doğrultusunda gerekli önlemleri almalıdır.**"

Tek bir tedbire indirgenmez; aşağıdaki bölüm boyunca göreceğiniz gibi
**5 ana tedbir başlığı altında 30+ alt madde** için doğrudan veya destekleyici
delil üretir.

---

## 2. SGB API ne sağlar? Hızlı arka plan

SGB API'sinden çekilen her kayıtta üç önemli sınıflandırma alanı vardır
(detay: [memory: sgb_api_schema.md](../memory/sgb_api_schema.md)):

| Alan | Anlamı | Örnek |
|------|--------|-------|
| `desc` (Açıklama) | IoC'nin neyle ilgili olduğu | `Phishing`, `Botnet C&C`, `APT C&C`, `Malware`, `Mining`, `Exploit Kit`, `Mobile C&C` |
| `connectiontype` | Hangi protokol/ortam | `PH`, `BC`, `AC`, `MF`, `MM`, `EK`, `MC`, `OT` |
| `source` | Verinin kaynağı | `SGB`, `IH` (ihbar — daha düşük güvenirlik) |

Bu projede üretilen **kanonik tablo** (`feeds/sgb-master.csv` /
`feeds/sgb-master.jsonl`) bütün kayıtları yukarıdaki üç alan + zaman damgaları
ile birlikte yayar. SIEM'e taşınırken connectiontype bazında ayrı reference
set'lere bölünür: `SGB_PH_DOMAIN`, `SGB_BC_IP`, `SGB_AC_URL` …

---

## 3. BG Rehberi madde haritası — Hangi tedbire ne sağlıyoruz?

Aşağıdaki tabloda **sol sütun BG Rehberi'nin gerçek madde numarası**; orta
sütun maddenin özet beklentisi (rehberden); sağ sütun ise bu proje ile o
beklentinin nasıl karşılandığıdır.

### 3.1 Ağ ve Sistem Güvenliği

#### 3.1.4 — E-Posta Sunucusu ve İstemcisi Güvenliği

| Madde | Tedbirin özeti | Bu proje nasıl karşılar? |
|-------|----------------|--------------------------|
| **3.1.4.10** Zararlı Yazılımdan Korunma | E-postada zararlı içerik tespit edilmeli (3.1.5.1'e atıf yapar). | Phishing connectiontype'lı kayıtlar (PH) e-posta gateway'inize iletildiğinde gelen maillerdeki link/domain'leri kara listede arar. Bkz. [UC-PH-003 — E-mail body link → SGB phishing domain](usecases/UC-PH-003.md). |
| **3.1.4.6** Servis Dışı Bırakma Saldırıları | E-posta bombardımanı vs. tespit edilmeli. | Doğrudan kapsamımız dışıdır; ancak SGB botnet C&C IP'lerinden gelen SMTP bağlantıları [UC-BC-001](usecases/UC-BC-001.md) ile tespit edilebilir. |

**Hangi rapor / use case ile delillendirilir?** UC-PH-001, UC-PH-002, UC-PH-003

#### 3.1.5 — Zararlı Yazılımlardan Korunma

| Madde | Tedbirin özeti | Bu proje nasıl karşılar? |
|-------|----------------|--------------------------|
| **3.1.5.1** | Zararlı yazılımdan korunma uygulamaları kullanılmalı, **imza/IoC veri tabanı güncel** olmalı, politikalar **merkezi** yönetilmeli. | SGB IoC feed'i tam olarak bu "güncel imza/IoC veri tabanı"nın **dış kaynaklı, ulusal makamca onaylı** bileşenidir. Saatlik delta sync + `feeds-latest` rolling release URL'leri sayesinde imza tazeliği güvence altına alınır. |
| **3.1.5.6** | Tüm zararlı yazılım tespitleri **merkezi yönetim ve kayıt sunucularına iletilmeli**. | UC-MF-*, UC-BC-*, UC-EK-*, UC-MM-* use case'lerinin tetiklediği her alarm SIEM offense'ı / Splunk notable event'i olarak merkezi sistemde saklanır. |
| **3.1.5.7** | **DNS sorgu kayıtları** tutulmalı (zararlı IP'lere erişimin denetlenmesi için). | Bu kayıtların **anlamlandırılması** SGB feed'i ile mümkündür: DNS log → `SGB_*_DOMAIN` lookup'ı. UC-PH-001, UC-BC-002 buna doğrudan bağlıdır. |

#### 3.1.6 — Ağ Güvenliği

| Madde | Tedbirin özeti | Bu proje nasıl karşılar? |
|-------|----------------|--------------------------|
| **3.1.6.4** | **Kara liste veya beyaz liste** kullanılarak ağ erişimleri sınırlandırılmalı. | SGB feed'i, kara liste için **resmi, ulusal kaynaklı** içerik sağlar. Firewall/proxy entegrasyonları için txt slice'ları (`feeds/by-connectiontype/*.txt`) ve docs/ana sayfasındaki Fortinet/Palo Alto/pfSense kılavuzları doğrudan bu maddeye hizmet eder. |
| **3.1.6.5** | İzin verilmeyen trafik engellenmeli. | Aynı feed çıktısı blok listesine eklenir. UC-BC-001 / UC-AC-001 hit'leri "engellendi mi?" denetimini test eder. |
| **3.1.6.18** | **A tabanlı saldırı tespit/engelleme sistemi (IDS/IPS)** kullanılmalı. | IDS exploit alarmı + SGB EK feed kesişimi için [UC-EK-002](usecases/UC-EK-002.md) hazırdır. SIEM'de korelasyon kuralı olarak çalışır. |
| **3.1.6.20** | **URL filtreleri** kullanılmalı. | Proxy URL filtre + SGB phishing/malware URL feed birleşimi: UC-PH-002, UC-MF-001. |
| **3.1.6.21** | URL kategorilendirme servisi kullanılmalı. | SGB connectiontype alanı tam olarak bir kategori taksonomisidir (PH/BC/AC/EK/MF/MM/MC/OT). Bu projenin ürettiği `SGB_*_URL` reference set'leri proxy'lere bu kategorileri taşır. |
| **3.1.6.22** | URL'ler **kayıt altına alınmalı**. | Bu maddeyi SIEM ingest karşılar; SGB feed lookup'ı kayıttaki URL'leri "biliniyor mu" diye etiketler ve UC-PH-002 tetiklenir. |
| **3.1.6.28** | **Uygulama seviyesi saldırılara karşı WAF/IPS/DDoS** uygun konumlandırılmalı. | EK ve AC feed'lerinden gelen indicator'lar WAF/IPS kara listesine push edilebilir; UC-EK-001, UC-EK-002 buna yardımcı olur. |

#### 3.1.8 — İz ve Denetim Kayıtlarının Tutulması ve İzlenmesi (LOG)

| Madde | Tedbirin özeti | Bu proje nasıl karşılar? |
|-------|----------------|--------------------------|
| **3.1.8.1** | Tüm sistem ve ağ cihazlarında **kayıt mekanizması etkin** olmalı, kayıtlar belirli süre saklanmalı. | Bu madde "log üret" der; biz log'u **anlamlandırırız**. UC sonucu alarmlar ve "match'lendi" tag'leri ise yeni bir kayıt türüdür ve aynı politikaya tabidir. |
| **3.1.8.4** | Detaylı kayıt: olay, kaynak, zaman, kullanıcı, kaynak/hedef adres, işlem detayı. | Üretilen alarmlar (offense / notable) tam olarak bu alanlarla doldurulur (asset, SGB indicator value, connectiontype, criticality, first_seen_utc). |
| **3.1.8.6** | **Merkezi kayıt yönetimi** — kayıtlar merkezi log yönetim sisteminde toplanmalı, hata uyarı mekanizması olmalı. | SIEM (QRadar/Splunk/Sentinel) zaten merkezi log yönetim sistemidir. Bizim entegrasyon paketlerimiz oraya enrichment getirir. |
| **3.1.8.7** | **Kayıt analizi araçları / SIEM kullanımı**: "Siber olayların korelasyon kuralları doğrultusunda tespiti ve detaylı analizi için siber tehdit ve olay yönetim sistemleri veya kayıt analizi araçları kullanılmalı." | **Bu projenin tam karşılığı.** docs/usecases/ altındaki 22 use case = "korelasyon kuralı kütüphanesi". Her UC bir tehdit senaryosunu adresler. |
| **3.1.8.8** | SIEM yapılandırması düzenli gözden geçirilmeli (FP elenmeli). | UC dosyalarındaki "False positive notları" bölümleri ve `source=IH` için ayrı reference set önerimiz tam olarak bu gözden geçirme döngüsünü besler. |

#### 3.1.10 — Siber Güvenlik Olay Yönetimi

| Madde | Tedbirin özeti | Bu proje nasıl karşılar? |
|-------|----------------|--------------------------|
| **3.1.10.4** ⭐ | **"SGB ve olası diğer siber tehdit istihbarat kaynaklarından alınan bildirimler doğrultusunda gerekli önlemler alınmalı."** | **Bu projenin doğrudan referans uygulamasıdır.** SGB API → otomatik feed → SIEM kara liste/korelasyon = madde 3.1.10.4'ün operasyonel hâli. |
| **3.1.10.5** | Siber olay raporları **standardize** edilmeli, SGB'ye iletilmeli. | UC-AC-001 / UC-XX-003 gibi yüksek kritiklikli use case'ler alarm payload'ında "report-ready" alanlarla doldurulur; bu çıktılar olay raporuna doğrudan eklenebilir. |
| **3.1.10.8** | Olaylar puanlanmalı (risk temelli önceliklendirme). | [siem/qradar/severity-matrix.md](../siem/qradar/severity-matrix.md) — base severity × criticality matrisi tam olarak bu önceliklendirme modelidir. |

#### 3.1.11 — Sızma Testleri ve Güvenlik Denetimleri

| Madde | Tedbirin özeti | Bu proje nasıl karşılar? |
|-------|----------------|--------------------------|
| **3.1.11.1** | Düzenli sızma testi / güvenlik denetimi yapılmalı. | Doğrudan kapsamımız dışıdır; ancak SGB feed'i ile **sürekli (continuous)** denetim sağlanır: feed'de yeni IoC çıktığında SIEM otomatik olarak geçmiş 90 günlük log'ları tarar (Sentinel "indicator backsearch" pattern'i; bkz. [integrations/sentinel.md](integrations/sentinel.md)). Sızma testi yıllık fotoğraf çekerken bu mekanizma günlük film yayınlar. |

### 3.3 Taşınabilir Cihaz ve Ortam Güvenliği

| Madde | Tedbirin özeti | Bu proje nasıl karşılar? |
|-------|----------------|--------------------------|
| **3.3.1.x** Akıllı Telefon/Tablet | Mobil cihaz güvenliği. | SGB Mobile C&C (MC) feed'i MDM / mobile VPN log'ları ile korelasyona girer. Bkz. [UC-MC-001](usecases/UC-MC-001.md), [UC-MC-002](usecases/UC-MC-002.md). |
| **3.3.2.x** Taşınabilir Bilgisayar | Notebook güvenliği. | MF (Malware File) feed'i EDR ile birleşince taşınabilir bilgisayar üzerinde indirilen zararlı dosyayı tespit eder. Bkz. [UC-MF-002](usecases/UC-MF-002.md). |

### 3.6 Fiziksel Mekânların Güvenliği

| Madde | Tedbirin özeti | Bu proje nasıl karşılar? |
|-------|----------------|--------------------------|
| **3.6.1.12 / 3.6.2.13** | Fiziksel güvenlik sistemlerinin iz kayıtları siber olay tespitini desteklemeli (alarm, hata mesajları SIEM'e). | Doğrudan kapsamımız dışıdır; ancak SIEM'inize fiziksel sistem log'unu eklediğinizde bizim UC'lerimiz aynı SIEM'de korelasyona girer (örn. fiziksel erişim + dahili host'tan SGB C&C trafiği = içeriden tehdit göstergesi). |

### 4.5 Kritik Altyapılar Güvenliği

| Madde | Tedbirin özeti | Bu proje nasıl karşılar? |
|-------|----------------|--------------------------|
| **4.5.2** Enerji EKS | OT/EKS özelinde güvenlik. | SGB OT feed'i bu sektör için derlenir; [UC-OT-001](usecases/UC-OT-001.md) "info-only baseline" alarm kuralı ile başlangıç görünürlüğü sağlar. |
| **4.5.3** Elektronik haberleşme | Telekom sektörü. | MC + AC feed'i mobil/IP altyapısındaki tehditlerin tespiti için kullanılır. |

### 5. Sıkılaştırma Tedbirleri

Bu bölümün doğrudan karşılığı kapsamımız dışıdır (OS/DB/sunucu sıkılaştırma);
ancak sıkılaştırılmış sistemler bile SGB indicator'larına maruz kalabileceği
için **derin savunma (defense-in-depth)** çerçevesinde bu projeyi sıkılaştırma
ile birlikte konumlandırın.

---

## 4. Use case → BG madde matrisi (özet)

Hangi use case hangi maddeyi delillendiriyor? Aşağıdaki matris denetim
hazırlığında "her UC için neyi anlatacağım" sorusunun cevabıdır.

| Use Case | Birincil BG maddeleri | Destekleyici BG maddeleri |
|----------|------------------------|---------------------------|
| [UC-PH-001](usecases/UC-PH-001.md) DNS → SGB phishing domain | 3.1.5.1, 3.1.5.7, 3.1.6.20 | 3.1.4.10, 3.1.8.6, 3.1.8.7, 3.1.10.4 |
| [UC-PH-002](usecases/UC-PH-002.md) Proxy → SGB phishing URL | 3.1.6.20, 3.1.6.22 | 3.1.5.1, 3.1.8.7, 3.1.10.4 |
| [UC-PH-003](usecases/UC-PH-003.md) Email body link → SGB phishing | 3.1.4.10 | 3.1.5.1, 3.1.8.7, 3.1.10.4 |
| [UC-BC-001](usecases/UC-BC-001.md) Outbound → SGB Botnet C&C IP | 3.1.5.1, 3.1.6.4, 3.1.6.5 | 3.1.8.6, 3.1.8.7, 3.1.10.4 |
| [UC-BC-002](usecases/UC-BC-002.md) DNS → SGB Botnet C&C domain | 3.1.5.1, 3.1.5.7, 3.1.6.4 | 3.1.8.7, 3.1.10.4 |
| [UC-BC-003](usecases/UC-BC-003.md) Periyodik beacon (NetFlow) | 3.1.6.4, 3.1.6.18, 3.1.8.7 | 3.1.10.4, 3.1.10.8 |
| [UC-AC-001](usecases/UC-AC-001.md) APT C&C herhangi eşleşme | 3.1.10.4, 3.1.10.5, 3.1.10.8 | 3.1.5.6, 3.1.8.6, 3.1.8.7 |
| [UC-AC-002](usecases/UC-AC-002.md) Aynı asset 3+ AC match / 30 dk | 3.1.8.7, 3.1.10.4, 3.1.10.8 | 3.1.10.5 |
| [UC-EK-001](usecases/UC-EK-001.md) HTTP → SGB Exploit Kit URL | 3.1.5.1, 3.1.6.20, 3.1.6.28 | 3.1.8.7, 3.1.10.4 |
| [UC-EK-002](usecases/UC-EK-002.md) IDS exploit + SGB EK IP/URL | 3.1.6.18, 3.1.6.28, 3.1.8.7 | 3.1.5.1, 3.1.10.4 |
| [UC-MF-001](usecases/UC-MF-001.md) Proxy download → SGB malware URL | 3.1.5.1, 3.1.6.20 | 3.1.5.6, 3.1.8.7 |
| [UC-MF-002](usecases/UC-MF-002.md) EDR fetch → SGB malware host | 3.1.5.1, 3.1.5.6 | 3.3.2, 3.1.8.7 |
| [UC-MM-001](usecases/UC-MM-001.md) Outbound → SGB mining | 3.1.6.4, 3.1.6.5 | 3.1.5.1, 3.1.8.7 |
| [UC-MM-002](usecases/UC-MM-002.md) CPU spike + SGB MM hit | 3.1.5.1, 3.1.8.7 | 3.1.10.8 |
| [UC-MC-001](usecases/UC-MC-001.md) Mobil/VPN → SGB MC | 3.3.1, 3.1.6.4 | 3.1.10.4 |
| [UC-MC-002](usecases/UC-MC-002.md) MDM app traffic → SGB MC | 3.3.1, 3.3.1.10 | 3.1.10.4 |
| [UC-OT-001](usecases/UC-OT-001.md) Herhangi SGB OT match | 4.5.2, 4.5.3 | 3.1.10.4 |
| [UC-XX-001](usecases/UC-XX-001.md) Asset 2+ farklı CT / 24 saat | 3.1.8.7, 3.1.8.8 | 3.1.10.8 |
| [UC-XX-002](usecases/UC-XX-002.md) Aynı indicator 2x / 7 gün | 3.1.8.7, 3.1.10.8 | — |
| [UC-XX-003](usecases/UC-XX-003.md) Org-wide criticality artışı | 3.1.8.7, 3.1.10.5, 3.1.10.8 | — |

⭐ **Bütün use case'lerin ortak BG referansı: 3.1.10.4 + 3.1.8.7.** Yani bir
denetçi "siz SGB tehdit istihbaratını nasıl kullanıyorsunuz?" diye sorduğunda
göstereceğiniz dokümantasyon zaten bu kütüphanedir.

---

## 5. Entegrasyon → BG madde matrisi

| Entegrasyon | Doğrudan karşıladığı maddeler |
|-------------|-------------------------------|
| [QRadar](integrations/qradar.md) | 3.1.8.6, 3.1.8.7, 3.1.8.8, 3.1.10.4 |
| [Splunk](integrations/splunk.md) | 3.1.8.6, 3.1.8.7, 3.1.8.8, 3.1.10.4 |
| [Microsoft Sentinel](integrations/sentinel.md) | 3.1.8.6, 3.1.8.7, 3.1.10.4 + bulut için 4.3 |
| [MISP](integrations/misp.md) | 3.1.10.4 (TI hub fonksiyonu) |
| [OpenCTI](integrations/opencti.md) | 3.1.10.4 |
| [Generic STIX](integrations/generic-stix.md) | 3.1.10.4 (EDR/XDR'a IoC besleme) |
| [Firewall/proxy ana sayfa](index.html) | 3.1.6.4, 3.1.6.5, 3.1.6.20 |

---

## 6. Denetimde ne göstereceksiniz? (Pratik kılavuz)

Bir BG Rehberi iç/dış denetiminde aşağıdaki sorular sorulur ve verilebilecek
cevaplar şunlardır:

**Soru: "Madde 3.1.10.4 — SGB tehdit bildirimlerini nasıl yönetiyorsunuz?"**

- Cevap: SGB API'sinden saatlik otomatik delta sync alıyoruz
  ([setup-docker.md](setup-docker.md) ya da
  [setup-k8s.md](setup-k8s.md) işletim ortamımız). Gelen IoC veriyi
  vendor-bağımsız feed paketine (`feeds/sgb-master.csv` + STIX 2.1) çeviriyoruz
  ve SIEM'imize (QRadar/Splunk/Sentinel) otomatik yüklüyoruz. Buradan üretilen
  korelasyon alarmları SOC ekibimizce SOAR/ticket sistemine düşüyor.

**Soru: "Madde 3.1.5.7 — DNS sorgu kayıtlarını nasıl denetliyorsunuz?"**

- Cevap: DNS log'larını SIEM'e besliyoruz. SIEM tarafında SGB phishing/botnet
  domain reference set'leri otomatik bakıyor (UC-PH-001, UC-BC-002).
  Tetiklenen alarm sayısı / asset bazlı dağılım dashboard'umuzda mevcut.

**Soru: "Madde 3.1.6.4 — Kara liste politikanız nedir?"**

- Cevap: Firewall/proxy kara liste içeriğimizin **bir bileşeni** SGB feed'idir.
  Saatlik tazelenir, txt formatında `feeds/by-connectiontype/ip.txt` vb.
  yollardan tedarik edilir. Cihaz kuralı (`SGB blocklist auto-update`) bunu
  4 saatte bir pull eder.

**Soru: "Madde 3.1.8.7 — SIEM korelasyon kurallarınız neyi kapsar?"**

- Cevap: 22 use case'lik kütüphanemiz var (docs/usecases/), 8 connectiontype'ı
  + cross-category meta-rule'ları kapsıyor. Severity QRadar magnitude /
  Splunk urgency'ye eşleniyor (severity-matrix.md).

**Soru: "Madde 3.1.10.8 — Olayları nasıl önceliklendiriyorsunuz?"**

- Cevap: Her use case'in **base severity**'si vardır (AC=10, BC=8, MF=7, PH=5,
  MM=3, OT=3 baseline). Asset criticality modifier ile çarpılır. Risk
  temelli puanlama matrisi yazılı olarak [severity-matrix.md](../siem/qradar/severity-matrix.md)
  içindedir.

---

## 7. Bu projenin **karşılamadığı** maddeler (dürüstlük bölümü)

Bu projenin SGB tehdit istihbaratı odağı dışında kalan ve **ayrıca uyum
çalışması gerektiren** ana başlıklar:

- **3.1.1 — 3.1.2** Donanım/Yazılım envanteri (CMDB konusu)
- **3.1.3** Tehdit ve Zafiyet Yönetimi (zafiyet tarayıcı; biz tehdit
  istihbaratı tarafıyız)
- **3.1.9** Sanallaştırma güvenliği (hypervisor sıkılaştırma)
- **3.1.12** Kimlik Doğrulama ve Erişim Yönetimi (IAM)
- **3.1.13** Felaket Kurtarma / İş Sürekliliği
- **3.2.x** Uygulama ve veri güvenliği (SAST/DAST/SCA)
- **3.5.x** Personel güvenliği + farkındalık eğitimleri
- **4.1.x** Kişisel verilerin güvenliği (KVKK)
- **4.4.x** Kripto uygulamaları
- **5.x** Sıkılaştırma (OS/DB/web sunucu)

Bu maddeler için ayrı çözümler / süreçler gereklidir; SGB feed'i bunları
**ikame etmez**.

---

## 8. Tipik uyum yolculuğu — Faz faz ne yapmalı?

**Faz 1 (1. hafta) — Veri akışını kur**

1. [setup-docker.md](setup-docker.md) veya [setup-k8s.md](setup-k8s.md) ile
   sync container'ını ayağa kaldır.
2. İlk full sync'i çalıştır, `feeds/sgb-master.csv` dolduğunu doğrula.
3. Otomatik saatlik delta sync cron'unu aç.

**Faz 2 (2. hafta) — SIEM/CTI entegrasyonu**

4. SIEM'iniz QRadar ise [integrations/qradar.md](integrations/qradar.md);
   Splunk ise [integrations/splunk.md](integrations/splunk.md); Sentinel ise
   [integrations/sentinel.md](integrations/sentinel.md).
5. Lookup/reference set yüklendiğini doğrula. Hit sayısı 0 değil mi?

**Faz 3 (3-4. hafta) — Use case devreye alma**

6. UC-PH-001, UC-BC-001, UC-AC-001 ile başla (en yüksek değer/risk oranı).
7. 2 hafta gözlem; FP gelirse UC dosyasındaki "FP notları" bölümündeki
   suppress önerilerini uygula.
8. Kalan use case'leri devreye al.

**Faz 4 (sürekli) — Denetim hazırlığı**

9. Aylık özet rapor: hangi UC kaç kez tetiklendi, asset kritiklik dağılımı,
   ortalama triage süresi.
10. BG Rehberi denetim sorularına bu dokümandaki "6. bölüm — Pratik kılavuz"
    kısmını cevap şablonu olarak kullan.
11. SGB raporlaması (3.1.10.5) için UC-AC-* ve UC-XX-003 alarm payload'larını
    standardize olay raporuna aktarın.

---

## 9. İlgili dokümanlar

- Use case kütüphanesi → [usecases/README.md](usecases/README.md)
- Entegrasyon kılavuzları → [integrations/README.md](integrations/README.md)
- Kurulum (Docker / Kubernetes / GitHub Actions / GitLab CI) →
  [setup-docker.md](setup-docker.md), [setup-k8s.md](setup-k8s.md),
  [setup-github.md](setup-github.md), [setup-gitlab.md](setup-gitlab.md)
- Severity matrisi → [../siem/qradar/severity-matrix.md](../siem/qradar/severity-matrix.md)
- Firewall/proxy hızlı başlangıç → [index.html](index.html)
