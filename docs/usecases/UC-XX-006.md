# UC-XX-006 — SGB Listesindeki IP'den Kuruma Gelen (Inbound) Erişim

> **TL;DR:** Kütüphanedeki diğer tüm kurallar outbound yönlüdür
> ("kurum içinden SGB indicator'ına"). Bu kural ters yönü izler: SGB
> listesindeki bir IP'den kurumun dışa açık servislerine (VPN, RDP
> gateway, OWA/M365, SSH, web) gelen bağlantı ve **özellikle oturum açma
> denemeleri**. Başarılı oturum = en yüksek öncelik.

## Bu use case nedir? (Basit anlatım)

SGB IP listesindeki adresler çoğunlukla C&C sunucularıdır — ama aynı
altyapı saldırganın **çıkış noktası** olarak da kullanılır: oradan
kuruma tarama, brute force, password spray ve çalıntı kimlikle oturum
açma gelir.

Bu UC inbound event'lerde `source_ip` alanını tüm SGB IP set'lerinde
arar. Severity kademelidir:

- Kaynak `SGB_AC_IP`'de → 10 (not: [UC-AC-001](UC-AC-001.md) source_ip
  alanını zaten her log'da arar; bu UC diğer CT'ler için inbound
  görünürlüğü ve **kimlik doğrulama bağlamını** ekler).
- Kaynak `SGB_BC_IP`'de → 7.
- Diğer CT'ler → 5.
- Olay **başarılı oturum açma** ise +2 (üst sınır 10).

Not: Engelleme feed'ini (`ip-list.txt`) firewall'una basan kurumda bu
trafik zaten bloklanır — o durumda bu UC "block" loglarını izleyen bir
görünürlük katmanıdır ve engellemenin çalıştığının kanıtını üretir.
Feed'i yalnız SIEM'de tüketen kurumda ise tek savunma hattıdır.

## Senaryo (Hikâye)

- 03:40 — SGB BC listesindeki `91.X.X.X` adresinden kurum VPN gateway'ine
  9 farklı hesapla 47 başarısız oturum denemesi (password spray).
- 03:52 — Aynı IP'den `o.kaya` hesabıyla **başarılı** VPN oturumu.
- 03:52:01 — SIEM: `source_ip` `SGB_BC_IP`'de + auth success →
  severity 9 (BC 7 + başarılı oturum 2).
- 03:52:05 — SOAR: oturum sonlandırılır, hesap askıya alınır, MFA reset
  zorlanır; IR'a "credential compromise şüphesi" ticket'ı düşer.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.6.4** | Kara Liste Kullanımı | IP kara listesinin inbound yönde de işletilmesi. |
| **3.1.6.5** | İzin Verilmeyen Trafiğin Engellenmesi | Bloklama varsa kanıt, yoksa tespit katmanı. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Auth log + TI korelasyonu. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB IP feed'inin çift yönlü kullanımı. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-XX-006 |
| MITRE | TA0001 / T1133 External Remote Services + TA0006 / T1110 Brute Force |
| Connectiontype | XX (kaynak IP'nin CT'sine göre kademeli) |
| Severity | Dinamik 5-10: AC→10, BC→7, diğer→5; başarılı oturum +2 (max 10) |
| Veri kaynakları | VPN concentrator, RDP gateway, OWA/M365 sign-in, SSH, WAF, firewall inbound |
| TAXII koleksiyonu | Tüm IP içeren koleksiyonlar (legacy reference set: `SGB_AC_IP`, `SGB_BC_IP`, diğer `SGB_*_IP`, `SGB_IP_MAP`) |
| Response | PB-XX-006 (oturum sonlandırma + hesap askıya alma + MFA reset) |

## Tespit mantığı (vendor-bağımsız)

```text
when inbound authentication/connection event geldi
     (VPN, RDP gateway, OWA/M365 sign-in, SSH, WAF, kurumsal portal)
  AND source_ip herhangi bir SGB_*_IP set'inde
then offense aç
     severity = CT'ye göre (AC→10, BC→7, diğer→5)
     event "auth success" ise severity += 2 (max 10)
     source IP'yi SGB_INBOUND_SOURCES set'ine ekle (TTL 24 saat)
```

## QRadar uygulaması

**Kural tipi:** Event Rule (log source group: "Remote Access / Auth")

```
when the event category is one of: Authentication, VPN Session, Remote Access
  AND when the Source IP is contained in any of:
      SGB_AC_IP, SGB_BC_IP, SGB_MF_IP, SGB_MM_IP, SGB_OT_IP
```

**Response:**
- Severity: `SGB_IP_MAP` lookup'ından CT'ye göre (AC→10, BC→7, diğer→5)
- Event "Auth Success" kategorisindeyse ikinci kural +2 escalate eder
- Dispatch "SGB Inbound Access" + add source IP → `SGB_INBOUND_SOURCES`
- Auth success ise SOAR webhook (oturum sonlandırma playbook'u)

## Splunk uygulaması

**Saved search:** `SGB - UC-XX-006 - Inbound from SGB-listed IP`

```spl
(`sgb_vpn_index` OR `sgb_auth_index` OR `sgb_waf_index`)
| lookup sgb_ip_lookup value AS src_ip OUTPUT connectiontype, source
| where isnotnull(connectiontype)
| eval base=case(connectiontype="AC", 10, connectiontype="BC", 7, true(), 5)
| eval severity=min(10, base + if(action="success", 2, 0))
| stats count values(action) AS actions values(user) AS users
        by src_ip, connectiontype, severity
```

## Yanlış pozitif notları

- **CGN / dinamik ISP IP havuzları en önemli FP kaynağıdır:** ev
  kullanıcısının enfekte cihazı yüzünden feed'e giren tüketici IP'si
  kısa sürede başka aboneye tahsis edilir — o abone kurumun meşru
  çalışanı olabilir. Bu yüzden severity kademesi auth sonucuna bağlıdır:
  başarısız tek deneme düşük sinyal, başarılı oturum yüksek sinyaldir.
- **Çalışanın evdeki enfekte ağından meşru VPN bağlantısı:** hesap değil
  ev ağı enfektedir → kullanıcı bilgilendirme + cihaz taraması; hesap
  askıya alma orantısız olabilir (triage notu).
- **Tarama gürültüsü:** SGB IP'lerinden gelen ve hiçbir servise
  ulaşamayan (firewall deny) paketler için ayrı düşük-öncelik sayaç
  tutun; offense yalnız auth yüzeyine ulaşan trafiğe açılsın.

## Olay müdahale (PB-XX-006)

**Otomatik (auth success durumunda):**
1. Aktif oturumu sonlandır (VPN/IdP API).
2. Hesabı askıya al, MFA reset zorla.
3. P2 ticket + IAM ekibine bildirim.

**Manuel:**
1. Hesabın son 30 günlük oturum geçmişi — başka şüpheli kaynak var mı?
2. Aynı kaynak IP'den başka hesaplara deneme var mı? (Spray genişliği)
3. Kaynak IP'yi geo/ASN ile zenginleştir; CGN/tüketici bloğu ise FP
   ihtimalini değerlendir.
4. Başarılı oturum doğrulanmış compromise ise: kullanıcının eriştiği
   kaynaklar üzerinden kapsam belirleme + SGB raporlaması (3.1.10.5).
