# UC-BC-004 — DNS Yanıtı (A Kaydı) SGB C&C IP'sine Çözümleniyor

> **TL;DR:** UC-BC-002 sorgulanan domain'e bakar; bu UC ise DNS sunucusunun
> döndürdüğü **cevaba** (A/AAAA kaydı) bakar. Sorgulanan domain SGB
> listesinde henüz olmasa bile, çözümlenen IP SGB botnet/APT C&C
> listesindeyse alarm üretir. Fast-flux altyapısını diğer yüzünden yakalar.

## Bu use case nedir? (Basit anlatım)

Saldırgan her gün yeni domain açabilir (DGA, typosquatting); domain listesi
bu yarışta her zaman bir adım geridedir. Ama saldırganın **sunucu IP'si**
çok daha yavaş değişir — yeni açılan domain'ler çoğu zaman aynı C&C
IP'sine işaret eder.

DNS response log'u (BIND query+answer log, Windows DNS Analytical,
Infoblox, Zeek `dns.log`, Sysmon Event ID 22) sorgunun **cevabını** da
içerir: "`abc.example` → `185.X.X.X`". Bu UC, cevaptaki IP'yi `SGB_BC_IP`
ve `SGB_AC_IP` set'lerinde arar. Eşleşme varsa: sorgulanan domain feed'de
olmasa bile host bilinen C&C altyapısına yönlendirilmiş demektir.

**Bonus:** Bu UC'nin yakaladığı "feed'de olmayan domain" SGB'ye geri
bildirilebilecek **yeni IoC adayıdır** — 3.1.10.4'ün çift yönlü
işletilmesi.

## Senaryo (Hikâye)

- 19:05 — `WIN-SAT-03`, feed'de henüz bulunmayan `cdn-update7.example`
  domain'ine DNS sorgusu yapar; UC-BC-002 tetiklenmez (domain listede yok).
- 19:05:01 — DNS sunucusu cevabı döndürür: A kaydı `185.X.X.X` — bu IP
  `SGB_BC_IP` set'inde.
- 19:05:02 — SIEM, response log'undaki answer alanını set'te bulur →
  severity 8 alarm.
- 19:05:05 — RPZ ile domain sinkhole'a alınır; `cdn-update7.example`
  "aday IoC" olarak SGB geri bildirim listesine eklenir.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.5.7** | DNS Sorgularının Kayıtlarının Tutulması | Yalnız sorgu değil **cevap** kaydının da değerlendirilmesi — maddenin ileri seviye uygulaması. |
| **3.1.6.4** | Kara Liste Kullanımı | IP kara listesinin DNS cevap katmanında kullanımı. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | UC bizatihi SIEM kuralı. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB IP feed'i kullanımı + SGB'ye yeni domain geri bildirimi (çift yön). |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-BC-004 |
| MITRE | TA0011 / T1568 Dynamic Resolution + T1071.004 DNS C2 |
| Connectiontype | BC (AC eşleşmesinde 10'a eskalasyon) |
| Severity (base) | 8 (cevap `SGB_AC_IP`'de ise 10 sabit) |
| Veri kaynakları | DNS response log (BIND, Windows DNS Analytical, Infoblox), Zeek dns.log, Sysmon Event ID 22 |
| TAXII koleksiyonu | `sgb-botnet-cc` + `sgb-apt-cc` (legacy reference set: `SGB_BC_IP`, `SGB_AC_IP`, `SGB_IP_MAP`) |
| Response | PB-BC-004 (RPZ sinkhole + aday IoC bildirimi + EDR scan) |

## Tespit mantığı (vendor-bağımsız)

```text
when DNS response event geldi
  AND answer (A/AAAA) alanı SGB_BC_IP veya SGB_AC_IP set'inde
  AND source network "Trusted"
then offense aç
     severity = 8 (BC) / 10 (AC)
     sorgulanan domain'i SGB_CANDIDATE_IOC set'ine ekle (SGB'ye bildirim adayı)
     source IP'yi SGB_INFECTED_HOSTS'a ekle (TTL 7 gün)
```

## QRadar uygulaması

**Ön koşul:** DNS response parser + custom event property `DNS Answer`.
Windows DNS için Analytical log, BIND için query+answer logging açık olmalı.

```
when the event QID is one of: DNS Response QIDs
  AND when the "DNS Answer" property is contained in
      any of these reference set(s): SGB_BC_IP, SGB_AC_IP
  AND when the source network is one of: Trusted
```

**Response:**
- Dispatch new event "SGB C2 IP via DNS Answer"
- Severity 8 (`SGB_AC_IP` match ise 10)
- Add query domain → `SGB_CANDIDATE_IOC`, source IP → `SGB_INFECTED_HOSTS`

## Splunk uygulaması

**Saved search:** `SGB - UC-BC-004 - DNS answer resolves to SGB C2 IP`

```spl
`sgb_dns_index` (sourcetype=zeek:dns OR (sourcetype=XmlWinEventLog EventCode=22))
| eval answer=coalesce(answers, QueryResults)
| makemv delim=";" answer | mvexpand answer
| lookup sgb_ip_lookup value AS answer OUTPUT connectiontype, criticality_level, source
| where connectiontype IN ("BC", "AC")
| eval severity=if(connectiontype="AC", 10, 8)
| stats count values(query) AS candidate_domains by src_ip, answer, connectiontype, severity
```

## Yanlış pozitif notları

- **Paylaşımlı hosting / CDN IP'leri en büyük FP kaynağıdır:** feed'e tek
  kötü tenant yüzünden giren bir IP'ye yüzlerce meşru domain çözümlenebilir.
  Alarm üretirken sorgulanan domain'in yaşı/itibarı ikinci doğrulama
  adımı olmalı; bilinen CDN IP aralıkları için exception listesi tutun.
- **Sinkhole IP'leri:** cevap bilinen bir sinkhole'a çözümleniyorsa
  zararlı yazılım zaten yakalanmış demektir → severity 3'e düşür
  (UC-BC-002'deki sinkhole notuyla aynı mantık).
- **Bloklanmış cevaplar:** `0.0.0.0` / `127.0.0.1` dönen cevaplar
  (RPZ/Pi-hole zaten blokladı) eşleşme dışı tutulmalı.

## Olay müdahale (PB-BC-004)

**Otomatik:**
1. DNS RPZ: sorgulanan domain'i sinkhole'a yönlendir.
2. Domain'i `SGB_CANDIDATE_IOC` set'ine ekle (SGB'ye geri bildirim kuyruğu).
3. Source host'ta EDR "scan now".

**Manuel:**
1. Domain yaşı / whois / sertifika analizi — yeni kayıtlı domain ise
   güçlü sinyal.
2. Hangi process sorguladı? (Sysmon Event 22 process bilgisini içerir.)
3. Aynı IP'ye çözümlenen başka domain'ler var mı? (Passive DNS pivot)
4. Doğrulanırsa: domain'i SGB'ye bildir (3.1.10.4 geri bildirim hattı),
   UC-BC-001/002 akışındaki müdahale adımlarını uygula.
