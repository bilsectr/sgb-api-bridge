# QRadar Rule Worksheet — SGB Use Case Kütüphanesi

> **ÜRETİLMİŞ DOSYA — elle düzenlemeyin.** Kaynak: [docs/usecases/](../../docs/usecases/),
> üretici: [make_rule_sheet.py](make_rule_sheet.py). UC tanımları değişince yeniden üretin.

Üretim tarihi: 2026-06-11 · 24 kural · sıra = devreye alma önceliği

**Ön koşullar:** [setup_feeds.py](setup_feeds.py) ile 8 TAXII feed +
reference set'ler kurulmuş, feed'ler "Connected" durumda olmalı
([docs/integrations/qradar.md](../../docs/integrations/qradar.md) Adım 1-2).

Her kural için ortak ayarlar:

- Rule grubu: **SGB Use Cases** (yeni grup oluşturun — CMT export'u bu grupla yapılır)
- Severity formülü ve source=IH istisnaları: [usecases/README.md#severity](../../docs/usecases/README.md#severity)
- Offense annotation konvansiyonu: `"SGB <aciklama> — bkz. <UC-ID>"`

---

## Tier 1 — Feed sağlığı + en yüksek hacim/severity. Önce bunlar.

### [ ] UC-XX-004 — SGB Feed Sağlık ve Bütünlük İzleme (Operasyonel)

| | |
|---|---|
| Severity (base) | N/A — güvenlik offense'ı değil; önerilen: P2 operasyon ticket'ı |
| MITRE | — (operasyonel kural; ATT&CK tekniği yok) |
| TAXII feed | Tümü (koleksiyon bağımsız sağlık kontrolü) |
| Kanonik tanım | [docs/usecases/UC-XX-004.md](../../docs/usecases/UC-XX-004.md) |

QRadar reference set boyutunu kural içinden okuyamaz; küçük bir cron
script'i gerekir:

1. Script saatte bir `/api/reference_data/sets/{name}` çağırır,
   `number_of_elements` değerini syslog event'i olarak QRadar'a gönderir.
2. Event Rule: yeni değer, önceki değerin %80'inin altındaysa →
   "SGB Feed Volume Drop" alarmı.
3. Tazelik için: TAXII feed'inin "last polled / objects added" log'u
   3 saatten eskiyse aynı script ikinci bir event üretir.

### [ ] UC-PH-001 — Kurum İçinden SGB Phishing Domain'ine DNS Sorgusu

| | |
|---|---|
| Severity (base) | 5 (kritiklik modifier ile yükselir) |
| MITRE | TA0001 Initial Access / T1566.002 Spearphishing Link |
| TAXII feed | `sgb-phishing` (legacy reference set: `SGB_PH_DOMAIN` + `SGB_DOMAIN_MAP` (zenginleştirme için)) |
| Kanonik tanım | [docs/usecases/UC-PH-001.md](../../docs/usecases/UC-PH-001.md) |

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
  bkz. [README.md#severity](../../docs/../docs/usecases/README.md#severity))
- Annotate offense: "SGB phishing domain match — bkz. UC-PH-001"
- Reference set: add source IP to `SGB_SUSPECTED_HOSTS`
- (Opsiyonel) Email notification + SOAR webhook

### [ ] UC-PH-002 — Web Proxy Üzerinden SGB Phishing URL'sine HTTP İsteği

| | |
|---|---|
| Severity (base) | 5 |
| MITRE | TA0001 / T1566.002 Spearphishing Link |
| TAXII feed | `sgb-phishing` (legacy reference set: `SGB_PH_URL` + `SGB_URL_MAP`) |
| Kanonik tanım | [docs/usecases/UC-PH-002.md](../../docs/usecases/UC-PH-002.md) |

**Kural tipi:** Event Rule

```
when any of these properties (URL, "HTTP URL Host") is contained in
     any of these reference set(s): SGB_PH_URL
  AND when the source network is one of the following: Trusted
```

**Response:**
- Dispatch event "SGB Phishing URL access"
- Severity 5 + criticality modifier
- `SGB_SUSPECTED_HOSTS` set'ine source IP ekle

### [ ] UC-PH-003 — Gelen E-postanın Body'sinde SGB Phishing Domain/URL Linki

| | |
|---|---|
| Severity (base) | 6 (mail teslim edilmiş — exposure aşaması; PH-001'den 1 yüksek) |
| MITRE | TA0001 / T1566.002 |
| TAXII feed | `sgb-phishing` (legacy reference set: `SGB_PH_DOMAIN`, `SGB_PH_URL`) |
| Kanonik tanım | [docs/usecases/UC-PH-003.md](../../docs/usecases/UC-PH-003.md) |

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

### [ ] UC-BC-001 — Kurum İçinden SGB Botnet C&C IP'sine Giden Bağlantı

| | |
|---|---|
| Severity (base) | 8 (criticality ile 10'a çıkar) |
| MITRE | TA0011 Command & Control / T1071 Application Layer Protocol C2 |
| TAXII feed | `sgb-botnet-cc` (legacy reference set: `SGB_BC_IP` + `SGB_IP_MAP`) |
| Kanonik tanım | [docs/usecases/UC-BC-001.md](../../docs/usecases/UC-BC-001.md) |

**Kural tipi:** Event Rule + Flow Rule (paralel çalışsın; her ikisi de
hit aldığında deduplication QRadar tarafında halledilir).

**Event side:**
```
when the event QID is one of the following: Firewall Permit, Proxy Allow
  AND when any of (Destination IP) is contained in any of: SGB_BC_IP
  AND when the source network is one of: Trusted
```

**Flow side:** Aynı mantık `destinationip` için.

**Response:**
- Dispatch new event "SGB Botnet C2 Outbound"
- Magnitude severity: 8 → AQL action ile criticality lookup
- Annotate offense + add to `SGB_INFECTED_HOSTS` (TTL 7 gün)
- Forward to SOAR (webhook / syslog CEF)

### [ ] UC-BC-002 — DNS Sorgusu SGB Botnet C&C Alan Adına Gidiyor

| | |
|---|---|
| Severity (base) | 8 |
| MITRE | TA0011 / T1071.004 DNS C2 + T1568.002 Dynamic Resolution: DGA |
| TAXII feed | `sgb-botnet-cc` (legacy reference set: `SGB_BC_DOMAIN`, `SGB_DOMAIN_MAP`) |
| Kanonik tanım | [docs/usecases/UC-BC-002.md](../../docs/usecases/UC-BC-002.md) |

```
when the event QID is one of: DNS Query QIDs
  AND when query property is in SGB_BC_DOMAIN
  AND when source network is in Trusted
```

**Response:**
- Severity 8 + criticality modifier
- Add source IP → `SGB_INFECTED_HOSTS`
- Annotate offense "SGB Botnet C2 DNS"

### [ ] UC-AC-001 — Herhangi Bir Yönden / Herhangi Bir Log Kaynağında SGB APT C&C Eşleşmesi

| | |
|---|---|
| Severity (base) | **10 (sabit)** — criticality bile etkilemez |
| MITRE | TA0011 / T1071 + TA0001 Initial Access (genel) |
| TAXII feed | `sgb-apt-cc` (legacy reference set: `SGB_AC_IP`, `SGB_AC_DOMAIN`, `SGB_AC_URL`) |
| Kanonik tanım | [docs/usecases/UC-AC-001.md](../../docs/usecases/UC-AC-001.md) |

**Kural tipi:** Generic high-priority rule.

```
when any of these properties:
  Source IP, Destination IP, URL, Hostname, DNS Query
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

### [ ] UC-AC-002 — Aynı Asset Üzerinde 30 Dakika İçinde 3+ Farklı APT C&C Eşleşmesi

| | |
|---|---|
| Severity (base) | 10 (sabit, lockdown trigger) |
| MITRE | TA0011, TA0001 (initial access/C2 onayı) |
| TAXII feed | `sgb-apt-cc` (legacy reference set: `SGB_AC_IP`, `SGB_AC_DOMAIN`, `SGB_AC_URL`) |
| Kanonik tanım | [docs/usecases/UC-AC-002.md](../../docs/usecases/UC-AC-002.md) |

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

---

## Tier 2 — Composite/meta kurallar; ek veri kaynaklarına bağımlı.

### [ ] UC-BC-003 — SGB IP'sine Periyodik Beacon Trafiği (NetFlow)

| | |
|---|---|
| Severity (base) | 9 (composite — beacon paterni doğrulanmış BC sinyali, tekil hit'ten +1) |
| MITRE | TA0011 / T1071 + T1029 Scheduled Transfer |
| TAXII feed | `sgb-botnet-cc` (legacy reference set: `SGB_BC_IP`) |
| Kanonik tanım | [docs/usecases/UC-BC-003.md](../../docs/usecases/UC-BC-003.md) |

**Kural tipi:** Flow Rule + custom property "Avg Flow Interval"

Aggregator: "Bu kural aynı source IP + dest IP'de 1 saat içinde en az 5
kez match etti."

```
when flow event matches:
  destination IP in SGB_BC_IP
  AND flow byte count < 4096
THEN match must occur at least 5 times in 1 hour
     on the same source IP and destination IP
```

**Response:**
- Severity 9 + criticality
- Annotate offense "SGB Botnet Beacon Pattern"
- SOAR host isolate

### [ ] UC-BC-004 — DNS Yanıtı (A Kaydı) SGB C&C IP'sine Çözümleniyor

| | |
|---|---|
| Severity (base) | 8 (cevap `SGB_AC_IP`'de ise 10 sabit) |
| MITRE | TA0011 / T1568 Dynamic Resolution + T1071.004 DNS C2 |
| TAXII feed | `sgb-botnet-cc` + `sgb-apt-cc` (legacy reference set: `SGB_BC_IP`, `SGB_AC_IP`, `SGB_IP_MAP`) |
| Kanonik tanım | [docs/usecases/UC-BC-004.md](../../docs/usecases/UC-BC-004.md) |

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

### [ ] UC-MF-001 — Proxy Üzerinden SGB Malware URL'sinden Dosya İndirildi

| | |
|---|---|
| Severity (base) | 7 |
| MITRE | TA0002 / T1105 Ingress Tool Transfer |
| TAXII feed | `sgb-malware-download` (legacy reference set: `SGB_MF_URL`, `SGB_MF_DOMAIN`, `SGB_URL_MAP`) |
| Kanonik tanım | [docs/usecases/UC-MF-001.md](../../docs/usecases/UC-MF-001.md) |

```
when log source type is Proxy/SWG
  AND URL in SGB_MF_URL
  AND HTTP status in (200, 206)
  AND bytes_received > 1024
```

### [ ] UC-MF-002 — EDR'de Dosya Yazıldı + Aynı Process SGB Malware Host'undan Çekti (Composite)

| | |
|---|---|
| Severity (base) | 8 |
| MITRE | TA0002 / T1105 Ingress Tool Transfer |
| TAXII feed | `sgb-malware-download` (legacy reference set: `SGB_MF_DOMAIN`, `SGB_MF_IP`, `SGB_MF_URL`) |
| Kanonik tanım | [docs/usecases/UC-MF-002.md](../../docs/usecases/UC-MF-002.md) |

```
when EDR sourcetype event "Process Network Connection"
  AND destination host in SGB_MF_DOMAIN
  AND within 60 seconds
  AND EDR sourcetype event "File Create" by same process_guid
```

**Response:**
- EDR isolate API call (SOAR)
- Forensic snapshot
- Memory dump

### [ ] UC-MC-001 — Mobil/VPN Trafiği SGB Mobile C&C Indicator'ına

| | |
|---|---|
| Severity (base) | 7 |
| MITRE | TA0011 / T1437 Mobile Application Layer Protocol |
| TAXII feed | `sgb-mobile-cc` (legacy reference set: `SGB_MC_IP`, `SGB_MC_DOMAIN`, `SGB_MC_URL`) |
| Kanonik tanım | [docs/usecases/UC-MC-001.md](../../docs/usecases/UC-MC-001.md) |

```
when Log Source Group = "Mobile / MDM"
  AND dest_ip in SGB_MC_IP OR query in SGB_MC_DOMAIN OR url in SGB_MC_URL
```

### [ ] UC-MC-002 — MDM Application Trafiği SGB Mobile C&C'ye

| | |
|---|---|
| Severity (base) | 7 |
| MITRE | TA0011 / T1437 + T1474 Supply Chain |
| TAXII feed | `sgb-mobile-cc` (legacy reference set: `SGB_MC_DOMAIN`, `SGB_MC_IP`) |
| Kanonik tanım | [docs/usecases/UC-MC-002.md](../../docs/usecases/UC-MC-002.md) |

Custom event property: `Mobile App Package` (com.example.pkg).

```
when log source type in (Intune, Lookout, Zimperium)
  AND request_destination in SGB_MC_*
```

**Response:** severity 7, MDM API ile app blacklist + device retire-trigger
(manuel onaylı).

### [ ] UC-XX-001 — Aynı Asset 24 Saat İçinde 2+ Farklı Connectiontype'a Hit Etti

| | |
|---|---|
| Severity (base) | 8 (tek CT severity'lerini override) |
| MITRE | TA0011 + multi-stage |
| TAXII feed | (birden fazla - UC icerigine gore sgb-* koleksiyonlari) (legacy reference set: `SGB_*_MAP` (CT bilgisi)) |
| Kanonik tanım | [docs/usecases/UC-XX-001.md](../../docs/usecases/UC-XX-001.md) |

**Aggregator:** UC-PH-* OR UC-BC-* OR UC-AC-* OR UC-EK-* OR UC-MF-* OR
UC-MM-* OR UC-MC-* match'lerini source IP bazında topla, distinct count
"SGB_CT" custom property >=2.

### [ ] UC-XX-002 — Aynı Indicator 7 Gün İçinde Aynı Asset'te 2x Tekrar Etti

| | |
|---|---|
| Severity (base) | 7 |
| MITRE | TA0003 Persistence — IR ineffectiveness signal |
| TAXII feed | — |
| Kanonik tanım | [docs/usecases/UC-XX-002.md](../../docs/usecases/UC-XX-002.md) |

Reference Map `SGB_ASSET_HIT_HISTORY` (key=asset|indicator, value=last_seen).
Rule: SGB match → lookup → varsa escalate.

### [ ] UC-XX-005 — Yeni Eklenen Indicator İçin Retro-Hunt (Geriye Dönük Tarama)

| | |
|---|---|
| Severity (base) | Eşleşen CT'nin base severity'sini devralır ([README.md#severity](../../docs/../docs/usecases/README.md#severity)); alarm "retro-hunt" etiketi taşır |
| MITRE | Çapraz — eşleşen indicator'ın CT'sine göre (tarihsel tespit) |
| TAXII feed | Tümü (yeni eklenen objeler koleksiyon bağımsız taranır) |
| Kanonik tanım | [docs/usecases/UC-XX-005.md](../../docs/usecases/UC-XX-005.md) |

1. Ingest pipeline'ı son 24 saatte eklenen indicator'ları ayrı bir
   reference set'e yazar: `SGB_RECENT_ADDED` (TTL 24 saat).
2. Gece scheduled AQL:

```sql
SELECT sourceip, destinationip, "URL", "DNS Query", starttime
FROM events
WHERE REFERENCESETCONTAINS('SGB_RECENT_ADDED', "DNS Query")
   OR REFERENCESETCONTAINS('SGB_RECENT_ADDED', "URL")
   OR REFERENCESETCONTAINS('SGB_RECENT_ADDED', destinationip)
START '30 days ago'
```

3. Sonuç boş değilse CRE'ye "SGB Retro-Hunt Match" event'i dispatch edilir.
   (Alternatif: ilgili UC kuralını "Run rule against historical events"
   ile elle geçmişe koşturmak — büyük delta'larda scheduled AQL tercih edin.)

### [ ] UC-XX-006 — SGB Listesindeki IP'den Kuruma Gelen (Inbound) Erişim

| | |
|---|---|
| Severity (base) | Dinamik 5-10: AC→10, BC→7, diğer→5; başarılı oturum +2 (max 10) |
| MITRE | TA0001 / T1133 External Remote Services + TA0006 / T1110 Brute Force |
| TAXII feed | Tüm IP içeren koleksiyonlar (legacy reference set: `SGB_AC_IP`, `SGB_BC_IP`, diğer `SGB_*_IP`, `SGB_IP_MAP`) |
| Kanonik tanım | [docs/usecases/UC-XX-006.md](../../docs/usecases/UC-XX-006.md) |

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

---

## Tier 3 — Düşük hacim / bilgilendirme. Maliyetsizse açın.

### [ ] UC-EK-001 — HTTP İsteği SGB Exploit Kit URL'sine

| | |
|---|---|
| Severity (base) | 8 |
| MITRE | TA0001 / T1189 Drive-by Compromise + TA0002 / T1203 Exploitation for Client Execution |
| TAXII feed | `sgb-exploit-kit` (legacy reference set: `SGB_EK_URL`, `SGB_EK_DOMAIN`, `SGB_URL_MAP`) |
| Kanonik tanım | [docs/usecases/UC-EK-001.md](../../docs/usecases/UC-EK-001.md) |

```
when URL is contained in SGB_EK_URL
```

**Enrichment:** Parse User-Agent; non-standard (kütüphane gibi
`python-requests`, `curl`) UA + EK URL kombinasyonu → severity +1.

**Response:**
- Severity 8 + criticality
- Notify SOC
- Push source IP → `SGB_EXPLOITED_HOSTS`
- EDR scan trigger via SOAR

### [ ] UC-EK-002 — IDS Exploit Alarmı + SGB EK IP/URL Eşleşmesi (Composite)

| | |
|---|---|
| Severity (base) | 9 |
| MITRE | TA0001 / T1189 Drive-by Compromise + TA0002 / T1203 |
| TAXII feed | `sgb-exploit-kit` (legacy reference set: `SGB_EK_IP`, `SGB_EK_URL`) |
| Kanonik tanım | [docs/usecases/UC-EK-002.md](../../docs/usecases/UC-EK-002.md) |

**Kural tipi:** Common Rule (cross-source aggregator)

```
when IDS exploit category event happens
  AND SGB_EK_* set match happens
  on the same source IP and destination IP
  within 300 seconds
```

**Response:**
- Severity 9
- Dispatch "SGB EK + IDS confirmed"
- Auto-trigger host isolation (severity 9 threshold)

### [ ] UC-MM-001 — Outbound Trafik SGB Mining Indicator'ına

| | |
|---|---|
| Severity (base) | 3 (policy/perf) |
| MITRE | TA0040 Impact / T1496 Resource Hijacking |
| TAXII feed | `sgb-mining` (legacy reference set: `SGB_MM_IP`, `SGB_MM_DOMAIN`, `SGB_IP_MAP`) |
| Kanonik tanım | [docs/usecases/UC-MM-001.md](../../docs/usecases/UC-MM-001.md) |

```
when dest_ip in SGB_MM_IP OR DNS query in SGB_MM_DOMAIN
```

**Response:** severity 3, add → `SGB_MINING_HOSTS`, weekly summary report.

### [ ] UC-MM-002 — CPU Yükü Yüksek + SGB MM Eşleşmesi (Composite)

| | |
|---|---|
| Severity (base) | 5 |
| MITRE | TA0040 / T1496 |
| TAXII feed | `sgb-mining` (legacy reference set: `SGB_MM_IP`, `SGB_MM_DOMAIN`) |
| Kanonik tanım | [docs/usecases/UC-MM-002.md](../../docs/usecases/UC-MM-002.md) |

**QRadar:** Common Rule combining UC-MM-001 + EDR custom event
"high CPU asset"; time correlation 1 saat, same asset.

**Splunk:** Saved search joining EDR perf index + `sgb_dest_ct="MM"`.

```spl
`sgb_edr_perf_index` earliest=-1h
| stats avg(cpu_pct) AS avg_cpu by host
| where avg_cpu > 85
| join host [search `sgb_notable_index` sgb_ct="MM" earliest=-5m | stats count by host]
```

### [ ] UC-OT-001 — Herhangi SGB "Other (OT)" Eşleşmesi (Bilgilendirme Baseline)

| | |
|---|---|
| Severity (base) | 3 (offense açılmaz, log only); kritik asset segmentinde 5 (offense açılır) |
| MITRE | (kategori belirsiz) |
| TAXII feed | `sgb-other` (legacy reference set: `SGB_OT_IP`, `SGB_OT_DOMAIN`, `SGB_OT_URL`) |
| Kanonik tanım | [docs/usecases/UC-OT-001.md](../../docs/usecases/UC-OT-001.md) |

```
when SGB_OT_* match → Magnitude = 1 (do NOT create offense)
```

**Response:** log only + add to `SGB_OT_OBSERVED` (24h TTL).

Ayrı saatlik scheduled search: `count(SGB_OT match) > 100 / hour` → alarm.

**Kritik segment kademesi:**

```
when SGB_OT_* match
  AND source asset is in asset group "Critical Assets"
→ Magnitude = 5, offense aç ("SGB OT match on critical segment")
```

### [ ] UC-XX-003 — Organizasyon Geneli Kritiklik Spike (Saatlik avg criticality > 7)

| | |
|---|---|
| Severity (base) | dinamik (7-10) |
| MITRE | (cross — emergent campaign indicator) |
| TAXII feed | (birden fazla - UC icerigine gore sgb-* koleksiyonlari) (legacy reference set: `SGB_*_MAP` (criticality alanı)) |
| Kanonik tanım | [docs/usecases/UC-XX-003.md](../../docs/usecases/UC-XX-003.md) |

Anomaly Detection rule on custom property "SGB Criticality";
AQL search scheduled / 1h, threshold action.

---

## Tamamlandığında: CMT export

```bash
# Console'da, SGB Use Cases rule grubunu ve bağımlılıklarını export et:
/opt/qradar/bin/contentManagement.pl -a export -c 28 -i <rule_group_id> -t
# veya tüm custom rule'ları alıp UI'dan ayıklamak için: -a export -c 28 -i all
```

Çıkan zip'i `apps/qradar/build.py --input <export.zip>` ile dağıtım
paketine çevirin (bkz. [README.md](README.md)).
