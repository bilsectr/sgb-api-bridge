# UC-MM-001 — Outbound Trafik SGB Mining Indicator'ına

> **TL;DR:** Bir host, SGB'nin "cryptomining" olarak işaretlediği bir
> havuz (pool) veya cüzdan host'una bağlanıyor. Çoğunlukla APT değildir;
> "yetkisiz kaynak kullanımı" politika ihlalidir. Severity 3.

## Bu use case nedir? (Basit anlatım)

Mining = bir cihazın CPU/GPU'sunu kripto para üretmek için kullanmak.
Saldırgan veya yetkisiz çalışan, kurum cihazlarını mining için
kullanırsa: elektrik faturası artar, donanım yıpranır, gerçek iş yükü
performansı düşer.

SGB'nin **mining pool / wallet host** listesi (`SGB_MM_IP`,
`SGB_MM_DOMAIN`) firewall, NetFlow, proxy ve DNS log'larında aranır.

Severity 3 olmasının nedeni: çoğu mining = "policy violation" (politika
ihlali), zorunlu IR olayı değil. Ama yine de:
- Container'ize edilmiş cryptojacking malware olabilir.
- Tedarikçi kütüphanesinde compromise olmuş olabilir (supply-chain).
- Insider threat olabilir.

Bu yüzden ticket açılır, haftalık özet raporda yer alır.

## Senaryo (Hikâye)

- 02:00 — Lab `LIN-LAB-44` sunucusu `monero-pool.example:4444`'e
  bağlantı denediği görülür.
- 02:00:02 — SIEM destination'u `SGB_MM_DOMAIN`'de bulur → severity 3.
- 02:00:03 — Haftalık özet raporda yer alacak şekilde kayıt.
- 02:30 — Eğer aynı host'ta CPU > %85 ise UC-MM-002 composite tetiklenir.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.6.4** | Kara Liste Kullanımı | Mining indicator'ları kara listenin parçası. |
| **3.1.6.5** | İzin Verilmeyen Trafiğin Engellenmesi | Mining trafik politika dışı → blok. |
| **3.1.5.1** | Zararlı Yazılımdan Korunma | Cryptojacking malware bu kapsamda. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | UC bizatihi SIEM kuralı. |
| **3.3.1.10** Taşınabilir cihaz ayrımı | Lab/dev cihazlar mining yapıyorsa segmentasyon değerlendirilmeli. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-MM-001 |
| MITRE | TA0040 Impact / T1496 Resource Hijacking |
| Connectiontype | MM |
| Severity (base) | 3 (policy/perf) |
| Veri kaynakları | Firewall, NetFlow, Proxy, DNS |
| Reference / lookup | `SGB_MM_IP`, `SGB_MM_DOMAIN`, `SGB_IP_MAP` |
| Response | PB-MM-001 (ticket + haftalık raporda yer alır) |

## Tespit mantığı

```text
when firewall/netflow/proxy event geldi
  AND dest_ip in SGB_MM_IP OR DNS query in SGB_MM_DOMAIN
then alarm (severity=3), add host to SGB_MINING_HOSTS, weekly report
```

## QRadar uygulaması

```
when dest_ip in SGB_MM_IP OR DNS query in SGB_MM_DOMAIN
```

**Response:** severity 3, add → `SGB_MINING_HOSTS`, weekly summary report.

## Splunk uygulaması

**Saved search:** `SGB - UC-MM-001 - Mining pool outbound`

```spl
(`sgb_firewall_index` OR `sgb_dns_index`)
| lookup sgb_ip_lookup    value AS dest_ip OUTPUT connectiontype AS ct_ip
| lookup sgb_domain_lookup value AS query   OUTPUT connectiontype AS ct_dom
| where ct_ip="MM" OR ct_dom="MM"
| stats count by src_ip, dest_ip, query
```

## Yanlış pozitif notları

- **IT admin test/dev ortamında crypto wallet** → exception by asset role.
- **Browser extension dolayli mining** (CoinHive vb. eğer block edilmediyse)
  → kullanıcıya bilgilendirme yeterli, hard block değil.
- **Blockchain dev ekibi** → dedicated exception.

## Olay müdahale (PB-MM-001)

**Otomatik:**
1. Source host → `SGB_MINING_HOSTS`.
2. Haftalık özet raporuna ekleme (Slack / email).

**Manuel (haftalık triage):**
1. Hangi process mining yapıyor? EDR ile süre.
2. Insider mi, malware mi, supply-chain mi?
3. Eğer composite UC-MM-002 tetiklendiyse → IR ticket P3.
