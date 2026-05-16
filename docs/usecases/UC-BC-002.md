# UC-BC-002 — DNS Sorgusu SGB Botnet C&C Alan Adına Gidiyor

> **TL;DR:** UC-BC-001 IP bazlı tespit yapar; bu UC ise DNS bazlı tespit
> yapar. Botnet operatörleri C&C IP'sini sık değiştirir; **domain bazlı
> tespit fast-flux ve DGA durumlarında çok daha güvenilirdir.**

## Bu use case nedir? (Basit anlatım)

Botnet C&C alt yapıları çoğu zaman tek IP yerine **domain** üzerinden
çalışır. Saldırgan IP'yi her birkaç saatte değiştirip aynı domain'in
DNS kaydını güncelliyor (fast-flux) — veya bir algoritma ile günlük yeni
domain üretiyor (DGA: Domain Generation Algorithm).

Bu durumda **IP listesi her zaman geç kalır**, ama domain listesi
saldırganın "ev adresi"ni tutar. Bu yüzden SGB feed'inde hem IP hem
domain ayrı set olarak bulunur ve **iki ayrı kural** koşulur.

UC-BC-001 + UC-BC-002 ikisi birlikte yüksek kapsama sağlar; aynı asset
1 saat içinde her ikisini de tetiklerse meta-rule [UC-XX-001](UC-XX-001.md)
devreye girer ("multi-stage compromise" göstergesi).

## Senaryo (Hikâye)

- 23:14 — Bot, DGA ile günün domain'ini hesaplar: `xj3kfasd9.example`.
- 23:14:01 — DNS sorgusu kurum DNS sunucusundan geçer.
- 23:14:02 — SIEM, query alanını `SGB_BC_DOMAIN` set'inde bulur.
- 23:14:02 — Severity 8 alarm; host `WIN-DEV-12` `SGB_INFECTED_HOSTS`'a
  eklenir.
- 23:14:05 — Otomatik response: DNS sinkhole, sorgu sahte 127.0.0.1
  dönecek şekilde yönlendirilir; SOC bilgilendirilir.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.5.1** | Zararlı Yazılımdan Korunma | DNS katmanında zararlı altyapı tespiti. |
| **3.1.5.7** | DNS Sorgularının Kayıtlarının Tutulması | DNS log'unu anlamlandırır. |
| **3.1.6.4** | Kara Liste Kullanımı | DNS RPZ (Response Policy Zone) için zararlı domain listesi. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | UC bizatihi SIEM kuralı. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB domain feed'i operasyonel kullanım. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-BC-002 |
| MITRE | TA0011 / T1071.004 DNS C2 |
| Connectiontype | BC |
| Severity (base) | 8 |
| Veri kaynakları | DNS query logs (BIND, Windows DNS, Infoblox, Umbrella) |
| Reference / lookup | `SGB_BC_DOMAIN`, `SGB_DOMAIN_MAP` |
| Response | PB-BC-002 (DNS sinkhole + host quarantine) |

## Tespit mantığı

```text
when DNS query event geldi
  AND query alanı SGB_BC_DOMAIN set'inde
  AND source network "Trusted"
then offense aç, severity=8 + criticality modifier
     source IP'yi SGB_INFECTED_HOSTS'a ekle
```

## QRadar uygulaması

```
when the event QID is one of: DNS Query QIDs
  AND when query property is in SGB_BC_DOMAIN
  AND when source network is in Trusted
```

**Response:**
- Severity 8 + criticality modifier
- Add source IP → `SGB_INFECTED_HOSTS`
- Annotate offense "SGB Botnet C2 DNS"

## Splunk uygulaması

**Saved search:** `SGB - UC-BC-002 - Botnet C2 DNS query`

**Macro:** `sgb_botnet_dns_search`

```spl
`sgb_dns_index`
| lookup sgb_domain_lookup value AS query OUTPUT connectiontype, criticality_level, source
| where connectiontype="BC"
| stats count values(query) AS queried_domains by src_ip, source
```

## Yanlış pozitif notları

- **Security tooling** (VirusTotal, URLscan, URLhaus) doğal olarak malware
  domain'lerine DNS sorgusu yapar → SOC asset list exception.
- **Sinkhole DNS sunucuları** (Conficker sinkhole, Microsoft DCU sinkhole)
  SGB feed'inde olabilir. Sinkhole'a sorgu aslında "iyi haber" sayılır
  (zararlı yazılım yakalandı, sinkhole'a yönlendirildi); severity'yi 3'e
  düşürün, alarm'ı sadece kayıt için tut.
- **DNS resolver chaining'inde** kurum DNS sorgusu upstream'e iletirken
  upstream'in log'u tetiklenebilir → kurum içi `Trusted` filtresi şart.

## Olay müdahale (PB-BC-002)

**Otomatik:**
1. DNS RPZ ile alan adını sinkhole IP'sine yönlendir.
2. Source host'u `SGB_INFECTED_HOSTS`'a ekle.
3. EDR'de host'a "scan now" tetikle.

**Manuel:**
1. Host'ta domain'i hangi process sorguladı? (Sysmon Event 22 / EDR DNS
   telemetry)
2. Aynı domain'i sorgulayan başka host var mı? (Lateral hareket göstergesi)
3. UC-BC-001 ile cross-reference: aynı host IP bazlı bağlantı da yaptı mı?
   Evetse iki sinyal birleşir, compromise kesin.
4. Disk imaging + memory dump.
