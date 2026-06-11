# SGB SIEM Use Case Kütüphanesi

SGB indicator feed'ini tüketen **vendor-bağımsız** use case kütüphanesi.
Her use case Türkçe ve detaylı anlatımla; BG Rehberi madde eşleştirmesi
ile birlikte gelir.

> **BG Rehberi ile ilişki:** Bu kütüphane, Bilgi ve İletişim Güvenliği
> Rehberi'nin **3.1.8.7 — Kayıt Analizi Araçları Kullanımı (SIEM)** ve
> **3.1.10.4 — Siber Tehdit Bildirimlerinin Yönetilmesi** maddelerinin
> operasyonel karşılığıdır. Tüm madde eşleştirmeleri için:
> [../bg-rehber-mapping.md](../bg-rehber-mapping.md).

Her use case'in:

- Kanonik tanımı burada (bu dizinde, `UC-*.md`)
- BG Rehberi karşılığı (her dosyanın "BG Rehberi karşılığı" bölümü)
- TAXII koleksiyon eşleşmesi (her dosyanın "Teknik özet" tablosunda)
- Ürün bazlı kurulum: [integrations/](../integrations/) (QRadar, Splunk, Sentinel, MISP, OpenCTI, XSOAR, …)
- Severity formülü: aşağıdaki [Severity matrisi](#severity) bölümü

## ID konvansiyonu

```
UC-<CT>-<NNN>   CT = connectiontype kodu (PH/BC/AC/EK/MF/MM/MC/OT)
UC-XX-<NNN>     Cross-category / meta-rule
```

## Index

| ID | Türkçe başlık | CT | Severity (base) | Birincil BG maddeleri |
|----|---------------|----|------|------|
| [UC-PH-001](UC-PH-001.md) | SGB Phishing Domain'ine DNS Sorgusu | PH | 5 | 3.1.5.7, 3.1.6.20 |
| [UC-PH-002](UC-PH-002.md) | Proxy Üzerinden SGB Phishing URL'sine HTTP İsteği | PH | 5 | 3.1.6.20, 3.1.6.22 |
| [UC-PH-003](UC-PH-003.md) | Mail body link → SGB Phishing | PH | 6 | 3.1.4.10 |
| [UC-BC-001](UC-BC-001.md) | SGB Botnet C&C IP'sine Outbound | BC | 8 | 3.1.5.1, 3.1.6.4, 3.1.6.5 |
| [UC-BC-002](UC-BC-002.md) | SGB Botnet C&C Domain'ine DNS | BC | 8 | 3.1.5.7, 3.1.6.4 |
| [UC-BC-003](UC-BC-003.md) | SGB IP'sine Periyodik Beacon (NetFlow) | BC | 9 | 3.1.6.4, 3.1.6.18 |
| [UC-BC-004](UC-BC-004.md) | DNS Yanıtı SGB C&C IP'sine Çözümleniyor | BC | 8 | 3.1.5.7, 3.1.6.4 |
| [UC-AC-001](UC-AC-001.md) | Herhangi SGB APT C&C Eşleşmesi | AC | 10 | 3.1.10.4, 3.1.10.5, 3.1.10.8 |
| [UC-AC-002](UC-AC-002.md) | Aynı Asset 3+ APT match / 30 dk | AC | 10 | 3.1.10.4, 3.1.10.5 |
| [UC-EK-001](UC-EK-001.md) | HTTP → SGB Exploit Kit URL | EK | 8 | 3.1.6.20, 3.1.6.28 |
| [UC-EK-002](UC-EK-002.md) | IDS Exploit + SGB EK Composite | EK | 9 | 3.1.6.18, 3.1.6.28 |
| [UC-MF-001](UC-MF-001.md) | Proxy ile SGB Malware URL'den İndirme | MF | 7 | 3.1.5.1, 3.1.6.20 |
| [UC-MF-002](UC-MF-002.md) | EDR Dosya + SGB Malware Host (Composite) | MF | 8 | 3.1.5.1, 3.1.5.6 |
| [UC-MM-001](UC-MM-001.md) | SGB Mining Indicator'ına Outbound | MM | 3 | 3.1.6.4, 3.1.6.5 |
| [UC-MM-002](UC-MM-002.md) | CPU Spike + SGB MM Composite | MM | 5 | 3.1.5.1, 3.1.10.8 |
| [UC-MC-001](UC-MC-001.md) | Mobile/VPN → SGB Mobile C&C | MC | 7 | 3.3.1, 3.1.6.4 |
| [UC-MC-002](UC-MC-002.md) | MDM App → SGB Mobile C&C | MC | 7 | 3.3.1, 3.3.1.3 |
| [UC-OT-001](UC-OT-001.md) | Herhangi SGB OT Match (Bilgilendirme) | OT | 3 (kritik segmentte 5) | 3.1.10.4, 3.1.8.7 |
| [UC-XX-001](UC-XX-001.md) | Asset 2+ Farklı CT / 24 Saat | XX | 8 | 3.1.8.7, 3.1.10.8 |
| [UC-XX-002](UC-XX-002.md) | Aynı Indicator 2x / 7 Gün (Re-infection) | XX | 7 | 3.1.8.7, 3.1.10.8 |
| [UC-XX-003](UC-XX-003.md) | Kurum Geneli Kritiklik Spike | XX | dinamik 7-10 | 3.1.8.7, 3.1.10.5 |
| [UC-XX-004](UC-XX-004.md) | SGB Feed Sağlık ve Bütünlük İzleme | XX | — (operasyonel) | 3.1.8.8, 3.1.10.4 |
| [UC-XX-005](UC-XX-005.md) | Yeni Indicator İçin Retro-Hunt | XX | CT base'i devralır | 3.1.8.6, 3.1.8.7 |
| [UC-XX-006](UC-XX-006.md) | SGB IP'sinden Kuruma Inbound Erişim | XX | dinamik 5-10 | 3.1.6.4, 3.1.8.7 |

## Devreye alma önceliği {#tiers}

Kütüphane CT taksonomisinin tamamını kapsar; ancak feed'in veri hacmi
CT'ler arasında çok dengesizdir (2026-06 itibarıyla: PH ~%70, OT ~%21,
BC+AC ~%5; EK ~25 ve MM ~200 aktif kayıt — ikisi birlikte feed'in
%0,05'i). Sıfırdan kurulumda önerilen sıra:

| Tier | UC'ler | Gerekçe |
|------|--------|---------|
| **1 — önce bunlar** | UC-XX-004, UC-PH-001/002/003, UC-BC-001/002, UC-AC-001/002 | Feed sağlığı diğer her kuralın ön koşulu. PH feed hacminin %71'i; BC/AC en yüksek severity'li gerçek tehdit sinyalleri. |
| **2 — olgunlaşınca** | UC-BC-003/004, UC-MF-001/002, UC-MC-001/002, UC-XX-001/002/005/006 | Composite/meta kurallar; Tier 1 çıktılarına ve ek veri kaynaklarına (NetFlow, EDR, MDM, DNS response, auth logları) bağımlı. |
| **3 — düşük hacim / bilgilendirme** | UC-EK-001/002, UC-MM-001/002, UC-OT-001, UC-XX-003 | EK ve MM koleksiyonları çok küçük (feed'in ~%0,05'i) — kural maliyetsizse açın ama tetiklenme beklemeyin. OT info-only baseline. |

## Connectiontype kapsama matrisi

| CT | Açılım | Data source ailesi |
|----|--------|---------------------|
| PH | Phishing | DNS, Proxy, Email |
| BC | Botnet C&C | Firewall, Proxy, NetFlow |
| AC | APT C&C | TÜM kaynaklar (yüksek hassasiyetli match) |
| EK | Exploit Kit | Proxy, IDS, EDR |
| MF | Malware File | Proxy, EDR, Email-link |
| MM | Mining | Firewall, NetFlow, EDR perf |
| MC | Mobile C&C | MDM, Mobile VPN, App gateway |
| OT | Other — sınıflandırılmamış (Operational Technology/EKS **değildir**) | Generic (bilgilendirme) |
| XX | Cross/Meta | Tüm SGB notable event'larını aggregate eder |

> **Not — `category` boyutu:** SGB API'si connectiontype'tan bağımsız
> ikinci bir sınıflandırma ekseni daha yayınlar (`category`:
> BP/CA/MC/MD/MI/MU/PH) ve sync bu kataloğu DB'ye yazar. UC kütüphanesi
> şu an yalnızca connectiontype kullanır; `category` alanı
> zenginleştirme ve dashboard kırılımı için kullanılabilir.

## BG Rehberi → UC matrisi (özet)

| BG Rehberi maddesi | İlgili UC'ler |
|--------------------|---------------|
| **3.1.5.1** Zararlı Yazılımdan Korunma + Merkezi Yönetim | UC-PH-*, UC-BC-*, UC-EK-*, UC-MF-*, UC-MM-* |
| **3.1.5.6** Tespitlerin Merkezi Tutulması | UC-MF-002, UC-AC-001 |
| **3.1.5.7** DNS Sorgu Kayıtları | UC-PH-001, UC-BC-002, UC-BC-004 |
| **3.1.6.4** Kara Liste Kullanımı | UC-BC-*, UC-MM-*, UC-MC-001, UC-XX-006 |
| **3.1.6.5** İzin Verilmeyen Trafik Engellenmesi | UC-BC-001, UC-MM-001 |
| **3.1.6.18** IDS/IPS Kullanımı | UC-BC-003, UC-EK-002 |
| **3.1.6.20** A Tabanlı URL Filtreleri | UC-PH-002, UC-MF-001, UC-EK-001 |
| **3.1.6.21** URL Kategori Hizmeti | UC-PH-002 |
| **3.1.6.22** URL'lerin Kayıt Altına Alınması | UC-PH-002 |
| **3.1.6.28** Uygulama Seviyesi Saldırılar (WAF/IPS) | UC-EK-001, UC-EK-002 |
| **3.1.8.6** Merkezi Kayıt Yönetimi | Tüm UC'ler; UC-XX-005 retro-hunt log saklama süresine doğrudan bağımlıdır |
| **3.1.8.7** Kayıt Analizi Araçları (SIEM) | **Tüm UC'ler** (ortak) |
| **3.1.8.8** SIEM Düzenli Yapılandırma | UC-XX-001, UC-XX-002, UC-XX-004 |
| **3.1.10.4** Siber Tehdit Bildirimlerinin Yönetilmesi | **Tüm UC'ler** (ortak — projenin omurgası) |
| **3.1.10.5** Olay Raporlarının Standardize Edilmesi | UC-AC-*, UC-XX-003 |
| **3.1.10.8** Olay Puanlama / Önceliklendirme | UC-AC-*, UC-MM-002, UC-XX-* |
| **3.3.1** Akıllı Telefon ve Tablet Güvenliği | UC-MC-001, UC-MC-002 |
| **3.3.2** Taşınabilir Bilgisayar Güvenliği | UC-MF-002 |

## TAXII koleksiyon → UC eşleştirmesi {#taxii}

Tüm UC'ler [TAXII 2.1 servisi](../setup-taxii.md) (`https://sgb-taxii.bilsec.tr/taxii2/`)
üzerinden tüketilir. SIEM kuralı yazarken eşleşen koleksiyonu aboneliğe alın:

| UC prefix | TAXII collection |
|-----------|------------------|
| `UC-PH-*` | `sgb-phishing` |
| `UC-BC-*` | `sgb-botnet-cc` |
| `UC-AC-*` | `sgb-apt-cc` |
| `UC-EK-*` | `sgb-exploit-kit` |
| `UC-MF-*` | `sgb-malware-download` |
| `UC-MM-*` | `sgb-mining` |
| `UC-MC-*` | `sgb-mobile-cc` |
| `UC-OT-*` | `sgb-other` |
| `UC-XX-*` (çapraz) | İlgili tüm koleksiyonlara abone ol |

> **Not:** [UC-BC-004](UC-BC-004.md) cevap-IP eşleşmesi için hem
> `sgb-botnet-cc` hem `sgb-apt-cc` koleksiyonlarının IP'lerini kullanır.

## Severity matrisi {#severity}

Tüm SIEM'lerde aynı formül kullanılır:

| CT | Anlam | Base severity |
|----|-------|--------------:|
| AC | APT C&C | **10** (sabit) |
| BC | Botnet C&C | 8 |
| EK | Exploit Kit | 8 |
| MF | Malware Download | 7 |
| MC | Mobile C&C | 7 |
| PH | Phishing | 5 |
| MM | Mining | 3 |
| OT | Other | 3 |

`final_severity = clamp(base + ((criticality_level - 5) / 2), 1, 10)`

- criticality 8+ → +1.5 → +2
- criticality ≤ 3 → -1
- criticality 4-7 → değişiklik yok

**Source confidence (offense açma eşiği):**

- Source ∈ {US, SB, SO} → offense aç
- Source = RS → offense aç, severity -1
- Source = IH → offense açma, yalnız kayıt at (yüksek FP)
  - **İstisna (AC, BC):** APT ve Botnet C&C eşleşmelerinde `source=IH`
    olsa bile offense açılır — bu iki CT'de ihbar kayıtlarının doğruluğu
    yüksektir (bkz. [UC-AC-001](UC-AC-001.md), [UC-BC-001](UC-BC-001.md)).
    Otomatik blok aksiyonları yine de manuel onay gerektirir.

## Yeni use case eklemek

1. [_template.md](_template.md) kopyala → `UC-<CT>-<NNN>.md`
2. README'deki Index tablosuna satır ekle (BG madde referansı dahil)
3. Teknik özet tablosunda doğru TAXII koleksiyonunu belirt
4. [../bg-rehber-mapping.md](../bg-rehber-mapping.md) içindeki "UC → BG madde
   matrisi" tablosuna satır ekle
5. (Opsiyonel) [../integrations/](../integrations/) altına yeni ürün ingest guide'ı yaz
