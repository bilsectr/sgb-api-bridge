# UC-XX-004 — SGB Feed Sağlık ve Bütünlük İzleme (Operasyonel)

> **TL;DR:** Feed'in kendisini izleyen operasyonel kural: reference
> set/lookup eleman sayısı ani düşerse veya feed güncellenmeyi keserse
> alarm üretir. Feed sessizce boşalırsa **tüm UC kütüphanesi kör kalır**
> ve hiçbir güvenlik kuralı bunu haber vermez — "eşleşme yok" durumu
> "tehdit yok" ile aynı görünür.

## Bu use case nedir? (Basit anlatım)

Bu kütüphanedeki bütün kurallar tek bir varsayıma dayanır: "SGB feed'i
SIEM'e güncel ve eksiksiz yüklü." Bu varsayım bozulduğunda — API kesintisi,
sync hatası, TAXII servis arızası, reference set'in yanlışlıkla
temizlenmesi — kurallar hata vermez, sadece **eşleşme üretmeyi keser**.
SOC için bu en tehlikeli arıza modudur: gösterge yokluğu, güvenlik
yokluğuyla karıştırılır.

Bu UC üç kontrolü periyodik çalıştırır:

1. **Hacim:** reference set / lookup eleman sayısı bir önceki ölçüme göre
   >%20 düştü mü?
2. **Tazelik:** TAXII koleksiyonuna son N saatte yeni obje eklendi mi?
   (Normal kadans saatliktir.)
3. **Nabız (opsiyonel):** son 24 saatte hiçbir SGB kuralı eşleşme
   üretmediyse bilgi alarmı — normal hacimli bir kurumda en azından PH
   eşleşmesi beklenir.

## Senaryo (Hikâye — gerçek olay, 10 Haziran 2026)

- 10 Haziran, ~11:17 — SGB API'si geçici olarak boş sayfalar döndürür;
  saatlik sync bunu "kayıtlar kaldırılmış" olarak yorumlar ve **324.181
  domain'i removed** işaretler.
- Feed dosyası ~454K satırdan ~130K satıra iner; firewall'lar ve SIEM
  reference set'leri sessizce daralır.
- Hiçbir güvenlik kuralı alarm üretmez — kapsama kaybını gören tek şey
  commit geçmişindeki `stats.json` diff'idir.
- **UC-XX-004 kurulu olsaydı:** bir sonraki saatlik kontrolde "domain set
  eleman sayısı %71 düştü" alarmı üretilir, SOC feed'i degraded moda alır
  ve kaynak taraflı teşhis dakikalar içinde başlardı.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.8.8** | SIEM'in Düzenli Olarak Yapılandırılması | Korelasyon altyapısının girdisinin (feed) sürekli doğrulanması. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | Bildirim akışının **kesintisiz** işlediğinin denetlenebilir kanıtı. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | İzleme altyapısının kendi kendini izlemesi. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-XX-004 |
| MITRE | — (operasyonel kural; ATT&CK tekniği yok) |
| Connectiontype | XX (meta — tüm CT'lerin ön koşulu) |
| Severity | N/A — güvenlik offense'ı değil; önerilen: P2 operasyon ticket'ı |
| Veri kaynakları | SIEM reference set/lookup metadata'sı, TAXII koleksiyon manifest'i, `stats.json` |
| TAXII koleksiyonu | Tümü (koleksiyon bağımsız sağlık kontrolü) |
| Response | PB-XX-004 (feed restore + degraded mod + retro-hunt) |

## Tespit mantığı (vendor-bağımsız)

```text
schedule = saatlik
checks:
  1. hacim:    count_now < count_1h_ago * 0.8        → alarm (ani daralma)
  2. tazelik:  TAXII'de son eklenen obje > 3 saat eski → alarm (stale feed)
               (kaynak tarafı: stats.json last_update_utc > 3 saat eski)
  3. nabız:    son 24 saatte 0 SGB eşleşmesi           → bilgi alarmı
then P2 operasyon ticket'ı aç + feed'e bağımlı kuralları "degraded" etiketle
```

## QRadar uygulaması

QRadar reference set boyutunu kural içinden okuyamaz; küçük bir cron
script'i gerekir:

1. Script saatte bir `/api/reference_data/sets/{name}` çağırır,
   `number_of_elements` değerini syslog event'i olarak QRadar'a gönderir.
2. Event Rule: yeni değer, önceki değerin %80'inin altındaysa →
   "SGB Feed Volume Drop" alarmı.
3. Tazelik için: TAXII feed'inin "last polled / objects added" log'u
   3 saatten eskiyse aynı script ikinci bir event üretir.

## Splunk uygulaması

**Saved search 1 (snapshot, saatlik):**

```spl
| inputlookup sgb_domain_lookup | stats count AS n
| eval feed="domain", _time=now()
| outputlookup append=t sgb_feed_count_history
```

**Saved search 2 (kontrol, saatlik):**

```spl
| inputlookup sgb_feed_count_history
| sort - _time | streamstats count AS rank by feed | where rank <= 2
| stats latest(n) AS now earliest(n) AS prev by feed
| eval drop_pct=round(100*(prev-now)/prev, 1)
| where drop_pct > 20
```

## Yanlış pozitif / kalibrasyon notları

- **SGB'nin meşru toplu temizliği:** SGB gerçekten çok sayıda kaydı
  kaldırabilir. Alarm "feed bozuk" demek değildir; "insan baksın"
  demektir. Eşik %20 başlangıç değeridir, feed davranışına göre kalibre
  edin.
- **Planlı bakım pencereleri** (SIEM upgrade, lookup rebuild) → bakım
  takvimiyle suppress.
- **Nabız kontrolü** küçük kurumlarda (az kullanıcı, az trafik) doğal
  olarak sessiz kalabilir → pencereyi 72 saate çıkarın veya devre dışı
  bırakın.

## Olay müdahale (PB-XX-004)

**Otomatik:**
1. P2 operasyon ticket'ı aç (güvenlik offense kuyruğunu kirletme).
2. Feed'e bağımlı UC'leri dashboard'da "degraded" işaretle.

**Manuel:**
1. Sync loglarını incele (GitHub Actions `sync-delta.yml` çalışmaları).
2. `stats.json` commit geçmişini diff'le — düşüş hangi sync'te başladı?
3. SGB API'sini elle kontrol et (boş sayfa mı, hata mı, gerçek silme mi?).
4. Gerekirse `feeds-latest` release asset'inden son sağlıklı SQLite'ı
   geri yükle; reference set'leri yeniden besle.
5. Feed normale döndükten sonra: kesinti penceresini [UC-XX-005](UC-XX-005.md)
   retro-hunt ile geriye dönük tara — kesinti sırasında kaçan eşleşmeler
   telafi edilir.
