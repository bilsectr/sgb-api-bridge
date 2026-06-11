# UC-XX-005 — Yeni Eklenen Indicator İçin Retro-Hunt (Geriye Dönük Tarama)

> **TL;DR:** Feed'e yeni eklenen her indicator, geçmiş loglarda da aranır
> (30-90 gün). SGB bir IoC'yi yayınladığında saldırı çoğu zaman haftalar
> önce başlamıştır; gerçek-zamanlı kurallar yalnızca "yayın sonrası"
> trafiği görür. Bu meta-kural yayın **öncesi** compromise'ı yakalar.

## Bu use case nedir? (Basit anlatım)

Kütüphanedeki bütün gerçek-zamanlı kurallar şu anda akan log'u feed ile
karşılaştırır. Ama tehdit istihbaratının doğası gereği indicator'lar
**geriden gelir**: SGB bir C&C domain'ini tespit edip yayınladığında, o
altyapı haftalardır aktif olabilir. Kurum o domain'e 3 hafta önce
bağlandıysa hiçbir kural tetiklenmemiştir — log'lar duruyordur ama kimse
o gözle bakmamıştır.

Retro-hunt bu boşluğu kapatır: günde bir kez, **son 24 saatte feed'e
eklenen** indicator'lar (TAXII `added_after` parametresi tam bunu verir)
geçmiş loglarda aranır. Eşleşme bulunursa "retro-hunt" etiketli alarm
açılır — olay zamanı, log'un orijinal zamanıdır.

İkinci kullanım: [UC-XX-004](UC-XX-004.md) bir feed kesintisi tespit
ettiğinde, kesinti penceresi bu mekanizmayla geriye dönük taranır.

## Senaryo (Hikâye)

- 1 Mart — `WIN-ENG-15`, `stage.evilcorp.example` domain'ine bağlanır.
  Domain o tarihte hiçbir feed'de yok; alarm üretilmez.
- 12 Mart 09:00 — SGB domain'i AC (APT C&C) olarak yayınlar; saatlik
  sync ile feed'e girer.
- 13 Mart 02:00 — Gece retro-hunt job'ı son 24 saatte eklenen
  indicator'ları 30 günlük geçmişte arar.
- 13 Mart 02:05 — 1 Mart'taki bağlantı bulunur → severity 10, "retro-hunt"
  etiketli alarm. Host **12 gündür** potansiyel compromise altında;
  kapsam belirleme (scoping) derhal başlar.

## BG Rehberi karşılığı

| Madde | Madde adı | Bu UC ne sağlar? |
|-------|-----------|-------------------|
| **3.1.8.6** | Merkezi Kayıt Yönetimi | Log saklama süresi bu kuralın ön koşuludur — retention yoksa retro-hunt yoktur. |
| **3.1.8.7** | Kayıt Analizi Araçları (SIEM) | Tarihsel korelasyon — maddenin geriye dönük uygulanması. |
| **3.1.10.4** | Siber Tehdit Bildirimlerinin Yönetilmesi | Bildirimin yalnız geleceğe değil geçmişe de uygulanması. |
| **3.1.10.8** | Siber Olay Puanlama ve Önceliklendirme | Retro bulgular compromise süresine göre önceliklendirilir. |

## Teknik özet

| Alan | Değer |
|------|-------|
| ID | UC-XX-005 |
| MITRE | Çapraz — eşleşen indicator'ın CT'sine göre (tarihsel tespit) |
| Connectiontype | XX (meta — tüm CT'ler) |
| Severity | Eşleşen CT'nin base severity'sini devralır ([README.md#severity](README.md#severity)); alarm "retro-hunt" etiketi taşır |
| Veri kaynakları | Geçmiş loglar (proxy, DNS, firewall, mail) + feed delta'sı (TAXII `added_after`) |
| TAXII koleksiyonu | Tümü (yeni eklenen objeler koleksiyon bağımsız taranır) |
| Response | PB-XX-005 (tarihsel IR — kapsam belirleme öncelikli) |

## Tespit mantığı (vendor-bağımsız)

```text
schedule = günlük (gece, düşük yük penceresi)
input    = son 24 saatte feed'e EKLENEN indicator'lar (TAXII added_after)
window   = domain/URL için 30-90 gün geriye
           IP için 7-14 gün geriye (IP churn — aşağıdaki FP notuna bakın)
when geçmiş event'te yeni indicator eşleşmesi bulunursa
then alarm aç ("retro-hunt" etiketi)
     severity = eşleşen CT'nin base severity'si
     olay zamanı = log'un orijinal zamanı (job'ın çalışma zamanı değil)
```

## QRadar uygulaması

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

## Splunk uygulaması

**Saved search:** `SGB - UC-XX-005 - Retro-hunt new indicators` (cron: gece)

```spl
| tstats count min(_time) AS first_seen
  WHERE (index IN (proxy, dns, firewall)) earliest=-30d
    [| inputlookup sgb_indicators
     | where added_utc >= relative_time(now(), "-1d")
     | fields value | rename value AS query | format ]
  BY src_ip, query
| lookup sgb_domain_lookup value AS query OUTPUT connectiontype
| eval alert_type="retro-hunt", event_time=strftime(first_seen, "%F %T")
```

(IP indicator'ları için aynı arama `dest_ip` alanı ve `earliest=-14d`
penceresiyle ayrı koşulur.)

## Yanlış pozitif notları

- **IP churn:** Bir IP'nin sahibi zamanla değişir — feed'e bugün giren IP,
  3 hafta önceki logda tamamen başka bir hizmete aitti olabilir. Bu
  yüzden IP retro-hunt penceresi kısa tutulur (7-14 gün); domain ve URL
  90 güne kadar güvenlidir.
- **CDN / paylaşımlı hosting** geçmiş eşleşmelerde de aynı FP'yi üretir →
  gerçek-zamanlı kurallardaki exception listeleri retro-hunt'a da
  uygulanmalı.
- **Retention sınırı:** SIEM'de 30 günden kısa saklama varsa pencereyi
  retention'a göre daraltın; kural hata vermez ama sessizce eksik tarar.

## Olay müdahale (PB-XX-005)

**Retro bulgu, canlı alarmdan farklı ele alınır — olay geçmişte:**

1. **Kapsam belirleme önce gelir:** eşleşme tarihinden bugüne host neler
   yaptı? (Lateral hareket, yeni hesaplar, veri çıkışı.)
2. Host'un bugünkü durumunu doğrula: EDR full scan, persistence kontrolü.
3. Aynı indicator'a o dönemde başka host da hit etmiş mi? (Retro sonucu
   genişlet.)
4. AC eşleşmesiyse: compromise süresi bilgisiyle birlikte SGB raporlaması
   (3.1.10.5) — "X gündür aktif" bilgisi rapor önceliğini değiştirir.
5. Olay zaman çizelgesine retro bulgunun **orijinal log zamanını** yaz;
   alarm zamanı yanıltıcıdır.
