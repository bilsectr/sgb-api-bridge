# Docker Kurulumu

Tek konteyner ile SGB API Bridge'i ayağa kaldır. İçinde **nginx** (feed'leri
HTTP olarak yayar) + **sync loop** (saatte bir SGB API'sinden delta sync)
birlikte çalışır.

## Bu kurulum BG Rehberi'nin neyini karşılar?

| Madde | Madde adı | Bu kurulum nasıl katkı sağlar? |
|-------|-----------|--------------------------------|
| **3.1.10.4** ⭐ | Siber Tehdit Bildirimlerinin Yönetilmesi | SGB API → kurum içi feed sunucusu = "bildirimlerin operasyonel altyapısı". |
| **3.1.5.1** | Zararlı Yazılımdan Korunma + Merkezi Yönetim | Saatlik otomatik sync = "imza/IoC veri tabanı güncel olmalı". |
| **3.1.6.4** | Kara Liste Kullanımı | Feed çıktısı doğrudan firewall/proxy kara listesinin **veri kaynağı**. |
| **3.1.13** | Felaket Kurtarma | Tek konteyner + named volume + GitHub Actions yedek kanal = basit DR profili. |

> Tüm BG madde eşleştirmeleri için: [bg-rehber-mapping.md](bg-rehber-mapping.md)

## Önkoşullar

- Docker 20.10+ (compose v2 ile)
- Host'tan SGB API'sine (`https://siberguvenlik.gov.tr`) erişim. Proxy varsa
  Docker daemon ayarlarında `HTTPS_PROXY` set edilmeli.
- ~1 GB disk (state + feed dosyaları için).

## Hızlı başlangıç (5 dakika)

```bash
docker run -d \
  --name sgb-api-bridge \
  -p 8080:80 \
  -v sgb-api-bridge-data:/data \
  --restart unless-stopped \
  ghcr.io/bilsectr/sgb-api-bridge:latest
```

Konteyner ayağa kalkar ve **hemen kullanılabilir**:

- İmaj, geçmiş feed verisini (`docs/*-list.txt`) ve `state/seen_ids.json`'u
  **gömülü taşır**. Boş bir volume'a ilk açılışta bu seed verisi `/data`'ya
  kopyalanır.
- HTTP 8080 portu anında dolu feed'leri sunar — full sync beklemeye gerek yok.
- Internal loop her saat **delta sync** çalıştırır, seed verisindeki
  `max_id`'den devam eder.
- `docker logs -f sgb-api-bridge` ile izleyebilirsin.

> İmaj her hafta yeniden build edilir; gömülü seed verisi en fazla ~1 hafta
> bayattır, ilk delta bu boşluğu kapatır. **Full sync gerekmez.**

## docker-compose ile

```bash
git clone https://github.com/bilsectr/sgb-api-bridge.git
cd sgb-api-bridge
docker compose -f docker/docker-compose.yml up -d
docker compose -f docker/docker-compose.yml logs -f
```

## Feed URL'leri

```
http://<host-ip>:8080/domain-list.txt
http://<host-ip>:8080/ip-list.txt
http://<host-ip>:8080/url-list.txt
http://<host-ip>:8080/ip6-list.txt
http://<host-ip>:8080/ip6net-list.txt
http://<host-ip>:8080/stats.json
```

Bu URL'leri firewall/proxy/SIEM cihazlarına **kara liste kaynağı** olarak
verirsiniz. Cihaz konfigürasyonu örneği — FortiGate:

```
config system external-resource
    edit "SGB-Domain"
        set type domain
        set resource "http://10.0.0.5:8080/domain-list.txt"
        set refresh-rate 60
    next
    edit "SGB-IP"
        set type address
        set resource "http://10.0.0.5:8080/ip-list.txt"
        set refresh-rate 60
    next
end
```

> Bu yapılandırma BG **3.1.6.4** (Kara Liste Kullanımı) ve **3.1.6.5**
> (İzin Verilmeyen Trafiğin Engellenmesi) maddelerinin somut karşılığıdır.

## HTTPS önerisi (BG 3.1.6.34, 3.1.8.4)

Konteyner kendisi sadece HTTP konuşur. Üretimde **reverse proxy** ile HTTPS
sonlandırması yap (BG **3.1.6.34** "Kablosuz İletişim Güvenliği" değil ama
genel **TS ISO/IEC 27001** prensibi — kurum içi servisler bile şifreli
iletişim kullanmalı):

- Traefik, Caddy, nginx-proxy ile otomatik Let's Encrypt
- Veya kurumsal CA ile statik sertifika

Caddy ile en kısa örnek:

```caddyfile
sgb-feed.kurum.local {
    reverse_proxy localhost:8080
}
```

## Manuel komutlar

```bash
# Tek seferlik delta (debug için)
docker exec sgb-api-bridge /entrypoint.sh sync-once delta

# Health check
docker exec sgb-api-bridge /entrypoint.sh healthcheck

# Container içinde shell
docker exec -it sgb-api-bridge sh

# Sıfırdan tam re-sync (NADİR — seed verisi çok bayatladıysa, ~10-15+ saat):
docker run --rm -v sgb-api-bridge-data:/data \
  ghcr.io/bilsectr/sgb-api-bridge:latest sync-once full

# State + feed'leri tamamen sil (sonraki açılış seed verisinden tekrar başlar)
docker run --rm -v sgb-api-bridge-data:/data alpine \
  sh -c "rm -rf /data/state /data/docs"
```

## Yapılandırma (env variables)

| Variable | Default | Açıklama |
|---|---|---|
| `SGB_BRIDGE_ROOT` | `/data` | State ve feed dosyalarının kök dizini |
| `SGB_BRIDGE_DELTA_INTERVAL_SEC` | `3600` | Loop modunda delta sync sıklığı (sn) |
| `SGB_BRIDGE_DELTA_MAX_PAGES` | `1000` | Delta'nın tek seferde gezeceği maks. sayfa (bayat state güvenlik tavanı) |
| `TZ` | `UTC` | Konteyner saat dilimi (loglar için) |

## Denetim için (BG 3.1.8.4 — Detaylı Kayıt)

Bu kurulumun ürettiği denetim kayıtları:

- **Container log'u** (`docker logs`): her sync başlangıç/bitiş, hata, kaç
  yeni indicator çekildi
- **`/data/state/seen_ids.json`**: bayat state izleme (max_id, son sync
  zamanı)
- **`/data/docs/stats.json`**: kamu erişimli özet (last_update_utc, sayılar)

Bu kayıtları kurum SIEM'inize (örn. Splunk Universal Forwarder, Filebeat,
Fluent Bit) ileterek BG **3.1.8.6** (Merkezi Kayıt Yönetimi) kapsamına alın.

## Sorun giderme

- **404 dönüyor**: Seed verisi kopyalanmamış olabilir.
  `docker exec sgb-api-bridge ls -la /data/docs` ile kontrol et. Boşsa
  imajı kendin build ettiysen `docs/` klasörünü dahil etmemişsindir —
  `sync-once full` ile bootstrap et.
- **Konteyner sürekli restart oluyor**: SGB API'sine erişim yok ya da disk
  dolu. `docker logs sgb-api-bridge --tail 200` incele.
- **`Permission denied` /data altında**: Volume'un sahibi yanlış UID.
  Container `www-data` (UID 33) ile çalışır. Host'ta
  `chown -R 33:33 /var/lib/docker/volumes/sgb-api-bridge-data/_data`
  ile düzelt.
- **İmaj çekilemiyor**: Air-gapped ortamlarda `docker save / load` ile
  transferle:

  ```bash
  docker pull ghcr.io/bilsectr/sgb-api-bridge:latest
  docker save ghcr.io/bilsectr/sgb-api-bridge:latest | gzip > sgb-api-bridge.tar.gz
  # Hedef makineye kopyala:
  gunzip -c sgb-api-bridge.tar.gz | docker load
  ```

## İmajı kendin build etmek (supply-chain güvenliği — BG 3.5.3)

BG **3.5.3 (Tedarikçi İlişkileri Güvenliği)** kapsamında dışarıdan hazır
imaj çekmek yerine kendin build etmek tercih edilebilir:

```bash
git clone https://github.com/bilsectr/sgb-api-bridge.git
cd sgb-api-bridge
docker build -f docker/Dockerfile -t kurum/sgb-api-bridge:1.0 .
docker push kurum-registry.local/sgb-api-bridge:1.0
```

İdeal olarak kurum içi private registry'ye push edip Docker Content Trust
veya cosign ile imzalayın.
