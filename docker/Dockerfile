# syntax=docker/dockerfile:1.6
# sgb-api-bridge: tek imaj, mode dispatcher ile hem all-in-one (Docker) hem split (K8s) destekler.
#
# Default davranis (docker run sgb-api-bridge):
#   - nginx /data/docs ve /data/feeds'i 80 portundan serve eder
#   - python sync.py --mode loop arka planda delta'yi saatte bir tetikler
#
# Alternatif modlar (K8s CronJob ve manuel kullanim icin):
#   docker run --rm sgb-api-bridge sync-once delta
#   docker run --rm sgb-api-bridge sync-once full
#   docker run --rm sgb-api-bridge healthcheck
#   docker run -d sgb-api-bridge serve              # sadece HTTP, sync yok
#   docker run -d sgb-api-bridge loop               # sadece sync, HTTP yok
#
# HTTP endpoint'ler (default serve modunda):
#   /                                                  HTML ana sayfa
#   /domain-list.txt /ip-list.txt /url-list.txt ...    geriye uyumlu duz feed'ler
#   /feeds/sgb-master.csv                              master kanonik tablo
#   /feeds/sgb-master.jsonl                            JSON Lines
#   /feeds/stix/sgb-{type}.stix2.json                  STIX 2.1 bundle (per-type)
#   /feeds/by-connectiontype/*.txt                     CT bazli slice'lar
#   /feeds/index.json                                  manifest (sha256 + size)
#   /taxii2/ /api/                                     TAXII 2.1 servisi
#   /stats.json                                        SQLite + count'lar dahil saglik

FROM python:3.11-slim AS build
RUN pip install --no-cache-dir --prefix=/install requests

FROM python:3.11-slim

LABEL org.opencontainers.image.title="SGB API Bridge" \
      org.opencontainers.image.description="SGB (eski USOM) tehdit beslemesini firewall feed'leri ve TAXII 2.1 servisine cevirir" \
      org.opencontainers.image.source="https://github.com/bilsectr/sgb-api-bridge" \
      org.opencontainers.image.licenses="MIT"

# nginx + curl (healthcheck) + tar (extract/push utility)
RUN apt-get update \
 && apt-get install -y --no-install-recommends nginx curl tar \
 && rm -rf /var/lib/apt/lists/* /var/log/nginx/* \
 && rm /etc/nginx/sites-enabled/default

# Python paketleri
COPY --from=build /install /usr/local

# Uygulama - tum scripts/ dizini (sync.py sgb_db'yi import ediyor)
COPY scripts/ /app/scripts/
# nginx + entrypoint
COPY docker/nginx.conf /etc/nginx/conf.d/sgb-api-bridge.conf
COPY docker/entrypoint.sh /entrypoint.sh

# Seed verisi: repo'daki gecmis feed'ler + state + (varsa) SQLite DB imaja gomulur.
# Fresh container (bos volume) ilk acilista bunu /data'ya kopyalar, full sync gerekmez.
COPY docs /app/seed/docs
COPY state /app/seed/state

RUN chmod +x /entrypoint.sh \
 && mkdir -p /data/docs /data/state /data/feeds \
 && chown -R www-data:www-data /data /app \
 && ln -sf /dev/stdout /var/log/nginx/access.log \
 && ln -sf /dev/stderr /var/log/nginx/error.log \
 && touch /var/run/nginx.pid \
 && chown www-data:www-data /var/run/nginx.pid \
 && chown -R www-data:www-data /var/lib/nginx /var/log/nginx

USER www-data
WORKDIR /data

EXPOSE 80
VOLUME ["/data"]

# Builder'lar SGB_BRIDGE_ROOT'u kullanir (default /data).
# PYTHONPATH=/app/scripts: sync.py'nin "import sgb_db" yapabilmesi icin.
ENV SGB_BRIDGE_ROOT=/data \
    SGB_BRIDGE_DELTA_INTERVAL_SEC=3600 \
    SGB_BRIDGE_RECONCILE_EVERY=24 \
    PYTHONPATH=/app/scripts \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=60s --timeout=5s --start-period=30s \
  CMD curl -fsS http://127.0.0.1/stats.json > /dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["all-in-one"]
