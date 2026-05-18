#!/bin/sh
set -e

# Komut dispatcher. K8s'de "command/args" ile, Docker'da direkt argument ile cagrilir.
#
# Modlar:
#   all-in-one      : nginx + python loop (default)
#   loop            : sadece python loop
#   serve           : sadece nginx
#   sync-once       : tek seferlik sync; ikinci arg full|delta|catalog-sync
#   healthcheck     : stats.json fresh mi
#   sh / bash       : interaktif shell (debug)

MODE="${1:-all-in-one}"
shift 2>/dev/null || true

DATA_ROOT="${SGB_BRIDGE_ROOT:-/data}"
TAXII_ENABLED="${SGB_BRIDGE_TAXII_ENABLED:-1}"
# Loop modu sync alt-modu: per-page=1000 ile full sync ~10 dk; silinen kayitlari
# yakaladigi icin TAXII/STIX cikti'sini stabil tutmak isteyenler icin default.
# Eski davranis icin: SGB_BRIDGE_SYNC_MODE=delta
SYNC_MODE="${SGB_BRIDGE_SYNC_MODE:-full}"

# Veri dizinleri yoksa olustur
mkdir -p "$DATA_ROOT/docs" "$DATA_ROOT/state" "$DATA_ROOT/feeds"

# Seed: volume/PVC bos ise imaja gomulu gecmis veriyi kopyala.
# -n (no-clobber): mevcut volume verisinin uzerine asla yazmaz.
if [ ! -f "$DATA_ROOT/state/seen_ids.json" ] && [ -d /app/seed ]; then
  echo "[entrypoint] $DATA_ROOT bos - imajdaki seed verisi kopyalaniyor"
  cp -rn /app/seed/docs/. "$DATA_ROOT/docs/" 2>/dev/null || true
  cp -rn /app/seed/state/. "$DATA_ROOT/state/" 2>/dev/null || true
  echo "[entrypoint] seed tamamlandi"
fi

# TAXII tree (docs/taxii/) rebuild — nginx /taxii2/ + /api/ rotalari bunu serve eder.
taxii_rebuild() {
  if [ "$TAXII_ENABLED" != "1" ]; then
    return 0
  fi
  if [ ! -f "$DATA_ROOT/state/sgb.db" ]; then
    echo "[entrypoint] taxii skip: $DATA_ROOT/state/sgb.db yok"
    return 0
  fi
  python /app/scripts/build_taxii.py --compact || echo "[entrypoint] build_taxii hata - devam"
}

case "$MODE" in
  all-in-one)
    echo "[entrypoint] all-in-one: nginx + python loop"
    nginx
    taxii_rebuild
    if [ "$TAXII_ENABLED" = "1" ]; then
      while :; do
        python /app/scripts/sync.py --mode "$SYNC_MODE" || echo "[entrypoint] sync hata"
        taxii_rebuild
        sleep "${SGB_BRIDGE_DELTA_INTERVAL_SEC:-3600}"
      done
    else
      exec python /app/scripts/sync.py --mode loop
    fi
    ;;
  loop)
    echo "[entrypoint] loop: sadece sync"
    taxii_rebuild
    if [ "$TAXII_ENABLED" = "1" ]; then
      while :; do
        python /app/scripts/sync.py --mode "$SYNC_MODE" || echo "[entrypoint] sync hata"
        taxii_rebuild
        sleep "${SGB_BRIDGE_DELTA_INTERVAL_SEC:-3600}"
      done
    else
      exec python /app/scripts/sync.py --mode loop
    fi
    ;;
  serve)
    echo "[entrypoint] serve: sadece nginx"
    exec nginx -g 'daemon off;'
    ;;
  sync-once)
    SUBMODE="${1:-delta}"
    echo "[entrypoint] sync-once: $SUBMODE"
    exec python /app/scripts/sync.py --mode "$SUBMODE"
    ;;
  healthcheck)
    exec python /app/scripts/sync.py --mode healthcheck
    ;;
  sh|bash)
    exec /bin/sh
    ;;
  *)
    exec "$MODE" "$@"
    ;;
esac
