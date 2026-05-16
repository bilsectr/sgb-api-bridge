# Kubernetes Kurulumu

**CronJob** (saatlik sync) + **Deployment** (nginx serve) + **PVC** (state ve
feed'ler) ile native Kubernetes deployment.

## Bu kurulum BG Rehberi'nin neyini karşılar?

| Madde | Madde adı | Bu kurulum nasıl katkı sağlar? |
|-------|-----------|--------------------------------|
| **3.1.10.4** ⭐ | Siber Tehdit Bildirimlerinin Yönetilmesi | K8s CronJob saatlik SGB sync = "bildirimlerin sürekli işlenmesi". |
| **3.1.5.1** | Zararlı Yazılımdan Korunma + Merkezi Yönetim | Cluster ölçeğinde saatlik IoC güncellemesi. |
| **3.1.6.4 / 3.1.6.5** | Kara Liste / İzin Verilmeyen Trafik | Service üzerinden cluster içi kara liste dağıtımı. |
| **3.1.9** | Sanallaştırma Güvenliği | K8s = container orkestrasyonu. Manifest'lerimizde RWO PVC + non-root container = hardening alt yapısı. |
| **3.1.13** | Felaket Kurtarma | StatefulSet/Deployment + PVC backup ile DR. |
| **4.3** | Bulut Bilişim Güvenliği | Eğer EKS/AKS/GKE'de çalışıyorsa bu madde uygulanır. |

> Tüm BG madde eşleştirmeleri için: [bg-rehber-mapping.md](bg-rehber-mapping.md)

## Önkoşullar

- Kubernetes 1.24+
- Default StorageClass (RWO yeterli; `local-path`, `gp2`, `csi-...` vb.)
- Cluster'ın ghcr.io'ya erişimi veya kendi private registry'ne mirror
- Cluster içinden SGB API'sine (`https://siberguvenlik.gov.tr`) çıkış

## Manifestler

Hepsi `k8s/` klasöründe, kustomize ile organize:

```
k8s/
├── kustomization.yaml
├── namespace.yaml
├── pvc.yaml                   # /data için 1Gi PVC (RWO)
├── cronjob-delta.yaml         # saatte bir (:23)  -- TEK zamanlı iş
├── deployment.yaml            # nginx serve (replicas=1)
├── service.yaml               # ClusterIP :80
├── ingress.yaml.example       # opsiyonel
└── job-full.yaml              # tek seferlik manuel bootstrap (kustomize'a DAHİL DEĞİL)
```

## Kurulum

```bash
git clone https://github.com/bilsectr/sgb-api-bridge.git
cd sgb-api-bridge
kubectl apply -k k8s/
```

Veya bash ile direkt:

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/cronjob-delta.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

## Bootstrap — genelde gerekmez

İmaj, geçmiş feed verisini (`docs/*-list.txt` + `state/seen_ids.json`)
**gömülü taşır**. İlk container açıldığında bu seed verisi boş PVC'ye
otomatik kopyalanır (entrypoint hallediyor). Yani:

- Delta CronJob ilk çalıştığında seed verisindeki `max_id`'den devam eder.
- Serve Deployment'ı anında dolu feed'leri sunar.
- **Full sync'e gerek yoktur.**

### Sıfırdan tam re-sync (nadir)

Yalnızca tamamen yeni bir veri seti çekmek istersen `job-full.yaml`'ı elle
uygula (kustomize'a dahil **değil**):

```bash
kubectl apply -f k8s/job-full.yaml
kubectl -n sgb-api-bridge logs -f job/sgb-sync-full
# Bitince:
kubectl -n sgb-api-bridge delete job sgb-sync-full
```

Full sync ~10-15+ saat sürer. `activeDeadlineSeconds: 54000` (15h) ile
sınırlı; resume destekli olduğu için pod öldürülse de bir sonraki deneme
kaldığı sayfadan devam eder.

## Feed'lere erişim

### Cluster içinden

Cluster içindeki diğer pod'lardan:
`http://sgb-api-bridge.sgb-api-bridge.svc.cluster.local/domain-list.txt`

### Cluster dışından — Port-forward (test)

```bash
kubectl -n sgb-api-bridge port-forward svc/sgb-api-bridge 8080:80
curl http://localhost:8080/domain-list.txt
```

### Cluster dışından — Ingress

`k8s/ingress.yaml.example` dosyasını kopyala:

```bash
cp k8s/ingress.yaml.example k8s/ingress.yaml
# host'u kendi domain'inle değiştir
kubectl apply -f k8s/ingress.yaml
```

Veya `kustomization.yaml` içinde Ingress satırını yorumdan çıkar.

### Cluster dışından — NodePort

`service.yaml`'da `type: ClusterIP` → `type: NodePort` yapıp
`nodePort: 30880` ekle. Sonra `http://<node-ip>:30880/domain-list.txt`.

## Yapılandırma

### Schedule değiştirme

`cronjob-delta.yaml` içindeki `schedule:` alanını değiştir (tek zamanlı iş
budur).

### İmaj tag'i sabitleme (BG 3.5.3 — Tedarikçi İlişkileri)

`kustomization.yaml`'da:

```yaml
images:
  - name: ghcr.io/bilsectr/sgb-api-bridge
    newTag: v1.0.0
```

Production'da `latest` yerine sabit tag öneririz. BG **3.5.3** kapsamında
tedarikçi (bu projede biz) versiyon yönetimi.

### Private registry mirror (air-gapped)

İmajı kendi registry'nize taşıyın:

```bash
docker pull ghcr.io/bilsectr/sgb-api-bridge:latest
docker tag ghcr.io/bilsectr/sgb-api-bridge:latest registry.kurum.local/sgb-api-bridge:1.0
docker push registry.kurum.local/sgb-api-bridge:1.0
```

Kustomization:

```yaml
images:
  - name: ghcr.io/bilsectr/sgb-api-bridge
    newName: registry.kurum.local/sgb-api-bridge
    newTag: "1.0"
```

### Proxy

Cluster proxy gerektiriyorsa CronJob'lardaki `env:` listesine ekle:

```yaml
- name: HTTPS_PROXY
  value: "http://proxy.kurum.local:8080"
- name: HTTP_PROXY
  value: "http://proxy.kurum.local:8080"
- name: NO_PROXY
  value: "localhost,127.0.0.1,.svc,.cluster.local"
```

## İzleme (BG 3.1.8.x — İz ve Denetim Kayıtları)

```bash
# CronJob durumu
kubectl -n sgb-api-bridge get cronjobs

# Son Job'lar
kubectl -n sgb-api-bridge get jobs --sort-by=.status.startTime

# Bir job'un log'u
kubectl -n sgb-api-bridge logs job/sgb-sync-delta-<hash>

# Serve pod'unun durumu
kubectl -n sgb-api-bridge get pods -l app.kubernetes.io/component=serve

# stats.json
kubectl -n sgb-api-bridge exec deploy/sgb-serve -- cat /data/docs/stats.json
```

**Üretimde:** Fluent Bit / Promtail / Vector ile pod log'larını merkezi
SIEM'inize yönlendirin (BG **3.1.8.6** Merkezi Kayıt Yönetimi). Bu
sayede "sync ne zaman koştu, başarılı mıydı, kaç IoC çekti" denetim
kayıtları her zaman merkezde olur.

## Önerilen güvenlik sıkılaştırmaları (BG 5.1, 3.1.9)

`deployment.yaml`'a şu pod-level securityContext'i ekleyin:

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 33      # www-data
        fsGroup: 33
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: nginx
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
```

Bu ayarlar BG **5.1.1** (Genel Sıkılaştırma) prensiplerinin K8s ortamına
uyarlamasıdır.

## Sorun giderme

- **PVC `Pending`**: cluster'ın default StorageClass'ı yok ya da PV
  provisioner çalışmıyor. `kubectl get storageclass` ile kontrol et,
  `pvc.yaml`'a `storageClassName:` ekle.
- **CronJob hiç çalışmıyor**: cluster saat dilimi UTC mi yoksa local mi?
  `kubectl describe cronjob/sgb-sync-delta` ile `Last Schedule Time` bak.
  v1.27+ ise `spec.timeZone` set edilebilir.
- **Pod `CrashLoopBackOff`**: `kubectl logs <pod>` ile incele. Tipik sebep:
  SGB API'ye erişim yok veya PVC'de yer kalmadı.
- **404 dönüyor**: seed verisi PVC'ye kopyalanmamış olabilir.
  `kubectl exec deploy/sgb-serve -- ls -la /data/docs` ile kontrol et.
  Boşsa: PVC mount'u veya entrypoint seed adımı çalışmamış — pod loglarına
  bak (`[entrypoint] seed tamamlandi` satırı görünmeli).
- **Deployment `0/1 ready` Recreate'te takıldı**: PVC RWO ise CronJob pod'u
  ile Deployment pod'u aynı node'da olmalı. Multi-node cluster'da node
  affinity ekle veya RWX PVC kullan.

## Helm chart?

Şimdilik plain YAML. İhtiyaç olursa Helm chart eklenebilir; mevcut
manifestler kustomize ile yeterince esnek.
