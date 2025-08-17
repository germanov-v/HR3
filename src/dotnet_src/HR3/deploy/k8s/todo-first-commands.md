```
kubectl create namespace jr2

kubectl apply -f certificates.yaml
kubectl apply -f ingress.yaml

```



---

# Команды (выполнить по порядку)

```bash
# 0) Неймспейс приложения
kubectl create namespace jr2

# 1) Установка cert-manager (если ещё не установлен)
kubectl create namespace cert-manager
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --set crds.enabled=true

# 2) ClusterIssuer’ы (staging + production)
kubectl apply -f clusterissuer-staging.yaml
kubectl apply -f clusterissuer-prod.yaml

# 3) Приложения: identity и api (Deployment + Service)
kubectl apply -n jr2 -f identity.yaml
kubectl apply -n jr2 -f api.yaml

# 4) Сертификаты для доменов (cert-manager выпустит их)
kubectl apply -n jr2 -f certificates.yaml

# 5) Ingress для доменов
kubectl apply -n jr2 -f ingress.yaml
```

> Важно: до применения убедись, что DNS A/AAAA записей `identity.v2.jobradar.ru` и `api.v2.jobradar.ru` указывают на публичный IP ingress’а/ноды и порты 80/443 открыты.

---

# Манифесты

## `clusterissuer-staging.yaml`

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    # Тестовый ACME — без лимитов, но невалидные для браузеров
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    email: you@example.com
    privateKeySecretRef:
      name: letsencrypt-staging-account-key
    solvers:
      - http01:
          ingress:
            class: traefik
```

## `clusterissuer-prod.yaml`

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt
spec:
  acme:
    # Боевой ACME
    server: https://acme-v02.api.letsencrypt.org/directory
    email: you@example.com
    privateKeySecretRef:
      name: letsencrypt-account-key
    solvers:
      - http01:
          ingress:
            class: traefik
```

## `identity.yaml`

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: identity
spec:
  replicas: 2
  selector:
    matchLabels:
      app: identity
  template:
    metadata:
      labels:
        app: identity
    spec:
      # imagePullSecrets:
      #   - name: nexus-pull-secret
      containers:
        - name: identity
          image: <PUT-YOUR-IMAGE-URL-HERE> # например  your-nexus/identity:tag
          ports:
            - containerPort: 8080
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 5
          livenessProbe:
            httpGet:
              path: /live
              port: 8080
            initialDelaySeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: identity
spec:
  type: ClusterIP
  selector:
    app: identity
  ports:
    - name: http
      port: 80
      targetPort: 8080
```

## `api.yaml`

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      # imagePullSecrets:
      #   - name: nexus-pull-secret
      containers:
        - name: api
          image: <PUT-YOUR-IMAGE-URL-HERE> # например your-nexus/api:tag
          ports:
            - containerPort: 8080
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 5
          livenessProbe:
            httpGet:
              path: /live
              port: 8080
            initialDelaySeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: ClusterIP
  selector:
    app: api
  ports:
    - name: http
      port: 80
      targetPort: 8080
```

## `certificates.yaml`

> Явно создаём два `Certificate`. Ingress лишь ссылается на их `secretName`. Выпуском займётся cert-manager через `ClusterIssuer: letsencrypt`.

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: identity-v2-jobradar-ru
spec:
  secretName: identity-v2-jobradar-ru-tls
  issuerRef:
    name: letsencrypt           # на время теста можно поставить letsencrypt-staging
    kind: ClusterIssuer
  dnsNames:
    - identity.v2.jobradar.ru
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: api-v2-jobradar-ru
spec:
  secretName: api-v2-jobradar-ru-tls
  issuerRef:
    name: letsencrypt           # или letsencrypt-staging для проверки
    kind: ClusterIssuer
  dnsNames:
    - api.v2.jobradar.ru
```

## `ingress.yaml`

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: jr2-ingress
  annotations:
    # (Опционально) HSTS и редиректы можно включить в Traefik/middleware отдельно
    kubernetes.io/ingress.class: traefik
spec:
  ingressClassName: traefik
  tls:
    - hosts:
        - identity.v2.jobradar.ru
      secretName: identity-v2-jobradar-ru-tls
    - hosts:
        - api.v2.jobradar.ru
      secretName: api-v2-jobradar-ru-tls
  rules:
    - host: identity.v2.jobradar.ru
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: identity
                port:
                  number: 80
    - host: api.v2.jobradar.ru
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api
                port:
                  number: 80
```

---

## Проверки/заметки

* Если сначала хочешь прогнать выпуск на **staging**, в `certificates.yaml` временно укажи `issuerRef.name: letsencrypt-staging`. После успешного выпуска — переключи на `letsencrypt` (prod), `kubectl apply -f certificates.yaml`.
* Если у тебя в Traefik глобальный принудительный редирект 80→443 — cert-manager всё равно создаёт временный challenge-ingress для `/.well-known/acme-challenge/*`. Обычно это работает «из коробки». Если вдруг нет — временно отключи редирект или добавь исключение.
* Для приватных регистри добавь `imagePullSecrets` и создай секрет:
  `kubectl -n jr2 create secret docker-registry nexus-pull-secret --docker-server=... --docker-username=... --docker-password=... --docker-email=...`

Хочешь — соберу то же самое как Helm-чарт с values, где ты просто подставишь домены и имена образов.
