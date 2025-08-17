Отлично. Ниже — минимальный, но полный чек-лист, как поставить **Traefik “нативно” (вне Kubernetes)** на Linux-хосте, поднять **HTTPS с автообновлением Let’s Encrypt** и сделать **защищённый Dashboard (UI)**.

---

# 1) Подготовка

```bash
# 1) Создать пользователя и директории
sudo useradd --system --no-create-home --shell /usr/sbin/nologin traefik || true
sudo mkdir -p /etc/traefik/dynamic
sudo mkdir -p /var/lib/traefik
sudo touch /var/lib/traefik/acme.json
sudo chmod 600 /var/lib/traefik/acme.json
sudo chown -R traefik:traefik /etc/traefik /var/lib/traefik

# 2) Ставим traefik-бинарь (замените URL на актуальный релиз под вашу ОС/арх)
# Примерно так:
# curl -L https://github.com/traefik/traefik/releases/download/vX.Y.Z/traefik_vX.Y.Z_linux_amd64.tar.gz | sudo tar -xz -C /usr/local/bin traefik
# sudo chmod +x /usr/local/bin/traefik

# 3) Утилита для basic-auth (любой способ)
sudo apt-get install -y apache2-utils  # Debian/Ubuntu
```

Сгенерируйте хэш для BasicAuth (логин/пароль — примерные):

```bash
htpasswd -nbB admin 'StrongP@ssw0rd'
# вывод вида: admin:$2y$05$....  <- скопируйте целиком после "admin:"
```

---

# 2) Статическая конфигурация `/etc/traefik/traefik.yml`

```yaml
# /etc/traefik/traefik.yml
entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

# Включаем Dashboard, но без открытого “insecure”
api:
  dashboard: true
  insecure: false

# Автовыпуск/обновление сертификатов Let's Encrypt (HTTP-01)
certificatesResolvers:
  letsencrypt:
    acme:
      email: admin@example.com          # <- ваш email
      storage: /var/lib/traefik/acme.json
      httpChallenge:
        entryPoint: web

providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true

log:
  level: INFO

accessLog: {}
```

---

# 3) Динамическая конфигурация (маршруты, middleware)

## `/etc/traefik/dynamic/middlewares.yml`

```yaml
http:
  middlewares:
    dashboard-auth:
      basicAuth:
        users:
          - "admin:$2y$05$REPLACE_WITH_YOUR_HASH_FROM_HTPASSWD"
    https-redirect:
      redirectScheme:
        scheme: https
        permanent: true
    security-headers:
      headers:
        stsSeconds: 31536000
        stsIncludeSubdomains: true
        stsPreload: true
        frameDeny: true
        contentTypeNosniff: true
        browserXssFilter: true
```

## `/etc/traefik/dynamic/dashboard.yml`

Замените `traefik.example.com` на ваш домен (должен указывать на IP сервера).

```yaml
http:
  routers:
    # HTTP -> HTTPS редирект
    redirect-to-https:
      entryPoints:
        - web
      rule: "Host(`traefik.example.com`)"
      middlewares:
        - https-redirect
      service: noop@internal

    # Защищённый Dashboard по HTTPS
    traefik-dashboard:
      entryPoints:
        - websecure
      rule: "Host(`traefik.example.com`)"
      tls:
        certResolver: letsencrypt
      middlewares:
        - dashboard-auth
        - security-headers
      service: api@internal
```

> Итог: UI доступен по **[https://traefik.example.com](https://traefik.example.com)** с BasicAuth. Сертификат выпустится автоматически (HTTP-01 через 80 порт).

---

# 4) systemd-юнит

```ini
# /etc/systemd/system/traefik.service
[Unit]
Description=Traefik Reverse Proxy
After=network-online.target
Wants=network-online.target

[Service]
User=traefik
Group=traefik
ExecStart=/usr/local/bin/traefik --configFile=/etc/traefik/traefik.yml
Restart=always
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

Запуск:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now traefik
sudo journalctl -u traefik -f
```

---

# 5) Что ещё важно

* **DNS**: укажите A-запись `traefik.example.com` на ваш сервер.
* **Фаервол**: откройте порты **80** и **443**.
* **Конфликты портов**: убедитесь, что Apache/Nginx не слушают 80/443 (или отключите их).
* **ACME хранилище**: `acme.json` должен быть с правами `600`, владельцем `traefik`.
* **Если 80 порт недоступен** (CDN/прокси/закрыт) — переключайтесь на **DNS-01** challenge (понадобится доступ к DNS API провайдера).
* **Продакшен-безопасность UI**: держите UI на отдельном домене, под BasicAuth, можно ограничить IP через ещё одно middleware.

---

# 6) Как проксировать ваши приложения

Пример файла `/etc/traefik/dynamic/app.yml` для бэкенда на другом порту:

```yaml
http:
  services:
    myapi:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:5000"

  routers:
    myapi-https:
      entryPoints: [ "websecure" ]
      rule: "Host(`api.example.com`)"
      tls:
        certResolver: letsencrypt
      service: myapi

    myapi-redirect:
      entryPoints: [ "web" ]
      rule: "Host(`api.example.com`)"
      middlewares: [ "https-redirect" ]
      service: noop@internal
```

---

Если хочешь — подгоню конфиги под твои домены (например, `identity.v2.jobradar.ru` и `api.v2.jobradar.ru`) и добавлю DNS-01 пример, если у тебя 80 порт занят или ты за Cloudflare.
