curl -fsSLo /tmp/traefik.tgz https://github.com/traefik/traefik/releases/download/v2.11.5/traefik_v2.11.5_linux_amd64.tar.gz
tar -xzf /tmp/traefik.tgz -C /tmp traefik
sudo mv /tmp/traefik /usr/local/bin/traefik && sudo chmod +x /usr/local/bin/traefik


# Создаём системного пользователя (если его нет)
sudo id traefik >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin traefik

# Директории для конфигов и ACME-хранилища
sudo mkdir -p /etc/traefik/dynamic && \
sudo mkdir -p /var/lib/traefik && \
sudo touch /var/lib/traefik/acme.json && \
sudo chmod 600 /var/lib/traefik/acme.json && \
sudo chown -R traefik:traefik /etc/traefik /var/lib/traefik