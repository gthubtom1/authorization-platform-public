#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$EUID" != 0 || "$(pwd -P)" != /opt/software-showcase ]]; then
  echo 'Run as root from the confirmed /opt/software-showcase installation.' >&2; exit 1
fi
if [[ ! -f .env ]]; then
  echo '先复制.env.example为.env，并填写本站域名和独立密钥。' >&2
  exit 1
fi
if grep -Eq 'replace-with|showcase\.example\.com' .env; then
  echo '.env仍有占位配置，拒绝安装。' >&2
  exit 1
fi
docker compose config --quiet
domain="$(python3 deploy/preflight.py)"
docker compose build app
# Quiesce confirmed writes first. A stopped old container can still own data.
docker compose stop app
if docker compose ps --status running --services | grep -qx app; then
  echo 'App has not stopped; refusing backup/migration.' >&2; exit 1
fi
docker compose run --rm --no-deps app python deploy/pre-update-backup.py
docker compose run --rm app python manage.py migrate --noinput
docker compose run --rm app python manage.py collectstatic --noinput
docker compose run --rm app python manage.py check --deploy --fail-level WARNING
docker compose up -d
docker compose exec -T app python manage.py check --deploy --fail-level WARNING
sed "s/__DOMAIN__/${domain}/g" deploy/host-nginx.conf.example > /etc/nginx/sites-available/software-showcase.conf
ln -sfn /etc/nginx/sites-available/software-showcase.conf /etc/nginx/sites-enabled/software-showcase.conf
nginx -t
systemctl reload nginx
echo 'INSTALL_STEPS_OK。还须按部署手册核对HTTPS、登录、图像和外链后，才算上线验收完成。'
