FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SITE_DATA_DIR=/data
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && groupadd -g 10001 website && useradd -u 10001 -g website -M website && mkdir -p /data /app/staticfiles && chown website:website /data /app/staticfiles
COPY --chown=website:website . /app
USER website
EXPOSE 8000
CMD ["gunicorn", "showcase.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "--timeout", "90", "--access-logfile", "-", "--error-logfile", "-"]
