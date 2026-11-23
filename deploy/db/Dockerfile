# PostgreSQL 17 + pgBackRest（WAL 归档与备份）
# 构建：docker build -t authorization-platform-db:pg17-pgbackrest .
FROM postgres:17-alpine

RUN apk --no-cache add pgbackrest tzdata

# pgbackrest 日志/状态目录（备份仓库与配置由 compose 挂载注入）
RUN mkdir -p /var/log/pgbackrest /var/spool/pgbackrest \
    && chown -R postgres:postgres /var/log/pgbackrest /var/spool/pgbackrest

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["pg_isready", "-U", "postgres"]