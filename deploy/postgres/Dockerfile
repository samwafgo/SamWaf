# 扩展无额外编译步骤；放入 PostgreSQL 的 extension 目录后由应用在独立 KV 库注册。
FROM postgres:17-alpine
COPY cache/postgres/samwaf_kv.control cache/postgres/samwaf_kv--1.0.sql /usr/local/share/postgresql/extension/
