# L1/L2 站点缓存与 PostgreSQL

本分支基于 SamWAF `df095c943e049f655a77dab2d5e93a6ca43d8092`。运行时主库、日志库和统计库使用 PostgreSQL，控制台及业务状态使用独立 PostgreSQL KV/TTL 数据库。站点响应缓存独立于该 KV 后端。

## 参考实现

本实现用 Go 完成 SamWAF 请求链路内的分层缓存，不加载 Nginx 模块、不读写 Nginx 私有缓存文件。

- [native-tier 0.1.1](https://github.com/PH-OpenResty/OpenResty_Plugin/tree/ee273f33fde65738d01d782d440afb0778465533/native-tier)：固定热度窗口、冷请求 L2、L1 MISS 经 L2、先提交 L2 再晋升、保留绝对到期、公共请求准入。
- [Nginx file cache](https://github.com/nginx/nginx/blob/2e8440bcdc438f0f1cd03da778a3843ddb3c86d9/src/http/ngx_http_file_cache.c)：缓存填充锁、临时文件与原子发布、Vary 变体、容量及 inactive 回收。
- [Nginx upstream](https://github.com/nginx/nginx/blob/2e8440bcdc438f0f1cd03da778a3843ddb3c86d9/src/http/ngx_http_upstream.c)：Set-Cookie、Cache-Control、Expires、Age 和条件再验证。

## 站点缓存

读取顺序：前置防护 → Access 认证 → 站点密码访问认证 → L1/L2 查询 → 回源。网站密码访问开启时保守绕过共享响应缓存。认证不受缓存开关或仅记录模式影响。

冷对象从 L2 查询，L2 MISS 才访问源站。默认在首次访问起的 90 分钟固定窗口内达到 3 次请求后成为热对象，热对象优先查询 L1，L1 MISS 再查询 L2。热度表固定 4096 个槽，碰撞仅重置热度，不改变内容键。

新对象沿响应读取过程流式写入同目录临时文件。已知长度、完整读取且未取消的公共 200 响应才原子发布到 L2；提交成功后才允许把符合单对象上限的热对象放入 L1。L2 命中晋升沿用原始绝对到期时间，不重新获得完整 TTL。

L1 使用独立的进程内 LRU，同时约束每站点总容量和所有站点合计容量。L2 使用磁盘文件、内存索引和跨进程文件锁，写入前预留整条文件的逻辑空间，计入并发临时文件，超过总容量或条目数时按最近访问顺序回收。索引通过 generation 文件发现其他 Worker 的发布；重启可以从已提交的 L2 文件恢复。索引元数据、在途读写缓冲和 WAF 其他功能的内存开销不计入 L1 正文配额。

每个 Worker 有独立 L1 和热度表；滚动重启重叠期间需按 Worker 数量估算 L1 合计内存。L2 目录可以由同一实例的新旧 Worker 共享。缓存目录由服务账户独占，文件权限 0600、目录 0700。

### 配置

全局配置：

```yaml
web_cache:
  l1_capacity_mb: 256
```

站点 `cache_json` 的内容：

```json
{
  "is_enable_cache": 1,
  "cache_location": "tiered",
  "cache_dir": "./data/cache",
  "l1_capacity_mb": 64,
  "l2_capacity_mb": 1024,
  "max_memory_size_mb": 4,
  "max_file_size_mb": 32,
  "heat_threshold": 3,
  "heat_window_seconds": 5400,
  "inactive_seconds": 86400,
  "max_entries": 100000,
  "lock_timeout_seconds": 5,
  "min_free_mb": 64
}
```

容量单位为 MiB。两个 `capacity` 字段控制总量；`max_memory_size_mb` 和 `max_file_size_mb` 保留为 L1/L2 单对象限制。缺失或非正数大小使用上述有限默认值。旧 `memory`、`file`、`all` 值统一进入新的分层链路，不再把网站正文放到全局 CacheStore。L1 大小统计包含正文、响应头及条目估算开销；L2 配额包含文件元数据和预留的临时文件。

缓存规则仍使用后缀、目录、文件匹配，优先级数字越大越优先。`cache_time <= 0` 明确禁止读取和写入。响应的 `s-maxage/max-age/Expires/X-Accel-Expires` 可以缩短规则给定的最长有效期。原始 Age 和 Date 带来的年龄会被保留。

内容键使用长度编码后 SHA256，包含配置指纹、scheme、实际 Host、完整 URI 和 GET 身份；HEAD 共享已有 GET 对象但不单独填充正文。`param_type=1` 仅让规则匹配忽略查询参数，内容键仍区分查询串，避免把有业务意义的参数合并。配置指纹包含站点、全局相关配置、缓存规则以及响应处理规则，配置更新使用新命名空间，旧在途请求仍使用其已确定的指纹。

### HTTP 边界

- 只接受无正文的 GET/HEAD；POST、PUT、PATCH 等直接回源。开启缓存不再把上传请求完整复制到内存。
- 请求包含 Cookie、Authorization、Proxy-Authorization、API Key、Upgrade、访问认证身份头或禁用缓存指令时绕过。
- Range/If-Range 保守回源，不缓存 206；本实现没有复制 Nginx 的完整 Range 切片行为。
- 响应包含 Set-Cookie、private/no-store/no-cache、Vary:* 或流式类型时不存储。
- Vary 按实际请求头隔离变体，响应上游伪造的缓存诊断及 X-Tier-* 内部头不进入存储。
- 未知最终长度、超过单对象上限、截断、读错误、请求取消和未读完即关闭的响应不发布。
- 过期对象有 ETag/Last-Modified 时向真实源站条件再验证。源站 304 可更新期限；新增私有策略会停止续期并清除旧对象。客户端自己的 304 不能被冒认为验证了没有校验器的旧正文。
- 本版本不提供后台更新、stale-if-error 或离线过时正文复用。过期时同步回源。
- 本地静态站点、静态路径和跳转由原处理链路服务，不创建反代填充锁。
- 缓存层自身流式处理。WAF 既有的响应检测、脱敏、编码转换等功能仍可能按自身规则缓冲正文；L1 配额不是进程 RSS 上限。

旧 `.hash.timestamp.cache` 文件不读取为新格式，按原清理任务回收。新目录为 `cache_dir/v2/<site-digest>/...`，迁移产生冷缓存。磁盘回收管理每 10 秒运行；读取不延长内容有效期，只更新 inactive 使用时间。

`X-Cache` 返回 MISS/HIT/BYPASS/REVALIDATED，`X-Cache-Layer` 返回 origin/l1/l2/off。系统信息和运行诊断提供两层命中、回源、绕过、L1 字节数、L2 文件及预留字节数等聚合指标，不返回缓存键、URL、凭据或正文。

`origin_reads` 记录缓存路径的回源尝试，包括条件再验证；BYPASS 单独计数。L2 指标描述本 Worker 已加载的索引，重启读取可按对象目录恢复，容量准入和定时管理再扫描完整索引。全局 YAML 的 L1 配额在启动时应用；站点 JSON 配置通过现有站点热更新路径生效。

## PostgreSQL KV/TTL

`cache/postgres/samwaf_kv--1.0.sql` 与 `.control` 是纯 SQL 扩展，没有外部 Redis 服务和原生共享库依赖。可将文件安装到 PostgreSQL extension 目录，由应用执行 `CREATE EXTENSION samwaf_kv`。数据库托管环境不能安装服务器文件时，应用在同一事务中安装完全相同的 schema/functions。

启动安装由 PostgreSQL 事务咨询锁协调。扩展提供 SET、GET、GETEX、TOUCH、EXISTS、DELETE、KEYS、原子 ADD、INCRBY 和分批过期清理。值使用 JSONB，键按 namespace 隔离。所有读取即时检查绝对到期；每分钟清理只是回收空间，不决定可见性。

trusted 扩展安装时 PostgreSQL 会以引导超级用户执行脚本，因此扩展脚本显式给原会话安装者授予 schema、表和函数权限。部署验收已使用无超级用户权限的应用角色验证首次安装及读写，不能只用 postgres 超级用户测试这一条路径。

凭证及封禁状态使用普通持久表，数据库重启后仍能保留未到期状态，不按网页 LRU 淘汰。GETEX 使用一条原子 UPDATE 返回值并续期。ADD 是条件 UPSERT，控制台防重放中间件使用它，避免跨请求/Worker 的先查后写竞争。INCRBY 支持固定窗口及显式续期。

多个独立实例共用数据库服务器时应设置不同 namespace；同一实例的滚动重启使用同一个 namespace。

控制台后端错误与未命中分别返回 ErrCacheBackend/ErrCacheMiss，诊断只记录操作和错误分类，不输出 SQL 参数或 DSN。PostgreSQL SET/SET TTL 从当前时刻重新计时；旧内存实现的 SetWithTTl 创建时间兼容语义不用于新运行后端。

## PostgreSQL 运行与部署

完整示例为 `deploy/config.postgres.yml`。正常 Worker 要求 `database.driver=postgres` 且 `cache.type=postgres`，错误配置不降级为 SQLite 或空的内存缓存。保留 SQLite/MySQL 代码用于离线迁移和兼容测试。

默认数据库为 `samwaf_core`、`samwaf_log`、`samwaf_stats` 和 `samwaf_cache`。服务角色有 CREATEDB 权限时自动创建；没有该权限时由管理员预建并授予应用所需权限。配置 host/user/password/sslmode/timezone 后即可复用现有 PostgreSQL 适配。

支持 `SAMWAF_PG_HOST/PORT/USER/PASSWORD/SSLMODE/TIMEZONE` 及 `SAMWAF_PG_CORE_DB/LOG_DB/STATS_DB/CACHE_DB` 环境变量。环境变量密码不写回配置文件。

Docker Compose 2.20+：先设置 `SAMWAF_PG_PASSWORD`，在仓库根目录执行：

```sh
docker compose up -d --build
```

根 Compose 引入 `deploy/compose.postgres.yml`，同时从当前源码构建应用与带扩展文件的 PostgreSQL 17 镜像。数据和 L2 保留在挂载卷内；PostgreSQL 就绪后启动应用。构建阶段按 `public/web_frontend.conf` 拉取官方控制台前端产物。上游 `samwaf/samwaf` 镜像不包含本分支。

已有 PostgreSQL 服务器可直接运行编译后的应用，环境变量覆盖示例中的连接目标。没有运行过 Docker 镜像构建的环境应先执行自身构建验收，不能把源码编译验证视为 Docker 构建验证。

## 旧 SQLite 数据迁移与回退

既有 SQLite 安装不自动切换数据库。缺少 driver 配置但检测到 `data/local.db` 时，保留 legacy 标识并拒绝正常启动，避免把新建空 PostgreSQL 误当作数据丢失后的旧实例。

1. 停止旧实例，在一致状态下备份 `conf`、整个 `data`（包括 `.keys`、WAL/SHM 如存在）和 `ssl`。自管外部密钥文件一并备份。校验备份哈希并确认可以恢复后再开始迁移。
2. 准备独立的目标 PostgreSQL 数据库，先执行 `SamWafLinux64 migratedb --from=sqlite --to=postgres --dry-run`。dry-run 不复制业务行，但连接检测可能创建目标空库，应使用专门的目标环境。
3. 正式执行相同命令去掉 `--dry-run`。工具支持断点、分表行数验证和迁移报告；目标有记录时默认跳过，`--force` 会覆盖，使用前另行备份目标。
4. 核对迁移报告及关键业务记录，再选择切换配置。切换时同时设置 PostgreSQL KV 后端，并创建、读回校验原配置备份和 SHA256 文件，随后原子替换新配置。
5. 启动新实例，核对主/日志/统计库、控制台登录与站点代理。旧 SQLite 文件和密钥继续保留，不删除。进程内旧登录态不迁移，切换后重新登录。

回退时停止新实例，恢复已校验的旧配置及旧二进制，使用保留的 SQLite/密钥快照。切换后新增的 PostgreSQL 数据另行保存；工具不自动把新增数据反向合并到 SQLite。

## 验证入口

- `wafenginecore/wafwebcache/tiered_test.go`、`revalidate_test.go`：冷热晋升、绝对 TTL、重启、Vary、查询串、凭据隔离、并发锁、容量、取消/截断、HEAD、304、Age。
- `wafenginecore/tiered_cache_integration_test.go`：真实 Go 反向代理的 L1/L2 链路、密码门顺序、开启缓存时上传完整转发。
- `cache/postgres_cache_test.go`：真实 PostgreSQL KV 读写、到期、原子续期/新增/计数、命名空间、清理、错误分类。
- `wafdb/migrate_postgres_config_test.go`：迁移同步切换 KV 后端、保留原配置并校验备份。
- `.github/workflows/tiered-cache-postgres.yml`：PostgreSQL 17/18、race、引擎验证、迁移配置备份及构建；普通数据库 owner 分别验证嵌入 SQL 与 trusted 扩展安装路径。原运行时冒烟工作流已增加 PostgreSQL。

实际执行结果、全仓测试的未通过项及性能测试边界见[验证记录](TIERED-CACHE-POSTGRES-VALIDATION.zh-CN.md)和[性能基准](PERFORMANCE-TIERED-POSTGRES.zh-CN.md)。GitHub Actions 的运行结果须以对应提交的实际记录为准。
