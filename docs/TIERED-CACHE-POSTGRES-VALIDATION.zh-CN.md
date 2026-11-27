# 分层缓存与 PostgreSQL 验证记录

本页记录缓存阶段 `c8d96c7`。后续 eBPF 与共享安全状态改造的最终提交验证、平台限制和部署结果见 [eBPF 验证记录](EBPF-IP-BAN-VALIDATION.zh-CN.md)，不能把本页历史结果视作后续提交的全仓通过证明。

验证日期为 2026-11-20 至 2026-11-21，日期按 America/Los_Angeles 记录。实现基于官方 `df095c943e049f655a77dab2d5e93a6ca43d8092`，包含本 PR 的分层缓存、PostgreSQL KV/TTL、配置迁移和 trusted 扩展授权修复。

本记录不包含服务器地址、凭据、管理入口、数据库备份或业务数据。

## 组件与集成验证

已执行的环境包括 Windows amd64 / Go 1.27.3、WSL Alpine Linux 3.22.2 / Go 1.25.9 / PostgreSQL 17.11，以及 Debian 13.8 ARM64 / Go 1.25.9 / PostgreSQL 17.12。Linux 构建启用 CGO；SQLite 相关依赖仍用于旧数据读取和离线迁移。

- HTTP 缓存：冷热晋升、绝对 TTL、重启恢复、Vary/查询串/Host/配置隔离、私有请求与响应绕过、HEAD/304、Age、单对象和总量预算、并发填充、取消/截断及废弃预留回收。
- PostgreSQL：字符串、整数、二进制和结构体往返，过期可见性、GETEX/TOUCH、原子 ADD/INCRBY、namespace 和字面前缀隔离、清理、错误分类及错误脱敏。
- 实际反向代理：origin → L2 → L1、密码门先于缓存、POST 上传完整转发、源站 304 再验证后继续返回完整表示。
- 配置迁移：数据库与 KV 同步切换、原配置备份逐字节读回校验后再原子替换。
- Linux race：缓存、配置和中间件通过；ARM64 上真实 PostgreSQL 和分层缓存的 race 验证也通过。
- 声明注释检查：14 个新增或重写 Go 文件的 131 个函数和 19 个类型有说明；注释补充时检查了 31 个 Go 文件的非注释 AST 保持不变。SQL、部署与集成修改亦补充了说明。

默认运行流程要求 PostgreSQL。测试适配器保留内存/Redis，不能把适配器测试成功当作正常 Worker 已完成 PostgreSQL 启动验证。

2026-11-21 提交前，再次从暂存区导出干净源码快照，在 Linux amd64 / Go 1.25.9 / PostgreSQL 17.11 上通过上述组件检查、API/命令编译和 CGO 构建。专用角色为非超级用户且无 CREATEDB 权限，分别在两个新库验证无扩展文件的嵌入 SQL 与真实 `CREATE EXTENSION` 路径；后一条明确核对 `pg_extension` 版本为 `1.0`。检查结束后专用集群停止并清理。

## 二进制部署验收

在 Debian ARM64 上通过 systemd 运行编译后的二进制，完成 28 项部署检查，包括：

- HTTPS 控制台、v2 加密握手/登录、改密、鉴权查询、退出及会话失效。
- 非超级用户且无 CREATEDB 权限的应用角色、四个独立数据库和持久会话；trusted 扩展安装后实际读写成功。
- 站点增删查改、origin/L2/L1、HEAD、Vary/查询串隔离、私有内容绕过、容量限制和 Range 绕过。
- 2,640,000 字节上传完整性；12 个并发相同 MISS 只回源一次；条件再验证及配置变更失效。
- SQL 注入、XSS、扫描器和目录遍历拦截，以及站点密码认证先于共享缓存。
- PostgreSQL 受控连接故障分类与恢复；应用、数据库和整机重启后恢复会话及 L2。
- 临时站点、测试数据库、源站和故障注入规则清理，服务恢复正常。

这里的 12 并发检查只验证填充合并语义。吞吐和延迟另见[性能基准](PERFORMANCE-TIERED-POSTGRES.zh-CN.md)。

## 全仓测试的已知限制

ARM64 上执行过 `go test -json -p 2 ./... -count=1 -timeout=300s`，移除了测试进程的网络管理和系统管理能力。全仓测试未全部通过：65 个包通过，14 个包失败；JSON 中记录 2,785 个测试/子测试 pass 事件、37 个 fail 事件和 8 个 skip 事件。这些计数不是去重后的顶层测试数。

失败涉及固定测试文件缺失、Kafka 相关编译签名、既有 Go vet 格式问题、外部服务和配置依赖、防火墙权限以及断言差异。12 项 API/service 失败已在未修改的官方 `df095c9` 上复现；其余失败尚未全部建立同环境的上游对照。因此不将全部失败笼统归因为上游问题，也不把组件通过描述为全仓通过。

`TestWafCache_SetWithTTl` 有两次固定 65 秒等待且没有断言，组件检查明确跳过它；新的 TTL、续期和并发测试正常执行。全仓失败未通过关闭测试或批量跳过来掩盖。

Docker 镜像构建和 Compose 启动尚未在本地执行，不能由二进制部署验证推导出镜像已通过。GitHub Actions 另提供 PostgreSQL 17/18 矩阵，实际结果应以 PR 对应提交的工作流为准。

## 可重复执行的组件命令

先准备专用 PostgreSQL 测试库，应用角色应为该库 owner，并设置 `SAMWAF_TEST_PG_CACHE_DSN`。不要指向业务数据库；用例在独立 namespace 中写入和清理数据，但首次安装会创建 schema 或扩展。

```sh
export CGO_ENABLED=1
export CGO_CFLAGS='-Wno-unused-variable -D_LARGEFILE64_SOURCE'
export SAMWAF_TEST_PG_CACHE_DSN='postgres://test_owner@127.0.0.1:5432/samwaf_cache_test?sslmode=disable'

go test -mod=readonly -race ./cache ./wafenginecore/wafwebcache ./wafconfig ./middleware \
  -skip '^TestWafCache_SetWithTTl$' -count=1 -timeout=180s
go test -mod=readonly ./wafenginecore \
  -run 'TestTieredCache|TestReadRequestBody|TestHttpAuthPathScope' -count=1 -timeout=120s
go test -mod=readonly ./wafdb -run '^TestMigratePostgresConfig' -count=1 -timeout=120s
go build -mod=readonly -o ./SamWafLinux64 ./cmd/samwaf
```

不安装扩展文件时，用例验证嵌入 SQL 路径。将 `cache/postgres/` 中的两份文件安装到 PostgreSQL extension 目录后，在另一个新建的专用数据库中重跑 PostgreSQL 用例，验证真实 trusted 扩展路径。工作流会检查 `pg_extension` 中 `samwaf_kv` 的版本为 `1.0`；只看到 schema 不能证明走过扩展安装。

## 性能边界

性能测试为同机、短窗口、闭环压测，普通页缓存保持启用；保护规则和 CC 状态在报告中逐项注明。没有独立发压机、固定到达率、长时间浸泡、冷 SSD 或 Redis 对照结果。已知防护路径 PostgreSQL 状态访问和持续 L2 填充仍有显著成本，本 PR 不声称已解决这些性能瓶颈。
