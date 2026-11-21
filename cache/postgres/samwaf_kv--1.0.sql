-- samwaf_kv 是纯 SQL 的持久 KV/TTL 扩展，无 Redis 进程或原生共享库依赖。
-- 服务器未安装扩展文件时，应用可以在事务中执行同一份 SQL 安装 schema/functions。
-- 所有函数使用调用者权限和限定 schema；clock_timestamp() 让过期判断使用实际时间，而非事务开始时间。
CREATE SCHEMA IF NOT EXISTS samwaf_kv;
-- namespace/cache_key 共同隔离实例和键；普通持久表保留未到期凭据，不按网页 LRU 淘汰。
-- expires_at 决定读取可见性，后台物理删除只负责空间回收。
CREATE TABLE IF NOT EXISTS samwaf_kv.entries (
    namespace text NOT NULL,
    cache_key text NOT NULL,
    value jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (namespace, cache_key),
    CHECK (octet_length(namespace) BETWEEN 1 AND 256),
    CHECK (octet_length(cache_key) BETWEEN 1 AND 8192)
);
-- 清理按到期时间分批选择，避免每个周期全表扫描或一次删除过多行。
CREATE INDEX IF NOT EXISTS entries_expires_idx ON samwaf_kv.entries (expires_at);

-- version 是 SQL API 的兼容版本；扩展包版本另由 control 文件声明为 1.0。
CREATE OR REPLACE FUNCTION samwaf_kv.version() RETURNS integer
LANGUAGE sql IMMUTABLE AS 'SELECT 1';

-- kv_set 原子覆盖值并重置期限，ttl_ms 的单位为毫秒；非正 TTL 明确删除键。
CREATE OR REPLACE FUNCTION samwaf_kv.kv_set(ns text, k text, v jsonb, ttl_ms bigint)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF ttl_ms <= 0 THEN
        DELETE FROM samwaf_kv.entries WHERE namespace=ns AND cache_key=k;
        RETURN;
    END IF;
    INSERT INTO samwaf_kv.entries(namespace,cache_key,value,created_at,expires_at)
    VALUES(ns,k,v,clock_timestamp(),clock_timestamp()+ttl_ms*interval '1 millisecond')
    ON CONFLICT(namespace,cache_key) DO UPDATE
    SET value=EXCLUDED.value,created_at=EXCLUDED.created_at,expires_at=EXCLUDED.expires_at;
END $$;

-- kv_get 只返回仍有效的记录；即使清理任务尚未删除该行，过期值也不可读取。
CREATE OR REPLACE FUNCTION samwaf_kv.kv_get(ns text, k text)
RETURNS jsonb LANGUAGE sql VOLATILE SET search_path = pg_catalog AS $$
    SELECT value FROM samwaf_kv.entries
    WHERE namespace=ns AND cache_key=k AND expires_at>clock_timestamp()
$$;

-- kv_getex 用一次 UPDATE 完成取值和续期，避免跨 Worker 的 GET 后再续期间隙。
-- 非正 TTL 退化为只读；缺失或已经过期的键不被复活。
CREATE OR REPLACE FUNCTION samwaf_kv.kv_getex(ns text, k text, ttl_ms bigint)
RETURNS jsonb LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE result jsonb;
BEGIN
    IF ttl_ms<=0 THEN RETURN samwaf_kv.kv_get(ns,k); END IF;
    UPDATE samwaf_kv.entries SET created_at=clock_timestamp(),
        expires_at=clock_timestamp()+ttl_ms*interval '1 millisecond'
    WHERE namespace=ns AND cache_key=k AND expires_at>clock_timestamp()
    RETURNING value INTO result;
    RETURN result;
END $$;

-- kv_touch 只给有效键续期，返回是否找到该键；非正 TTL 仅检查存在性，不删除。
CREATE OR REPLACE FUNCTION samwaf_kv.kv_touch(ns text, k text, ttl_ms bigint)
RETURNS boolean LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE affected bigint;
BEGIN
    IF ttl_ms<=0 THEN
        RETURN EXISTS(SELECT 1 FROM samwaf_kv.entries WHERE namespace=ns AND cache_key=k AND expires_at>clock_timestamp());
    END IF;
    UPDATE samwaf_kv.entries SET created_at=clock_timestamp(),
        expires_at=clock_timestamp()+ttl_ms*interval '1 millisecond'
    WHERE namespace=ns AND cache_key=k AND expires_at>clock_timestamp();
    GET DIAGNOSTICS affected=ROW_COUNT;
    RETURN affected=1;
END $$;

-- kv_exists 的存在性包含 TTL 判断，不能用物理行存在代替可用状态。
CREATE OR REPLACE FUNCTION samwaf_kv.kv_exists(ns text, k text)
RETURNS boolean LANGUAGE sql VOLATILE SET search_path = pg_catalog AS $$
    SELECT EXISTS(SELECT 1 FROM samwaf_kv.entries WHERE namespace=ns AND cache_key=k AND expires_at>clock_timestamp())
$$;

-- kv_delete 幂等撤销状态，返回是否实际删除了一行，不依赖该行是否已经到期。
CREATE OR REPLACE FUNCTION samwaf_kv.kv_delete(ns text, k text)
RETURNS boolean LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE affected bigint;
BEGIN
    DELETE FROM samwaf_kv.entries WHERE namespace=ns AND cache_key=k;
    GET DIAGNOSTICS affected=ROW_COUNT;
    RETURN affected=1;
END $$;

-- kv_expires 只暴露有效键的绝对到期时刻；缺失和过期都返回 SQL NULL。
CREATE OR REPLACE FUNCTION samwaf_kv.kv_expires(ns text, k text)
RETURNS timestamptz LANGUAGE sql VOLATILE SET search_path = pg_catalog AS $$
    SELECT expires_at FROM samwaf_kv.entries WHERE namespace=ns AND cache_key=k AND expires_at>clock_timestamp()
$$;

-- kv_keys 将 prefix 作为字面前缀，% 和 _ 不能扩大查询范围为 LIKE 通配匹配。
-- 结果仅限当前 namespace 的有效键，客户端用 expires_at 估算剩余时间。
CREATE OR REPLACE FUNCTION samwaf_kv.kv_keys(ns text, prefix text)
RETURNS TABLE(cache_key text,expires_at timestamptz)
LANGUAGE sql VOLATILE SET search_path = pg_catalog AS $$
    SELECT e.cache_key,e.expires_at FROM samwaf_kv.entries e
    WHERE e.namespace=ns AND starts_with(e.cache_key,prefix) AND e.expires_at>clock_timestamp()
$$;

-- kv_add 通过主键冲突锁和条件 UPSERT 实现原子首次占用。
-- 只有旧键已过期时才可替换；同时到达的防重放请求不能都把同一有效 nonce 占用成功。
CREATE OR REPLACE FUNCTION samwaf_kv.kv_add(ns text, k text, v jsonb, ttl_ms bigint)
RETURNS boolean LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE added boolean;
BEGIN
    IF ttl_ms<=0 THEN RETURN false; END IF;
    INSERT INTO samwaf_kv.entries(namespace,cache_key,value,created_at,expires_at)
    VALUES(ns,k,v,clock_timestamp(),clock_timestamp()+ttl_ms*interval '1 millisecond')
    ON CONFLICT(namespace,cache_key) DO UPDATE
    SET value=EXCLUDED.value,created_at=EXCLUDED.created_at,expires_at=EXCLUDED.expires_at
    WHERE samwaf_kv.entries.expires_at<=clock_timestamp()
    RETURNING true INTO added;
    RETURN coalesce(added,false);
END $$;

-- kv_incrby 在同一行锁内完成累加，缺失/过期记录从 delta 开始，不做应用层读改写。
-- renew=false 保持原固定窗口，true 显式续期；非整数已有值和数值溢出由 PostgreSQL 报错。
CREATE OR REPLACE FUNCTION samwaf_kv.kv_incrby(ns text, k text, delta bigint, ttl_ms bigint, renew boolean DEFAULT false)
RETURNS bigint LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE result bigint;
BEGIN
    IF ttl_ms<=0 THEN RAISE EXCEPTION 'TTL must be positive' USING ERRCODE='22023'; END IF;
    INSERT INTO samwaf_kv.entries(namespace,cache_key,value,created_at,expires_at)
    VALUES(ns,k,to_jsonb(delta),clock_timestamp(),clock_timestamp()+ttl_ms*interval '1 millisecond')
    ON CONFLICT(namespace,cache_key) DO UPDATE SET
    value=CASE WHEN samwaf_kv.entries.expires_at<=clock_timestamp() THEN to_jsonb(delta)
        ELSE to_jsonb((samwaf_kv.entries.value #>> '{}')::bigint+delta) END,
    created_at=CASE WHEN renew OR samwaf_kv.entries.expires_at<=clock_timestamp() THEN EXCLUDED.created_at ELSE samwaf_kv.entries.created_at END,
    expires_at=CASE WHEN renew OR samwaf_kv.entries.expires_at<=clock_timestamp() THEN EXCLUDED.expires_at ELSE samwaf_kv.entries.expires_at END
    RETURNING (value #>> '{}')::bigint INTO result;
    RETURN result;
END $$;

-- kv_cleanup 只删除已经过期的记录，批量限制在 1..50000，默认 5000。
-- FOR UPDATE SKIP LOCKED 允许多个 Worker 协作回收，避免清理等待正在处理的业务行锁。
CREATE OR REPLACE FUNCTION samwaf_kv.kv_cleanup(batch_size integer DEFAULT 5000)
RETURNS bigint LANGUAGE sql VOLATILE SET search_path = pg_catalog AS $$
    WITH expired AS (
        SELECT ctid FROM samwaf_kv.entries WHERE expires_at<=clock_timestamp()
        ORDER BY expires_at LIMIT greatest(1,least(batch_size,50000)) FOR UPDATE SKIP LOCKED
    ), removed AS (
        DELETE FROM samwaf_kv.entries e USING expired x WHERE e.ctid=x.ctid RETURNING 1
    ) SELECT count(*) FROM removed
$$;

-- trusted 扩展的安装脚本由 PostgreSQL 以引导超级用户执行，表并不自动归安装者所有。
-- 必须给原会话安装者授权，否则普通数据库 owner 虽能 CREATE EXTENSION，随后的 KV 读写仍会失败。
-- schema 直装路径中 session_user 就是应用角色，这些授权同样安全且幂等。
DO $$
BEGIN
    EXECUTE format('GRANT USAGE ON SCHEMA samwaf_kv TO %I', session_user);
    EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE samwaf_kv.entries TO %I', session_user);
    EXECUTE format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA samwaf_kv TO %I', session_user);
END $$;
