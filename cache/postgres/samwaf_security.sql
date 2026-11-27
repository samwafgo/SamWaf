-- 安全计数是独立的应用 schema，避免给已有 trusted KV 扩展的超级用户对象越权改定义。
-- 由数据库 owner 在事务咨询锁内首次安装，不需要超级用户或 CREATEDB。
CREATE SCHEMA IF NOT EXISTS samwaf_security;
CREATE TABLE IF NOT EXISTS samwaf_security.counters (
    namespace text NOT NULL,
    scope text NOT NULL,
    dimension text NOT NULL,
    mode text NOT NULL,
    window_sec integer NOT NULL,
    limit_count integer NOT NULL,
    state jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY(namespace,scope,dimension)
);
CREATE INDEX IF NOT EXISTS security_counter_expiry ON samwaf_security.counters(namespace,expires_at);
-- 配额只在新维度分配时锁定；同一个已存在维度只竞争它自己的行，不串行化整个站点。
CREATE TABLE IF NOT EXISTS samwaf_security.quota (
    namespace text NOT NULL,
    scope text NOT NULL,
    entries bigint NOT NULL DEFAULT 0,
    PRIMARY KEY(namespace,scope)
);

-- 一次 SQL 往返完成跨进程的计数/限流。buckets 延续十桶近似窗口；rate 是令牌桶；
-- window 延续旧 CC 的精确滑动窗口，时间戳数组最多保留 limit_count 个事件。
CREATE OR REPLACE FUNCTION samwaf_security.hit(
    ns text, sc text, dim text, win integer, lim integer, kind text,
    max_total integer, max_scope integer
) RETURNS TABLE(hit_count bigint,allowed boolean,degraded boolean,rejected boolean)
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE
    previous samwaf_security.counters%ROWTYPE;
    moment timestamptz := clock_timestamp();
    epoch_now double precision := extract(epoch FROM moment);
    payload jsonb;
    buckets bigint[];
    events double precision[];
    bucket_width integer;
    slot_now bigint;
    slot_old bigint;
    delta bigint;
    idx integer;
    tokens double precision;
    total_keys bigint;
    scope_keys bigint;
BEGIN
    IF ns='' OR sc='' OR octet_length(ns)>256 OR octet_length(sc)>512 OR octet_length(dim)>256
       OR win<1 OR win>604800 OR lim<0 OR lim>1000000 OR kind NOT IN ('buckets','rate','window')
       OR max_total<1 OR max_scope<1 THEN
        RAISE EXCEPTION 'invalid security counter configuration' USING ERRCODE='22023';
    END IF;
    hit_count:=0; allowed:=false; degraded:=false; rejected:=false;
    -- 缺失行也需要同键锁，避免首次并发插入出现先查后写竞争；不同维度互不阻塞。
    PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(ns,sc,dim)::text,7357140145));
    SELECT * INTO previous FROM samwaf_security.counters
      WHERE namespace=ns AND scope=sc AND dimension=dim FOR UPDATE;
    IF NOT FOUND THEN
        INSERT INTO samwaf_security.quota(namespace,scope) VALUES(ns,'') ON CONFLICT DO NOTHING;
        SELECT entries INTO total_keys FROM samwaf_security.quota WHERE namespace=ns AND scope='' FOR UPDATE;
        INSERT INTO samwaf_security.quota(namespace,scope) VALUES(ns,sc) ON CONFLICT DO NOTHING;
        SELECT entries INTO scope_keys FROM samwaf_security.quota WHERE namespace=ns AND scope=sc FOR UPDATE;
        IF total_keys>=max_total THEN rejected:=true; RETURN NEXT; RETURN; END IF;
        IF scope_keys>=max_scope THEN degraded:=true; RETURN NEXT; RETURN; END IF;
        UPDATE samwaf_security.quota SET entries=entries+1 WHERE namespace=ns AND scope IN ('',sc);
        payload:='{}'::jsonb;
    ELSIF previous.expires_at<=moment OR previous.mode<>kind OR previous.window_sec<>win OR previous.limit_count<>lim THEN
        payload:='{}'::jsonb;
    ELSE
        payload:=previous.state;
    END IF;

    IF kind='buckets' THEN
        bucket_width:=greatest(1,win/10);
        slot_now:=floor(epoch_now/bucket_width)::bigint;
        slot_old:=coalesce((payload->>'slot')::bigint,slot_now);
        SELECT coalesce(array_agg(value::bigint ORDER BY ordinality),array_fill(0::bigint,ARRAY[10])) INTO buckets
          FROM jsonb_array_elements_text(coalesce(payload->'counts','[]'::jsonb)) WITH ORDINALITY;
        delta:=slot_now-slot_old;
        IF cardinality(buckets)<>10 OR delta>=10 OR delta<0 THEN buckets:=array_fill(0::bigint,ARRAY[10]);
        ELSIF delta>0 THEN
            FOR i IN 1..delta::integer LOOP buckets[((slot_old+i)%10)::integer+1]:=0; END LOOP;
        END IF;
        idx:=(slot_now%10)::integer+1;
        buckets[idx]:=buckets[idx]+1;
        SELECT sum(value) INTO hit_count FROM unnest(buckets) value;
        allowed:=true;
        payload:=jsonb_build_object('slot',slot_now,'counts',to_jsonb(buckets));
    ELSIF kind='rate' THEN
        tokens:=least(lim::double precision,coalesce((payload->>'tokens')::double precision,lim::double precision)
          +greatest(0,epoch_now-coalesce((payload->>'at')::double precision,epoch_now))*lim/greatest(1,win));
        allowed:=tokens>=1;
        IF allowed THEN tokens:=tokens-1; END IF;
        hit_count:=greatest(0,lim-floor(tokens)::bigint);
        payload:=jsonb_build_object('tokens',tokens,'at',epoch_now);
    ELSE
        SELECT coalesce(array_agg(value::double precision ORDER BY ordinality),ARRAY[]::double precision[]) INTO events
          FROM jsonb_array_elements_text(coalesce(payload->'events','[]'::jsonb)) WITH ORDINALITY
          WHERE value::double precision>epoch_now-win;
        allowed:=cardinality(events)<lim;
        IF allowed THEN events:=array_append(events,epoch_now); END IF;
        hit_count:=cardinality(events);
        payload:=jsonb_build_object('events',to_jsonb(events));
    END IF;
    INSERT INTO samwaf_security.counters(namespace,scope,dimension,mode,window_sec,limit_count,state,expires_at)
      VALUES(ns,sc,dim,kind,win,lim,payload,moment+greatest(300,win*2)*interval '1 second')
      ON CONFLICT(namespace,scope,dimension) DO UPDATE SET state=EXCLUDED.state,expires_at=EXCLUDED.expires_at,
        mode=EXCLUDED.mode,window_sec=EXCLUDED.window_sec,limit_count=EXCLUDED.limit_count;
    RETURN NEXT;
END $$;

-- 清理与分配统一按 namespace 总配额行加锁，再操作来源配额，保持固定锁顺序。
-- 使用 SKIP LOCKED 不等待正在累加的热键；有效窗口从不按 LRU 淘汰。
CREATE OR REPLACE FUNCTION samwaf_security.cleanup(ns text, prefix text DEFAULT NULL, batch integer DEFAULT 5000, dimension_filter text DEFAULT NULL)
RETURNS bigint LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE removed bigint := 0; entry record;
BEGIN
    INSERT INTO samwaf_security.quota(namespace,scope) VALUES(ns,'') ON CONFLICT DO NOTHING;
    PERFORM 1 FROM samwaf_security.quota WHERE namespace=ns AND scope='' FOR UPDATE;
    FOR entry IN
      WITH chosen AS (
        SELECT ctid FROM samwaf_security.counters
          WHERE namespace=ns AND ((prefix IS NULL AND expires_at<=clock_timestamp()) OR (prefix IS NOT NULL AND starts_with(scope,prefix)))
            AND (dimension_filter IS NULL OR dimension=dimension_filter)
          ORDER BY expires_at LIMIT greatest(1,least(batch,50000)) FOR UPDATE SKIP LOCKED
      ), deleted AS (
        DELETE FROM samwaf_security.counters c USING chosen x WHERE c.ctid=x.ctid RETURNING c.scope
      ) SELECT scope,count(*) amount FROM deleted GROUP BY scope
    LOOP
        UPDATE samwaf_security.quota SET entries=greatest(0,entries-entry.amount)
          WHERE namespace=ns AND scope=entry.scope;
        removed:=removed+entry.amount;
    END LOOP;
    UPDATE samwaf_security.quota SET entries=greatest(0,entries-removed) WHERE namespace=ns AND scope='';
    DELETE FROM samwaf_security.quota WHERE namespace=ns AND scope<>'' AND entries=0;
    RETURN removed;
END $$;

CREATE OR REPLACE FUNCTION samwaf_security.version() RETURNS integer LANGUAGE sql IMMUTABLE AS 'SELECT 1';
