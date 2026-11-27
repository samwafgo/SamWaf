package cache

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"time"
)

// securityDDL 由普通数据库 owner 安装，与已有 trusted KV 扩展的所有权分开。
//
//go:embed postgres/samwaf_security.sql
var securityDDL string

// SecurityCount 一次数据库调用完成原子计数/限流与配额判断，所有 Worker 共享同一 namespace。
func (p *PostgresCache) SecurityCount(scope, dimension, mode string, window, limit, maxTotal, quota int) (count int64, allowed, degraded, rejected bool, err error) {
	ctx, cancel := p.op()
	defer cancel()
	err = p.db.QueryRowContext(ctx, "SELECT hit_count,allowed,degraded,rejected FROM samwaf_security.hit($1,$2,$3,$4,$5,$6,$7,$8)", p.namespace, scope, dimension, window, limit, mode, maxTotal, quota).Scan(&count, &allowed, &degraded, &rejected)
	if err != nil {
		err = p.note("security_count", err)
	}
	return
}

// DropSecurityCounters 只删除指定规则前缀的共享计数，失败返回，不能假装所有节点都已清零。
func (p *PostgresCache) DropSecurityCounters(prefix string) error {
	ctx, cancel := p.op()
	defer cancel()
	for batch := 0; batch < 64; batch++ {
		var removed int64
		err := p.db.QueryRowContext(ctx, "SELECT samwaf_security.cleanup($1,$2,5000)", p.namespace, prefix).Scan(&removed)
		if err != nil {
			return p.note("security_reset", err)
		}
		if removed < 5000 {
			return nil
		}
	}
	return errors.New("security counter reset budget exceeded")
}

// ExistsManyE 用一次参数化查询检查整组未到期封禁，不缓存负结果，封禁/撤销立即可见。
func (p *PostgresCache) ExistsManyE(parent context.Context, keys []string) (map[string]bool, error) {
	if len(keys) > 64 {
		return nil, errors.New("too many security lookup keys")
	}
	result := make(map[string]bool, len(keys))
	if len(keys) == 0 {
		return result, nil
	}
	ctx, cancel := context.WithTimeout(parent, p.timeout)
	defer cancel()
	rows, err := p.db.QueryContext(ctx, "SELECT cache_key FROM samwaf_kv.entries WHERE namespace=$1 AND cache_key=ANY($2::text[]) AND expires_at>clock_timestamp()", p.namespace, keys)
	if err != nil {
		return nil, p.note("security_lookup", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			return nil, p.note("security_lookup", err)
		}
		result[key] = true
	}
	if err = rows.Err(); err != nil {
		return nil, p.note("security_lookup", err)
	}
	return result, nil
}

// RemoveE 为解封提供有错误返回的删除，不沿用旧 Remove 接口吞掉故障的语义。
func (p *PostgresCache) RemoveE(key string) error {
	ctx, cancel := p.op()
	defer cancel()
	_, err := p.db.ExecContext(ctx, "SELECT samwaf_kv.kv_delete($1,$2)", p.namespace, key)
	return p.note("delete", err)
}

// UpdateJSONE 用事务级咨询锁保护同 namespace/key 的读改写；锁由数据库管理，跨进程有效。
// 回调只处理本次记录的私有 JSON 副本，失败/取消/崩溃都会回滚，不覆盖其他 Worker 已提交的计数。
func (p *PostgresCache) UpdateJSONE(key string, ttl time.Duration, mutate func([]byte) ([]byte, error)) error {
	if ttl <= 0 {
		return errors.New("security record TTL must be positive")
	}
	ctx, cancel := p.op()
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return p.note("record_update", err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,$2::text)::text,7357140143))", p.namespace, key); err != nil {
		return p.note("record_update", err)
	}
	var previous []byte
	err = tx.QueryRowContext(ctx, "SELECT value FROM samwaf_kv.entries WHERE namespace=$1 AND cache_key=$2 AND expires_at>clock_timestamp() FOR UPDATE", p.namespace, key).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return p.note("record_update", err)
	}
	updated, err := mutate(previous)
	if err != nil {
		return p.note("record_decode", err)
	}
	if _, err = tx.ExecContext(ctx, "SELECT samwaf_kv.kv_set($1,$2,$3::jsonb,$4)", p.namespace, key, string(updated), ttlMS(ttl)); err != nil {
		return p.note("record_update", err)
	}
	return p.note("record_update", tx.Commit())
}

// ReleaseSecurityE 按 namespace 原子撤销对应键，重置某 IP 时不会清空其他访客的计数。
func (p *PostgresCache) ReleaseSecurityE(keys []string, resetIP string) error {
	ctx, cancel := p.op()
	defer cancel()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return p.note("security_release", err)
	}
	defer tx.Rollback()
	if len(keys) > 0 {
		if _, err = tx.ExecContext(ctx, "DELETE FROM samwaf_kv.entries WHERE namespace=$1 AND cache_key=ANY($2::text[])", p.namespace, keys); err != nil {
			return p.note("security_release", err)
		}
	}
	if resetIP != "" {
		sum := sha256.Sum256([]byte(resetIP))
		dimension := hex.EncodeToString(sum[:])
		for batch := 0; batch < 64; batch++ {
			var removed int64
			if err = tx.QueryRowContext(ctx, "SELECT samwaf_security.cleanup($1,'',5000,$2)", p.namespace, dimension).Scan(&removed); err != nil {
				return p.note("security_release", err)
			}
			if removed < 5000 {
				break
			}
			if batch == 63 {
				return errors.New("security release budget exceeded")
			}
		}
	}
	return p.note("security_release", tx.Commit())
}
