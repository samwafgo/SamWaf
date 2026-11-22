package wafdb

import (
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// InstallIPBlockRevision 用数据库语句级触发器记录名单版本，覆盖 API、批处理及外部 SQL 写入。
// 版本递增与原变更同事务提交/回滚；不在请求判定热路径访问该表。
func InstallIPBlockRevision(db *gorm.DB) error {
	if db.Dialector.Name() != "postgres" {
		return nil
	}
	table := db.NamingStrategy.TableName("IPBlockList")
	quoted := `"` + strings.ReplaceAll(table, `"`, `""`) + `"`
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(7357140144)").Error; err != nil {
			return err
		}
		ddl := `CREATE SCHEMA IF NOT EXISTS samwaf_control;
CREATE TABLE IF NOT EXISTS samwaf_control.revisions (name text PRIMARY KEY, revision bigint NOT NULL);
INSERT INTO samwaf_control.revisions VALUES ('ip_block',1) ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION samwaf_control.ip_block_changed() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE current_revision bigint;
BEGIN
    UPDATE samwaf_control.revisions SET revision=revision+1 WHERE name='ip_block' RETURNING revision INTO current_revision;
    PERFORM pg_notify('samwaf_ip_blocks',current_revision::text);
    RETURN NULL;
END $$;`
		if err := tx.Exec(ddl).Error; err != nil {
			return err
		}
		// 只替换本应用命名的触发器，不删除用户其他审计或约束触发器。
		if err := tx.Exec(fmt.Sprintf("DROP TRIGGER IF EXISTS samwaf_ip_block_revision ON %s", quoted)).Error; err != nil {
			return err
		}
		return tx.Exec(fmt.Sprintf("CREATE TRIGGER samwaf_ip_block_revision AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION samwaf_control.ip_block_changed()", quoted)).Error
	})
}
