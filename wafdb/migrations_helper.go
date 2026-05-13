package wafdb

import (
	"SamWaf/wafdb/dialect"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// checkIndexExists reports whether indexName exists on tableName.
// Uses GORM's dialect-aware Migrator so it works on SQLite, MySQL, and SQL Server.
func checkIndexExists(db *gorm.DB, tableName, indexName string) bool {
	return db.Migrator().HasIndex(tableName, indexName)
}

// safeCreateIndex creates the named index only when it does not already exist.
// createSQL must be a SQLite-style "CREATE [UNIQUE] INDEX IF NOT EXISTS ..." statement;
// for MySQL the "IF NOT EXISTS" clause is stripped before execution because MySQL
// does not support it on CREATE INDEX.
func safeCreateIndex(tx *gorm.DB, table, indexName, createSQL string) error {
	if tx.Migrator().HasIndex(table, indexName) {
		return nil
	}
	execSQL := createSQL
	if dialect.Get().Name() == "mysql" {
		execSQL = strings.Replace(createSQL, "IF NOT EXISTS ", "", 1)
	}
	return tx.Exec(execSQL).Error
}

// safeDropIndex drops the named index only when it exists.
// MySQL requires the table name in the DROP statement; SQLite uses IF NOT EXISTS.
func safeDropIndex(tx *gorm.DB, table, indexName string) error {
	if !tx.Migrator().HasIndex(table, indexName) {
		return nil
	}
	if dialect.Get().Name() == "mysql" {
		return tx.Exec(fmt.Sprintf("DROP INDEX `%s` ON `%s`", indexName, table)).Error
	}
	return tx.Exec(fmt.Sprintf("DROP INDEX IF EXISTS %s", indexName)).Error
}
