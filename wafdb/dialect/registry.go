package dialect

// current is the active dialect, set once at startup via Register.
var current DBDialect

// Register sets the active dialect. Must be called before any DB operations.
// Typically called at the end of wafconfig.LoadAndInitConfig().
func Register(d DBDialect) {
	current = d
}

// Get returns the currently registered dialect.
// Panics if Register has not been called yet.
func Get() DBDialect {
	if current == nil {
		panic("wafdb/dialect: no dialect registered; call dialect.Register() during startup")
	}
	return current
}

// Q quotes an identifier with the active dialect's quoting characters.
//
// Use it in hand-written SQL fragments for column names that are reserved words in
// some engine — `key`, `ssl`, `role`, `status`. Hard-coding MySQL back-ticks there
// breaks PostgreSQL, which reads ` as an operator ("operator does not exist: `").
//
//	db.Where(dialect.Q("status")+" = ?", "active")
func Q(ident string) string {
	return Get().Quote(ident)
}
