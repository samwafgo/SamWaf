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
