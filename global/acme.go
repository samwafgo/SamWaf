package global

type ACMEConfig struct {
	DirectoryTimeoutSeconds int
	DirectoryMaxRetries     int
	TrustedCAs              map[string]ACMETrustedCA
}

type ACMETrustedCA struct {
	CAFile      string
	ConfigError string
}

func DefaultACMEConfig() ACMEConfig {
	return ACMEConfig{DirectoryTimeoutSeconds: 30, DirectoryMaxRetries: 5}
}
