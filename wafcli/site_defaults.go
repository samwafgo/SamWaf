package wafcli

// 复用控制台的站点初始字段；本分支 cache_json 使用 L1/L2 的有限默认预算。
// 旧前端的 memory/file/all 值由后端兼容解释；静态站点四类安全默认值与引擎一致。
const createDefaultsJSON = `{
  "ssl": 0,
  "remote_system": "默认",
  "remote_app": "默认",
  "defense_json": "{\"bot\":1,\"sqli\":1,\"xss\":1,\"scan\":1,\"rce\":1,\"sensitive\":1,\"traversal\":1,\"owaspset\":0}",
  "healthy_json": "{\"is_enable_healthy\":1,\"fail_count\":3,\"success_count\":3,\"response_time\":60,\"check_method\":\"GET\",\"check_path\":\"/\",\"expected_codes\":\"200,\"}",
  "captcha_json": "{\"is_enable_captcha\":0,\"path_prefix\":\"\",\"exclude_urls\":[],\"expire_time\":24,\"engine_type\":\"traditional\",\"cap_js_config\":{\"challengeCount\":50,\"challengeSize\":32,\"challengeDifficulty\":4,\"expiresMs\":600000,\"infoTitle\":{\"en\":\"\",\"zh\":\"\"},\"infoText\":{\"en\":\"\",\"zh\":\"\"}}}",
  "start_status": 0,
  "is_enable_load_balance": 0,
  "load_balance_stage": 1,
  "unrestricted_port": 0,
  "auto_jump_https": 0,
  "disable_http2": 0,
  "is_trans_back_domain": 0,
  "is_enable_http_auth_base": 0,
  "http_auth_base_type": "authorization",
  "response_time_out": 60,
  "is_enable_response_buffering": 1,
  "insecure_skip_verify": 0,
  "anti_leech_json": "{\"is_enable_anti_leech\":0,\"file_types\":\"gif|jpg|jpeg|png|bmp|swf\",\"valid_referers\":\"none;server_names\",\"action\":\"block\",\"redirect_url\":\"\"}",
  "cache_json": "{\"is_enable_cache\":0,\"cache_location\":\"tiered\",\"cache_dir\":\"./data/cache\",\"max_file_size_mb\":32,\"max_memory_size_mb\":4,\"l1_capacity_mb\":64,\"l2_capacity_mb\":1024,\"heat_threshold\":3,\"heat_window_seconds\":5400,\"inactive_seconds\":86400,\"max_entries\":100000,\"lock_timeout_seconds\":5,\"min_free_mb\":64}",
  "response_compress_json": "{\"is_enable\":0,\"prefer\":\"zstd_first\",\"min_length\":256,\"include_types\":\"\",\"include_extensions\":\"\",\"exclude_extensions\":\"\",\"exclude_paths\":\"\",\"compress_when_static_assist\":0}",
  "cookie_security_json": "{\"is_enable\":0,\"http_only\":1,\"secure\":2,\"same_site\":\"Lax\",\"exclude_cookies\":\"\"}",
  "csrf_json": "{\"is_enable\":0,\"protect_methods\":\"POST,PUT,DELETE,PATCH\",\"allowed_origins\":\"\",\"allow_empty_ref\":1,\"exclude_paths\":\"\"}",
  "access_json": "{\"mode\":0,\"exclude_paths\":\"\",\"require_otp\":0,\"unauth_action\":\"\",\"allow_ip_group_code\":\"\"}",
  "tamper_json": "{\"is_enable\":0,\"action\":\"replace\",\"max_size_kb\":1024}",
  "upload_security_json": "{\"is_enable\":0,\"check_ext\":0,\"ext_blacklist\":\"\",\"check_content\":0,\"check_magic\":0,\"check_size\":0,\"max_size_kb\":10240,\"over_limit_action\":\"block\",\"include_paths\":\"\",\"exclude_paths\":\"\"}",
  "static_site_json": "{\"is_enable_static_site\":0,\"static_site_path\":\"\",\"static_site_prefix\":\"/\",\"sensitive_paths\":\"/etc/passwd,/etc/shadow,/etc/group,/etc/gshadow,/etc/hosts,/etc/hostname,/etc/resolv.conf,/etc/ssh/,/var/log/,/.ssh/,/.bash_history,/.profile,/.bashrc,/etc/crontab,/var/spool/cron/,/etc/apache2/,/etc/nginx/,/etc/httpd/,/var/www/,/usr/share/,/var/tmp/,/var/run/,c:\\\\windows\\\\,c:\\\\program files\\\\,c:\\\\program files (x86)\\\\,c:\\\\users\\\\,c:\\\\documents and settings\\\\,c:\\\\windows\\\\system32\\\\,c:\\\\windows\\\\syswow64\\\\,c:\\\\boot.ini,c:\\\\autoexec.bat,c:\\\\config.sys,\\\\windows\\\\,\\\\program files\\\\,\\\\program files (x86)\\\\,\\\\users\\\\,\\\\documents and settings\\\\,\\\\windows\\\\system32\\\\,\\\\windows\\\\syswow64\\\\,boot.ini,autoexec.bat,config.sys,ntuser.dat,pagefile.sys,hiberfil.sys,swapfile.sys\",\"sensitive_extensions\":\".key,.pem,.crt,.p12,.pfx,.jks,.bak,.backup,.old,.orig,.save,.sql,.db,.sqlite,.mdb,.env,.htaccess,.htpasswd,.git,.svn,.hg,.bzr,.DS_Store,Thumbs.db,desktop.ini,.tmp,.temp,.lock,.pid\",\"allowed_extensions\":\".html,.htm,.css,.js,.mjs,.cjs,.json,.map,.png,.jpg,.jpeg,.gif,.svg,.ico,.webp,.avif,.pdf,.txt,.md,.xml,.woff,.woff2,.ttf,.eot,.otf,.mp4,.webm,.ogg,.mp3,.wav,.zip,.tar,.gz,.rar\",\"sensitive_patterns\":\"(?i)\\\\.git(/|\\\\\\\\),(?i)\\\\.svn(/|\\\\\\\\),(?i)\\\\.env,(?i)database\\\\.(php|xml|json|yaml|yml),(?i)(backup|dump|export)\\\\.(sql|db|tar|zip|gz),(?i)(id_rsa|id_dsa|id_ecdsa|id_ed25519),(?i)\\\\.ssh(/|\\\\\\\\).*,(?i)(access|error|debug)\\\\.log,(?i)web\\\\.config,(?i)phpinfo\\\\.php\"}",
  "default_encoding": "auto",
  "log_only_mode": 0,
  "ip_mode": "nic",
  "transport_json": "{\"max_idle_conns\":0,\"max_idle_conns_per_host\":0,\"max_conns_per_host\":0,\"idle_conn_timeout\":0,\"tls_handshake_timeout\":0,\"expect_continue_timeout\":0}",
  "custom_headers_json": "{\"is_enable_custom_headers\":0,\"headers\":[]}"
}`
