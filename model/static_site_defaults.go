package model

// 静态站点四类清单的默认值，引擎、启动巡检与命令行建站共用。
const (
	// StaticSiteDefaultSensitivePaths 敏感路径
	StaticSiteDefaultSensitivePaths = "/etc/passwd,/etc/shadow,/etc/group,/etc/gshadow,/etc/hosts,/etc/hostname,/etc/resolv.conf,/etc/ssh/,/var/log/,/.ssh/,/.bash_history,/.profile,/.bashrc,/etc/crontab,/var/spool/cron/,/etc/apache2/,/etc/nginx/,/etc/httpd/,/var/www/,/usr/share/,/var/tmp/,/var/run/,c:\\windows\\,c:\\program files\\,c:\\program files (x86)\\,c:\\users\\,c:\\documents and settings\\,c:\\windows\\system32\\,c:\\windows\\syswow64\\,c:\\boot.ini,c:\\autoexec.bat,c:\\config.sys,\\windows\\,\\program files\\,\\program files (x86)\\,\\users\\,\\documents and settings\\,\\windows\\system32\\,\\windows\\syswow64\\,boot.ini,autoexec.bat,config.sys,ntuser.dat,pagefile.sys,hiberfil.sys,swapfile.sys"
	// StaticSiteDefaultSensitiveExtensions 敏感文件扩展名
	StaticSiteDefaultSensitiveExtensions = ".key,.pem,.crt,.p12,.pfx,.jks,.bak,.backup,.old,.orig,.save,.sql,.db,.sqlite,.mdb,.env,.htaccess,.htpasswd,.git,.svn,.hg,.bzr,.DS_Store,Thumbs.db,desktop.ini,.tmp,.temp,.lock,.pid"
	// StaticSiteDefaultAllowedExtensions 允许的文件扩展名
	StaticSiteDefaultAllowedExtensions = ".html,.htm,.css,.js,.mjs,.cjs,.json,.map,.png,.jpg,.jpeg,.gif,.svg,.ico,.webp,.avif,.pdf,.txt,.md,.xml,.woff,.woff2,.ttf,.eot,.otf,.mp4,.webm,.ogg,.mp3,.wav,.zip,.tar,.gz,.rar"
	// StaticSiteDefaultSensitivePatterns 敏感文件名模式（正则）
	StaticSiteDefaultSensitivePatterns = `(?i)\.git(/|\\),(?i)\.svn(/|\\),(?i)\.env,(?i)database\.(php|xml|json|yaml|yml),(?i)(backup|dump|export)\.(sql|db|tar|zip|gz),(?i)(id_rsa|id_dsa|id_ecdsa|id_ed25519),(?i)\.ssh(/|\\).*,(?i)(access|error|debug)\.log,(?i)web\.config,(?i)phpinfo\.php`
)
