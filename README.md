[English](README.md) | [简体中文](README_cn.md) | [Español](README_es.md) | [हिन्दी](README_hi.md) | [العربية](README_ar.md) | [Français](README_fr.md) | [Português](README_pt.md) | [Русский](README_ru.md) | [বাংলা](README_bn.md) | [اردو](README_ur.md) | [日本語](README_ja.md) | [Deutsch](README_de.md) | [Bahasa Indonesia](README_id.md) | [한국어](README_ko.md)


<div align="center">
 <img alt="SamWaf" width="100" src="./docs/images/logo.png"> 

A lightweight open-source web application firewall

[![Release](https://img.shields.io/github/release/samwafgo/SamWaf.svg)](https://github.com/samwafgo/SamWaf/releases)
[![Last commit](https://img.shields.io/github/last-commit/samwafgo/SamWaf?style=flat-square&color=blue&logo=github)](https://github.com/samwafgo/SamWaf/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/samwaf/samwaf?style=flat-square&color=blue&label=Docker+Image+Pulls)](https://hub.docker.com/r/samwaf/samwaf)
[![Release Downloads](https://img.shields.io/github/downloads/samwafgo/samwaf/total?style=flat-square&color=blue&label=Release+Downloads)](https://github.com/samwafgo/SamWaf/releases)
[![Gitee](https://img.shields.io/badge/Gitee-blue?style=flat-square&logo=Gitee)](https://gitee.com/samwaf/SamWaf)
[![GitHub stars](https://img.shields.io/github/stars/samwafgo/SamWaf?style=flat-square&logo=Github)](https://github.com/samwafgo/SamWaf)
[![Gitee star](https://gitee.com/samwaf/SamWaf/badge/star.svg?theme=gray)](https://gitee.com/samwaf/SamWaf)
[![Atomgit star](https://atomgit.com/SamSafe/SamWaf/star/badge.svg)](https://atomgit.com/SamSafe/SamWaf)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)
</div>

  
## Development Motivation:
- **Lightweight**: Initially, I used some security products  based on nginx, apache, and iis plugins for protection, but the plugin form had a high coupling degree.
- **Privatization**: Later, most cloud protection services were adopted, but private deployment is affordable only for medium and large enterprises, while small companies and studios find it costly.
- **Privacy Encryption**: During web protection, it is preferable to process local data without sending it to the cloud. The goal was to create a tool that encrypts local information and network communications for the management end.
- **DIY**: Over the years of website maintenance and development, there were specific functions I wanted to add but couldn't achieve.
- **Awareness**: If the webmaster has never used a similar WAF, it is inconvenient to understand who is accessing the site and what requests are being made solely from logs or nginx, apache, IIS, etc.

In short, the goal was to create an effective tool for website or API protection to handle abnormal situations and ensure the normal operation of websites and applications.

# Software Introduction
SamWaf is a lightweight, open-source web application firewall for small companies, studios, and personal websites. It supports fully private deployment, encrypts data stored locally, is easy to start, and supports Linux, Windows 64-bit and ARM64, with Docker images available. By default it uses an embedded encrypted SQLite database with zero external dependencies, and can optionally switch to MySQL.

## Architecture

![SamWaf Architecture](./docs/images_en/tecDesign.svg)

## Interface
![SamWaf Web Application Firewall Overview](/docs/images_en/overview.png)

<table>
    <tr>
        <td align="center">Add Host</td>
        <td align="center">Attack Log</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/add_host.png" alt="Add Host"/></td>
        <td><img src="./docs/images_en/attacklog.png" alt="Attack Log"/></td>
    </tr>
    <tr>
        <td align="center">CC</td>
        <td align="center">IP Blocklist</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/cc.png" alt="CC"/></td>
        <td><img src="./docs/images_en/ipblock.png" alt="IP Blocklist"/></td>
    </tr>
    <tr>
        <td align="center">IP Allowlist</td>
        <td align="center">LDP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/ipallow.png" alt="IP Allowlist"/></td>
        <td><img src="./docs/images_en/ldp.png" alt="LDP"/></td>
    </tr>
    <tr>
        <td align="center">Add Rule Script Log</td>
        <td align="center">Select Log</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/log_add_rule_script.png" alt="Add Rule Script Log"/></td>
        <td><img src="./docs/images_en/log_select.png" alt="Select Log"/></td>
    </tr>
    <tr>
        <td align="center">Log Details</td>
        <td align="center">Manual Rule</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/logdetail.png" alt="Log Details"/></td>
        <td><img src="./docs/images_en/manual_rule.png" alt="Manual Rule"/></td>
    </tr>
    <tr>
        <td align="center">URL Blocklist</td>
        <td align="center">URL Allowlist</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/urlblock.png" alt="URL Blocklist"/></td>
        <td><img src="./docs/images_en/urlallow.png" alt="URL Allowlist"/></td>
    </tr>
</table>

## Main Features

### Basics
- Completely open-source code (Apache 2.0)
- Fully private deployment; data is encrypted and stored locally only
- Single-file one-click start, lightweight with no third-party service dependencies (MySQL/Redis are optional)
- Fully independent engine; protection does not rely on IIS or Nginx
- IPv6 support

### Traffic Access
- HTTP/1.1, HTTP/2 and HTTP/3 (QUIC) support
- WebSocket forwarding
- Reverse proxy with load balancing (weighted round-robin, IP hash, least connections); health checks automatically remove unhealthy backends
- Path rules: per-path reverse proxy, static files, or 301/302 redirect, with configurable backend protocol and response timeout
- Static site serving
- TCP/UDP layer-4 tunnel forwarding (with IP access control and time-window control)
- Web page caching
- HTTP Basic Auth for site access
- Customizable blocking page

### Attack Protection
- SQL injection detection
- XSS (cross-site scripting) detection
- RCE (remote command execution) detection
- Scanner tool detection
- Path traversal detection
- File upload detection (dangerous extensions, webshell signatures, spoofed Content-Type)
- CC / rate-limit protection
- Fake crawler / bot detection (reverse-DNS verification of search-engine bots)
- Anti-leech (hotlink protection)
- CSRF protection (per-site Origin/Referer validation)
- Sensitive word filtering
- OWASP CRS rule set support (Coraza engine; rules can be enabled/disabled/overridden)
- Customizable protection rules, supporting both script and GUI editing
- Human verification: click CAPTCHA and Cap.js proof-of-work
- Log-only mode: record attacks without blocking, useful for observing and tuning rules

### Access Control
- IP allowlist / blocklist
- URL allowlist / blocklist
- Geo blocking (built-in offline ip2region/GeoIP2 databases, IPv4/IPv6)
- OS-firewall-linked IP banning
- Automatic banning when IP failure count reaches a threshold
- Global one-click configuration and per-site protection strategies

### Data Security
- Encrypted log storage
- Encrypted communication logs
- Data masking (DLP) with designated data privacy output
- Web page anti-tamper (baseline learning + automatic recovery)
- Cookie security hardening (HttpOnly/Secure/SameSite)

### SSL Certificates
- Automatic SSL certificate application and renewal (ACME, multi-CA with EAB support)
- SNI multi-certificate and multi-port HTTPS
- Bulk SSL certificate expiration check
- Automatic certificate loading

### Operations & Management
- Account RBAC, OTP two-factor authentication, login/operation logs
- Statistics reports and system/host monitoring
- Data retention policy with automatic log sharding and archiving
- SQLite (encrypted) by default, optional MySQL, with a built-in SQLite→MySQL migration tool
- Online one-click upgrade, zero-downtime rolling restart, and version rollback
- Batch tasks, scheduled tasks, and data backup
- Open API

### Notifications
- Email, DingTalk, Feishu, WeCom (WeChat Work), ServerChan, Webhook, Kafka, RabbitMQ, and log-file delivery channels

# Usage Instructions
**It is strongly recommended to conduct thorough testing in a test environment before deploying to production. If any issues arise, please provide feedback promptly.**
## Download the Latest Version
Gitee:  [https://gitee.com/samwaf/SamWaf/releases](https://gitee.com/samwaf/SamWaf/releases)

GitHub: [https://github.com/samwafgo/SamWaf/releases](https://github.com/samwafgo/SamWaf/releases)

AtomGit: [https://atomgit.com/SamSafe/SamWaf/releases](https://atomgit.com/SamSafe/SamWaf/releases)

## Quick Start

### Windows
- Start directly
```
SamWaf64.exe
```
- Run as a service (requires Administrator)
```
//Install & Start
SamWaf64.exe install && SamWaf64.exe start

//Stop &  Uninstall 
SamWaf64.exe stop && SamWaf64.exe uninstall
``` 

### Linux
- install
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh install 
``` 

- uninstall
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh uninstall 
```

### Docker
```
docker run -d --name=samwaf-instance \
           --restart always \
           -p 26666:26666 \
           -p 80:80 \
           -p 443:443 \
           -v /path/to/your/conf:/app/conf \
           -v /path/to/your/data:/app/data \
           -v /path/to/your/logs:/app/logs \
           -v /path/to/your/ssl:/app/ssl \
           samwaf/samwaf


```
More Detail Docker https://hub.docker.com/r/samwaf/samwaf

Tags:
- **latest**: The latest stable release (recommended for production use).
- **beta**: The latest testing version (allows testing of new features or specific bug fixes).

### Command-Line Tools

| Command | Description |
|---------|-------------|
| `install` / `uninstall` | Install / uninstall the system service |
| `start` / `stop` / `restart` | Start / stop / restart the service |
| `rolling-restart` | Zero-downtime rolling restart (swaps the worker without interrupting traffic) |
| `resetpwd` | Reset the administrator password |
| `resetotp` | Reset the security code (OTP) |
| `repairdb` | Repair a corrupted database |
| `execsql` | Execute SQL statements on a selected database |
| `migratedb` | Offline database migration SQLite → MySQL (`--dry-run` to estimate only, `--force` to overwrite) |
| `rollback` | Roll back to a previous backup version |

Example: `SamWaf64.exe resetpwd` (on Linux: `./SamWafLinux64 resetpwd`)

## Start Access

http://127.0.0.1:26666

Default account: admin  Initial password: fresh installs auto-generate a random password saved to `data/initial_password.txt` (existing installs keep their previous password; please change it upon first login)


## Upgrade Guide

**Note: The upgrade process will terminate the service, please upgrade during off-peak hours.**

### Automatic Upgrade
If a new version is available, an upgrade prompt will pop up for confirmation, allowing you to initiate the upgrade. The page will automatically refresh after the upgrade is complete.

### Manual Upgrade
- For direct launch:
    1. Close the application.
    2. Download the latest program and replace the existing files, then manually start it again.

- For service mode:
```
1. First, pause the service.

  Windows: SamWaf64.exe stop
  Linux: ./SamWafLinux64 stop
  
2. Replace with the latest application files.

3. Start the service:
Windows: SamWaf64.exe start
Linux: ./SamWafLinux64 start
```

**Note**: Upgrading the Windows service may trigger security rules from 360 or Huorong, preventing the new files from being replaced normally. In this case, you can manually replace the files. Those familiar with this area can help determine the correct handling method.

## Online Documentation

[Online Documentation](https://doc.samwaf.com/)

# Code Information
## Code Repository
- Gitee
[https://gitee.com/samwaf/SamWaf](https://gitee.com/samwaf/SamWaf)
- GitHub
[https://github.com/samwafgo/SamWaf](https://github.com/samwafgo/SamWaf)
- Atomgit
[https://atomgit.com/SamSafe/SamWaf](https://atomgit.com/SamSafe/SamWaf)

## Introduction and Compilation
How to Compile
[Compilation Instructions](./docs/compile.md)

Compile Online Manual：
[https://doc.samwaf.com/en/dev/](https://doc.samwaf.com/en/dev/)

## Tested and Supported Platforms
[Tested and Supported Platforms](./docs/Tested_supported_systems.md)

## Other Info 

- [Update IP Database](./docs/ipmodify.md)

## Testing Results
[Testing Results](./test/attackTest.md)

# Security Policy
[Security Policy](./SECURITY.md)

# Feedback
SamWaf is continuously iterating. We welcome feedback and suggestions.

- [Gitee Issues](https://gitee.com/samwaf/SamWaf/issues)
- [GitHub Issues](https://github.com/samwafgo/SamWaf/issues)
- [Atomgit Issues](https://atomgit.com/SamSafe/SamWaf/issues)
- Email feedback: samwafgo@gmail.com

# WeChat Public Account

<img alt="SamWaf" width="400px"  src="./docs/images/mp_samwaf.png"> 

## Star history

[![Star History Chart](https://api.star-history.com/svg?repos=samwafgo/samwaf&type=Date)](https://star-history.com/#samwafgo/samwaf&Date)


#  License
SamWaf is licensed under the Apache License 2.0. Refer to [LICENSE](./LICENSE) for more details.

For third-party software usage notice, see [ThirdLicense](./ThirdLicense)

# Contribution
 Thanks for the following contributors!

<a href="https://github.com/samwafgo/SamWaf/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=samwafgo/SamWaf" />
</a>
