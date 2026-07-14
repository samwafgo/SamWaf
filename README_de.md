[English](README.md) | [简体中文](README_cn.md) | [Español](README_es.md) | [हिन्दी](README_hi.md) | [العربية](README_ar.md) | [Français](README_fr.md) | [Português](README_pt.md) | [Русский](README_ru.md) | [বাংলা](README_bn.md) | [اردو](README_ur.md) | [日本語](README_ja.md) | [Deutsch](README_de.md) | [Bahasa Indonesia](README_id.md) | [한국어](README_ko.md)


<div align="center">
 <img alt="SamWaf" width="100" src="./docs/images/logo.png"> 

Eine leichtgewichtige Open-Source-Web-Application-Firewall

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

  
## Entwicklungsmotivation:
- **Leichtgewichtig**: Anfangs habe ich zum Schutz einige Sicherheitsprodukte auf Basis von nginx-, apache- und iis-Plugins eingesetzt, doch die Plugin-Form wies einen hohen Kopplungsgrad auf.
- **Private Bereitstellung**: Später kamen überwiegend Cloud-Schutzdienste zum Einsatz, doch eine private Bereitstellung ist nur für mittlere und große Unternehmen erschwinglich, während sie für kleine Firmen und Studios kostspielig ist.
- **Datenschutz durch Verschlüsselung**: Beim Web-Schutz ist es vorzuziehen, Daten lokal zu verarbeiten, ohne sie in die Cloud zu senden. Ziel war es, ein Werkzeug zu schaffen, das lokale Informationen und die Netzwerkkommunikation der Verwaltungsseite verschlüsselt.
- **DIY**: In den Jahren der Website-Wartung und -Entwicklung gab es bestimmte Funktionen, die ich gerne ergänzt hätte, aber nicht umsetzen konnte.
- **Transparenz**: Wenn der Webmaster noch nie eine vergleichbare WAF verwendet hat, ist es umständlich, allein anhand von Logs oder über nginx, apache, IIS usw. nachzuvollziehen, wer auf die Website zugreift und welche Anfragen gestellt werden.

Kurz gesagt: Ziel war es, ein wirksames Werkzeug zum Schutz von Websites oder APIs zu schaffen, um mit anormalen Situationen umzugehen und den normalen Betrieb von Websites und Anwendungen sicherzustellen.

# Software-Einführung
SamWaf ist eine leichtgewichtige Open-Source-Web-Application-Firewall für kleine Unternehmen, Studios und private Websites. Sie unterstützt eine vollständig private Bereitstellung, verschlüsselt lokal gespeicherte Daten, ist einfach zu starten und unterstützt Linux, Windows 64-Bit und ARM64; Docker-Images sind verfügbar. Standardmäßig verwendet sie eine eingebettete, verschlüsselte SQLite-Datenbank ohne jegliche externe Abhängigkeiten und kann optional auf MySQL / PostgreSQL umgestellt werden.

## Architektur

![SamWaf-Architektur](./docs/images_en/tecDesign.svg)

## Benutzeroberfläche
![Übersicht der SamWaf Web Application Firewall](/docs/images_en/overview.png)

<table>
    <tr>
        <td align="center">Host hinzufügen</td>
        <td align="center">Angriffsprotokoll</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/add_host.png" alt="Host hinzufügen"/></td>
        <td><img src="./docs/images_en/attacklog.png" alt="Angriffsprotokoll"/></td>
    </tr>
    <tr>
        <td align="center">CC</td>
        <td align="center">IP-Sperrliste</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/cc.png" alt="CC"/></td>
        <td><img src="./docs/images_en/ipblock.png" alt="IP-Sperrliste"/></td>
    </tr>
    <tr>
        <td align="center">IP-Zulassungsliste</td>
        <td align="center">LDP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/ipallow.png" alt="IP-Zulassungsliste"/></td>
        <td><img src="./docs/images_en/ldp.png" alt="LDP"/></td>
    </tr>
    <tr>
        <td align="center">Regelskript aus Protokoll hinzufügen</td>
        <td align="center">Protokollauswahl</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/log_add_rule_script.png" alt="Regelskript aus Protokoll hinzufügen"/></td>
        <td><img src="./docs/images_en/log_select.png" alt="Protokollauswahl"/></td>
    </tr>
    <tr>
        <td align="center">Protokolldetails</td>
        <td align="center">Manuelle Regel</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/logdetail.png" alt="Protokolldetails"/></td>
        <td><img src="./docs/images_en/manual_rule.png" alt="Manuelle Regel"/></td>
    </tr>
    <tr>
        <td align="center">URL-Sperrliste</td>
        <td align="center">URL-Zulassungsliste</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/urlblock.png" alt="URL-Sperrliste"/></td>
        <td><img src="./docs/images_en/urlallow.png" alt="URL-Zulassungsliste"/></td>
    </tr>
</table>

## Hauptfunktionen

### Grundlagen
- Vollständig quelloffener Code (Apache 2.0)
- Vollständig private Bereitstellung; Daten werden verschlüsselt und ausschließlich lokal gespeichert
- Ein-Klick-Start als einzelne Datei, leichtgewichtig und ohne Abhängigkeiten von Drittanbieterdiensten (MySQL/Redis sind optional)
- Vollständig eigenständige Engine; der Schutz ist nicht auf IIS oder Nginx angewiesen
- IPv6-Unterstützung

### Traffic-Anbindung
- Unterstützung für HTTP/1.1, HTTP/2 und HTTP/3 (QUIC)
- WebSocket-Weiterleitung
- Reverse Proxy mit Lastverteilung (gewichtetes Round-Robin, IP-Hash, Least Connections); Health-Checks entfernen fehlerhafte Backends automatisch
- Pfadregeln: Reverse Proxy, statische Dateien oder 301/302-Weiterleitung pro Pfad, mit konfigurierbarem Backend-Protokoll und Antwort-Timeout
- Bereitstellung statischer Websites
- TCP/UDP-Layer-4-Tunnelweiterleitung (mit IP-Zugriffskontrolle und Zeitfenstersteuerung)
- Webseiten-Caching
- HTTP Basic Auth für den Website-Zugriff
- Anpassbare Sperrseite

### Angriffsschutz
- Erkennung von SQL-Injection
- Erkennung von XSS (Cross-Site-Scripting)
- Erkennung von RCE (Remote Command Execution)
- Erkennung von Scanner-Tools
- Erkennung von Path Traversal
- Datei-Upload-Prüfung (gefährliche Dateiendungen, Webshell-Signaturen, gefälschter Content-Type)
- CC-/Rate-Limit-Schutz
- Erkennung gefälschter Crawler/Bots (Reverse-DNS-Verifizierung von Suchmaschinen-Bots)
- Hotlink-Schutz (Anti-Leech)
- CSRF-Schutz (Origin-/Referer-Validierung pro Website)
- Filterung sensibler Begriffe
- Unterstützung des OWASP-CRS-Regelwerks (Coraza-Engine; Regeln können aktiviert/deaktiviert/überschrieben werden)
- Anpassbare Schutzregeln, bearbeitbar per Skript und über die GUI
- Menschliche Verifizierung: Klick-CAPTCHA und Cap.js-Proof-of-Work
- Nur-Protokollieren-Modus: zeichnet Angriffe auf, ohne zu blockieren – nützlich zum Beobachten und Feinabstimmen von Regeln

### Zugriffskontrolle
- IP-Zulassungsliste / -Sperrliste
- URL-Zulassungsliste / -Sperrliste
- Geo-Blocking (integrierte Offline-Datenbanken ip2region/GeoIP2, IPv4/IPv6)
- IP-Sperrung mit Kopplung an die Betriebssystem-Firewall
- Automatische Sperrung, wenn die Zahl der Fehlversuche einer IP einen Schwellenwert erreicht
- Globale Ein-Klick-Konfiguration und Schutzstrategien pro Website

### Datensicherheit
- Verschlüsselte Protokollspeicherung
- Verschlüsselte Kommunikationsprotokolle
- Datenmaskierung (DLP) mit gezielter datenschutzkonformer Ausgabe
- Manipulationsschutz für Webseiten (Baseline-Lernen + automatische Wiederherstellung)
- Härtung der Cookie-Sicherheit (HttpOnly/Secure/SameSite)

### SSL-Zertifikate
- Automatische Beantragung und Erneuerung von SSL-Zertifikaten (ACME, mehrere CAs mit EAB-Unterstützung)
- SNI mit mehreren Zertifikaten und HTTPS auf mehreren Ports
- Massenprüfung des Ablaufdatums von SSL-Zertifikaten
- Automatisches Laden von Zertifikaten

### Betrieb & Verwaltung
- RBAC für Konten, OTP-Zwei-Faktor-Authentifizierung, Anmelde- und Aktionsprotokolle
- Statistikberichte sowie System- und Host-Überwachung
- Datenaufbewahrungsrichtlinie mit automatischem Log-Sharding und automatischer Archivierung
- Standardmäßig SQLite (verschlüsselt), optional MySQL / PostgreSQL, mit integriertem Migrationswerkzeug für SQLite→MySQL / SQLite→PostgreSQL / MySQL→PostgreSQL
- Online-Upgrade per Klick, Rolling-Restart ohne Ausfallzeit und Versions-Rollback
- Batch-Aufgaben, geplante Aufgaben und Datensicherung
- Offene API

### Benachrichtigungen
- Zustellkanäle: E-Mail, DingTalk, Feishu, WeCom (WeChat Work), ServerChan, Webhook, Kafka, RabbitMQ und Protokolldatei

# Nutzungshinweise
**Es wird dringend empfohlen, vor der Bereitstellung in der Produktion gründliche Tests in einer Testumgebung durchzuführen. Sollten Probleme auftreten, geben Sie bitte umgehend Rückmeldung.**
## Neueste Version herunterladen
Gitee:  [https://gitee.com/samwaf/SamWaf/releases](https://gitee.com/samwaf/SamWaf/releases)

GitHub: [https://github.com/samwafgo/SamWaf/releases](https://github.com/samwafgo/SamWaf/releases)

AtomGit: [https://atomgit.com/SamSafe/SamWaf/releases](https://atomgit.com/SamSafe/SamWaf/releases)

## Schnellstart

### Windows
- Direkt starten
```
SamWaf64.exe
```
- Als Dienst ausführen (erfordert Administratorrechte)
```
//Install & Start
SamWaf64.exe install && SamWaf64.exe start

//Stop &  Uninstall 
SamWaf64.exe stop && SamWaf64.exe uninstall
``` 

### Linux
- Installieren
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh install 
``` 

- Deinstallieren
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
Weitere Details zu Docker: https://hub.docker.com/r/samwaf/samwaf

Tags:
- **latest**: Die neueste stabile Version (für den Produktionseinsatz empfohlen).
- **beta**: Die neueste Testversion (ermöglicht das Testen neuer Funktionen oder gezielter Fehlerbehebungen).

### Kommandozeilenwerkzeuge

| Command | Beschreibung |
|---------|-------------|
| `install` / `uninstall` | Systemdienst installieren / deinstallieren |
| `start` / `stop` / `restart` | Dienst starten / stoppen / neu starten |
| `rolling-restart` | Rolling-Restart ohne Ausfallzeit (tauscht den Worker aus, ohne den Datenverkehr zu unterbrechen) |
| `resetpwd` | Administratorpasswort zurücksetzen |
| `resetotp` | Sicherheitscode (OTP) zurücksetzen |
| `repairdb` | Beschädigte Datenbank reparieren |
| `execsql` | SQL-Anweisungen auf einer ausgewählten Datenbank ausführen |
| `migratedb` | Offline-Datenbankmigration SQLite → MySQL / SQLite → PostgreSQL / MySQL → PostgreSQL (`--dry-run` nur zur Abschätzung, `--force` zum Überschreiben) |
| `rollback` | Auf eine frühere Sicherungsversion zurücksetzen |

Beispiel: `SamWaf64.exe resetpwd` (unter Linux: `./SamWafLinux64 resetpwd`)

## Zugriff starten

http://127.0.0.1:26666

Standardkonto: admin  Initialpasswort: Bei Neuinstallationen wird automatisch ein zufälliges Passwort erzeugt und in `data/initial_password.txt` gespeichert (bestehende Installationen behalten ihr bisheriges Passwort; bitte ändern Sie es bei der ersten Anmeldung)


## Upgrade-Anleitung

**Hinweis: Der Upgrade-Vorgang beendet den Dienst. Bitte führen Sie das Upgrade außerhalb der Hauptnutzungszeiten durch.**

### Automatisches Upgrade
Wenn eine neue Version verfügbar ist, erscheint eine Upgrade-Aufforderung zur Bestätigung, über die Sie das Upgrade starten können. Nach Abschluss des Upgrades wird die Seite automatisch aktualisiert.

### Manuelles Upgrade
- Bei direktem Start:
    1. Schließen Sie die Anwendung.
    2. Laden Sie das neueste Programm herunter, ersetzen Sie die vorhandenen Dateien und starten Sie die Anwendung anschließend manuell neu.

- Im Dienstmodus:
```
1. First, pause the service.

  Windows: SamWaf64.exe stop
  Linux: ./SamWafLinux64 stop
  
2. Replace with the latest application files.

3. Start the service:
Windows: SamWaf64.exe start
Linux: ./SamWafLinux64 start
```

**Hinweis**: Beim Upgrade des Windows-Dienstes können Sicherheitsregeln von 360 oder Huorong ausgelöst werden, wodurch die neuen Dateien nicht ordnungsgemäß ersetzt werden können. In diesem Fall können Sie die Dateien manuell ersetzen. Wer sich in diesem Bereich auskennt, kann bei der Ermittlung der richtigen Vorgehensweise helfen.

## Online-Dokumentation

[Online-Dokumentation](https://doc.samwaf.com/)

# Code-Informationen
## Code-Repository
- Gitee
[https://gitee.com/samwaf/SamWaf](https://gitee.com/samwaf/SamWaf)
- GitHub
[https://github.com/samwafgo/SamWaf](https://github.com/samwafgo/SamWaf)
- Atomgit
[https://atomgit.com/SamSafe/SamWaf](https://atomgit.com/SamSafe/SamWaf)

## Einführung und Kompilierung
Wie man kompiliert
[Kompilierungsanleitung](./docs/compile.md)

Online-Handbuch zur Kompilierung：
[https://doc.samwaf.com/en/dev/](https://doc.samwaf.com/en/dev/)

## Getestete und unterstützte Plattformen
[Getestete und unterstützte Plattformen](./docs/Tested_supported_systems.md)

## Weitere Informationen 

- [IP-Datenbank aktualisieren](./docs/ipmodify.md)

## Testergebnisse
[Testergebnisse](./test/attackTest.md)

# Sicherheitsrichtlinie
[Sicherheitsrichtlinie](./SECURITY.md)

# Feedback
SamWaf wird kontinuierlich weiterentwickelt. Feedback und Vorschläge sind willkommen.

- [Gitee Issues](https://gitee.com/samwaf/SamWaf/issues)
- [GitHub Issues](https://github.com/samwafgo/SamWaf/issues)
- [Atomgit Issues](https://atomgit.com/SamSafe/SamWaf/issues)
- Feedback per E-Mail: samwafgo@gmail.com

# Offizieller WeChat-Account

<img alt="SamWaf" width="400px"  src="./docs/images/mp_samwaf.png"> 

## Star-Verlauf

[![Star-History-Diagramm](https://api.star-history.com/svg?repos=samwafgo/samwaf&type=Date)](https://star-history.com/#samwafgo/samwaf&Date)


#  Lizenz
SamWaf ist unter der Apache License 2.0 lizenziert. Weitere Details finden Sie in der Datei [LICENSE](./LICENSE).

Hinweise zur Nutzung von Drittanbieter-Software finden Sie unter [ThirdLicense](./ThirdLicense)

# Mitwirkung
 Vielen Dank an die folgenden Mitwirkenden!

<a href="https://github.com/samwafgo/SamWaf/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=samwafgo/SamWaf" />
</a>
