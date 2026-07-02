[English](README.md) | [简体中文](README_cn.md) | [Español](README_es.md) | [हिन्दी](README_hi.md) | [العربية](README_ar.md) | [Français](README_fr.md) | [Português](README_pt.md) | [Русский](README_ru.md) | [বাংলা](README_bn.md) | [اردو](README_ur.md) | [日本語](README_ja.md) | [Deutsch](README_de.md) | [Bahasa Indonesia](README_id.md) | [한국어](README_ko.md)


<div align="center">
 <img alt="SamWaf" width="100" src="./docs/images/logo.png"> 

Лёгкий межсетевой экран для веб-приложений с открытым исходным кодом

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

  
## Мотивация разработки:
- **Лёгкость**: Изначально для защиты я использовал продукты безопасности на основе плагинов для nginx, apache и iis, однако плагинная форма означала высокую степень связанности.
- **Приватное развёртывание**: Позднее широкое распространение получили облачные сервисы защиты, но приватное развёртывание по карману лишь средним и крупным предприятиям, а для небольших компаний и студий оно обходится дорого.
- **Шифрование и приватность**: При защите веб-ресурсов предпочтительнее обрабатывать данные локально, не отправляя их в облако. Целью было создать инструмент, который шифрует локальную информацию и сетевое взаимодействие управляющей части.
- **DIY**: За годы сопровождения и разработки сайтов накопились функции, которые хотелось добавить, но реализовать их не удавалось.
- **Осведомлённость**: Если веб-мастер никогда не пользовался подобным WAF, ему неудобно понимать только по логам nginx, apache, IIS и т. д., кто обращается к сайту и какие запросы выполняются.

Одним словом, цель состояла в том, чтобы создать эффективный инструмент защиты сайтов и API, позволяющий справляться с нештатными ситуациями и обеспечивать нормальную работу сайтов и приложений.

# Описание программы
SamWaf — это лёгкий межсетевой экран для веб-приложений с открытым исходным кодом, предназначенный для небольших компаний, студий и персональных сайтов. Он поддерживает полностью приватное развёртывание, шифрует данные, хранящиеся локально, прост в запуске и работает на Linux, Windows 64-bit и ARM64; также доступны образы Docker. По умолчанию используется встроенная зашифрованная база данных SQLite без каких-либо внешних зависимостей, при необходимости можно переключиться на MySQL.

## Архитектура

![Архитектура SamWaf](./docs/images_en/tecDesign.svg)

## Интерфейс
![Обзор межсетевого экрана веб-приложений SamWaf](/docs/images_en/overview.png)

<table>
    <tr>
        <td align="center">Добавление хоста</td>
        <td align="center">Журнал атак</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/add_host.png" alt="Добавление хоста"/></td>
        <td><img src="./docs/images_en/attacklog.png" alt="Журнал атак"/></td>
    </tr>
    <tr>
        <td align="center">CC</td>
        <td align="center">Чёрный список IP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/cc.png" alt="CC"/></td>
        <td><img src="./docs/images_en/ipblock.png" alt="Чёрный список IP"/></td>
    </tr>
    <tr>
        <td align="center">Белый список IP</td>
        <td align="center">LDP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/ipallow.png" alt="Белый список IP"/></td>
        <td><img src="./docs/images_en/ldp.png" alt="LDP"/></td>
    </tr>
    <tr>
        <td align="center">Добавление скриптового правила из журнала</td>
        <td align="center">Выборка журналов</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/log_add_rule_script.png" alt="Добавление скриптового правила из журнала"/></td>
        <td><img src="./docs/images_en/log_select.png" alt="Выборка журналов"/></td>
    </tr>
    <tr>
        <td align="center">Детали журнала</td>
        <td align="center">Ручное правило</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/logdetail.png" alt="Детали журнала"/></td>
        <td><img src="./docs/images_en/manual_rule.png" alt="Ручное правило"/></td>
    </tr>
    <tr>
        <td align="center">Чёрный список URL</td>
        <td align="center">Белый список URL</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/urlblock.png" alt="Чёрный список URL"/></td>
        <td><img src="./docs/images_en/urlallow.png" alt="Белый список URL"/></td>
    </tr>
</table>

## Основные возможности

### Базовые возможности
- Полностью открытый исходный код (Apache 2.0)
- Полностью приватное развёртывание; данные шифруются и хранятся только локально
- Запуск одним файлом в один клик; лёгкий, без зависимостей от сторонних сервисов (MySQL/Redis опциональны)
- Полностью независимый движок; защита не зависит от IIS или Nginx
- Поддержка IPv6

### Приём трафика
- Поддержка HTTP/1.1, HTTP/2 и HTTP/3 (QUIC)
- Проксирование WebSocket
- Обратный прокси с балансировкой нагрузки (взвешенный round-robin, IP-хеш, наименьшее число соединений); проверки работоспособности автоматически исключают неработоспособные бэкенды
- Правила для путей: обратный прокси, статические файлы или редирект 301/302 для отдельных путей, с настраиваемым протоколом бэкенда и тайм-аутом ответа
- Раздача статических сайтов
- Туннельная пересылка TCP/UDP на уровне L4 (с контролем доступа по IP и по временным окнам)
- Кэширование веб-страниц
- HTTP Basic Auth для доступа к сайту
- Настраиваемая страница блокировки

### Защита от атак
- Обнаружение SQL-инъекций
- Обнаружение XSS (межсайтового скриптинга)
- Обнаружение RCE (удалённого выполнения команд)
- Обнаружение сканеров
- Обнаружение обхода каталогов (path traversal)
- Проверка загружаемых файлов (опасные расширения, сигнатуры веб-шеллов, поддельный Content-Type)
- Защита от CC-атак / ограничение частоты запросов
- Обнаружение поддельных краулеров и ботов (проверка ботов поисковых систем через обратный DNS)
- Защита от хотлинкинга (anti-leech)
- Защита от CSRF (проверка Origin/Referer для каждого сайта)
- Фильтрация чувствительных слов
- Поддержка набора правил OWASP CRS (движок Coraza; правила можно включать, отключать и переопределять)
- Настраиваемые правила защиты с редактированием как в виде скриптов, так и через графический интерфейс
- Проверка на человека: клик-CAPTCHA и proof-of-work на базе Cap.js
- Режим «только журналирование»: атаки записываются без блокировки — удобно для наблюдения и тонкой настройки правил

### Контроль доступа
- Белые и чёрные списки IP
- Белые и чёрные списки URL
- Географическая блокировка (встроенные офлайн-базы ip2region/GeoIP2, IPv4/IPv6)
- Блокировка IP с привязкой к брандмауэру ОС
- Автоматическая блокировка IP при достижении порогового числа нарушений
- Глобальная настройка в один клик и отдельные стратегии защиты для каждого сайта

### Безопасность данных
- Шифрованное хранение журналов
- Шифрование журналов обмена данными
- Маскирование данных (DLP) с настраиваемым выводом конфиденциальной информации
- Защита веб-страниц от несанкционированных изменений (построение эталона + автоматическое восстановление)
- Усиление безопасности cookie (HttpOnly/Secure/SameSite)

### SSL-сертификаты
- Автоматическое получение и продление SSL-сертификатов (ACME, несколько центров сертификации с поддержкой EAB)
- Несколько сертификатов через SNI и HTTPS на нескольких портах
- Массовая проверка сроков действия SSL-сертификатов
- Автоматическая загрузка сертификатов

### Эксплуатация и управление
- RBAC для учётных записей, двухфакторная аутентификация OTP, журналы входов и операций
- Статистические отчёты и мониторинг системы/хостов
- Политика хранения данных с автоматическим шардированием и архивированием журналов
- SQLite (с шифрованием) по умолчанию, опционально MySQL, со встроенным инструментом миграции SQLite→MySQL
- Онлайн-обновление в один клик, плавный перезапуск без простоя и откат версии
- Пакетные задачи, задачи по расписанию и резервное копирование данных
- Открытый API

### Уведомления
- Каналы доставки: электронная почта, DingTalk, Feishu, WeCom (WeChat Work), ServerChan, Webhook, Kafka, RabbitMQ и запись в файл журнала

# Инструкция по использованию
**Настоятельно рекомендуется провести тщательное тестирование в тестовой среде перед развёртыванием в продакшене. При возникновении любых проблем, пожалуйста, оперативно сообщайте о них.**
## Скачать последнюю версию
Gitee:  [https://gitee.com/samwaf/SamWaf/releases](https://gitee.com/samwaf/SamWaf/releases)

GitHub: [https://github.com/samwafgo/SamWaf/releases](https://github.com/samwafgo/SamWaf/releases)

AtomGit: [https://atomgit.com/SamSafe/SamWaf/releases](https://atomgit.com/SamSafe/SamWaf/releases)

## Быстрый старт

### Windows
- Прямой запуск
```
SamWaf64.exe
```
- Запуск в качестве службы (требуются права администратора)
```
//Install & Start
SamWaf64.exe install && SamWaf64.exe start

//Stop &  Uninstall 
SamWaf64.exe stop && SamWaf64.exe uninstall
``` 

### Linux
- Установка
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh install 
``` 

- Удаление
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
Подробнее о Docker: https://hub.docker.com/r/samwaf/samwaf

Теги:
- **latest**: последний стабильный выпуск (рекомендуется для использования в продакшене).
- **beta**: последняя тестовая версия (позволяет опробовать новые функции или отдельные исправления ошибок).

### Инструменты командной строки

| Command | Описание |
|---------|-------------|
| `install` / `uninstall` | Установка / удаление системной службы |
| `start` / `stop` / `restart` | Запуск / остановка / перезапуск службы |
| `rolling-restart` | Плавный перезапуск без простоя (замена воркера без прерывания трафика) |
| `resetpwd` | Сброс пароля администратора |
| `resetotp` | Сброс кода безопасности (OTP) |
| `repairdb` | Восстановление повреждённой базы данных |
| `execsql` | Выполнение SQL-запросов в выбранной базе данных |
| `migratedb` | Офлайн-миграция базы данных SQLite → MySQL (`--dry-run` — только оценка, `--force` — перезапись) |
| `rollback` | Откат к предыдущей резервной версии |

Пример: `SamWaf64.exe resetpwd` (в Linux: `./SamWafLinux64 resetpwd`)

## Запуск и доступ

http://127.0.0.1:26666

Учётная запись по умолчанию: admin  Пароль по умолчанию: admin868 (пожалуйста, смените пароль по умолчанию при первом входе)


## Руководство по обновлению

**Внимание: в процессе обновления служба будет остановлена, поэтому выполняйте обновление в часы наименьшей нагрузки.**

### Автоматическое обновление
Если доступна новая версия, появится окно с предложением обновления, в котором можно подтвердить запуск обновления. После завершения обновления страница автоматически обновится.

### Ручное обновление
- При прямом запуске:
    1. Закройте приложение.
    2. Скачайте последнюю версию программы, замените существующие файлы, затем снова запустите её вручную.

- В режиме службы:
```
1. First, pause the service.

  Windows: SamWaf64.exe stop
  Linux: ./SamWafLinux64 stop
  
2. Replace with the latest application files.

3. Start the service:
Windows: SamWaf64.exe start
Linux: ./SamWafLinux64 start
```

**Примечание**: при обновлении службы Windows могут сработать правила безопасности 360 или Huorong, из-за чего новые файлы не будут заменены штатным образом. В этом случае можно заменить файлы вручную. Те, кто разбирается в этой области, могут помочь определить правильный способ решения.

## Онлайн-документация

[Онлайн-документация](https://doc.samwaf.com/)

# Информация о коде
## Репозиторий кода
- Gitee
[https://gitee.com/samwaf/SamWaf](https://gitee.com/samwaf/SamWaf)
- GitHub
[https://github.com/samwafgo/SamWaf](https://github.com/samwafgo/SamWaf)
- Atomgit
[https://atomgit.com/SamSafe/SamWaf](https://atomgit.com/SamSafe/SamWaf)

## Введение и компиляция
Как выполнить компиляцию
[Инструкция по компиляции](./docs/compile.md)

Онлайн-руководство по компиляции：
[https://doc.samwaf.com/en/dev/](https://doc.samwaf.com/en/dev/)

## Протестированные и поддерживаемые платформы
[Протестированные и поддерживаемые платформы](./docs/Tested_supported_systems.md)

## Прочая информация 

- [Обновление базы IP-адресов](./docs/ipmodify.md)

## Результаты тестирования
[Результаты тестирования](./test/attackTest.md)

# Политика безопасности
[Политика безопасности](./SECURITY.md)

# Обратная связь
SamWaf постоянно развивается. Мы будем рады вашим отзывам и предложениям.

- [Gitee Issues](https://gitee.com/samwaf/SamWaf/issues)
- [GitHub Issues](https://github.com/samwafgo/SamWaf/issues)
- [Atomgit Issues](https://atomgit.com/SamSafe/SamWaf/issues)
- Обратная связь по электронной почте: samwafgo@gmail.com

# Официальный аккаунт WeChat

<img alt="SamWaf" width="400px"  src="./docs/images/mp_samwaf.png"> 

## История звёзд

[![График истории звёзд](https://api.star-history.com/svg?repos=samwafgo/samwaf&type=Date)](https://star-history.com/#samwafgo/samwaf&Date)


#  Лицензия
SamWaf распространяется под лицензией Apache License 2.0. Подробности см. в файле [LICENSE](./LICENSE).

Уведомление об использовании стороннего программного обеспечения см. в [ThirdLicense](./ThirdLicense)

# Вклад в проект
 Благодарим следующих контрибьюторов!

<a href="https://github.com/samwafgo/SamWaf/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=samwafgo/SamWaf" />
</a>
