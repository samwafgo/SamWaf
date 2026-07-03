[English](README.md) | [简体中文](README_cn.md) | [Español](README_es.md) | [हिन्दी](README_hi.md) | [العربية](README_ar.md) | [Français](README_fr.md) | [Português](README_pt.md) | [Русский](README_ru.md) | [বাংলা](README_bn.md) | [اردو](README_ur.md) | [日本語](README_ja.md) | [Deutsch](README_de.md) | [Bahasa Indonesia](README_id.md) | [한국어](README_ko.md)


<div align="center">
 <img alt="SamWaf" width="100" src="./docs/images/logo.png"> 

Un firewall de aplicaciones web ligero y de código abierto

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

  
## Motivación del desarrollo:
- **Ligero**: Al principio utilicé algunos productos de seguridad basados en plugins de nginx, apache e iis para la protección, pero el formato de plugin tenía un alto grado de acoplamiento.
- **Privatización**: Más adelante se adoptaron sobre todo servicios de protección en la nube, pero el despliegue privado solo resulta asequible para medianas y grandes empresas, mientras que a las pequeñas empresas y estudios les resulta costoso.
- **Cifrado y privacidad**: Durante la protección web es preferible procesar los datos localmente sin enviarlos a la nube. El objetivo era crear una herramienta que cifrara la información local y las comunicaciones de red del extremo de administración.
- **DIY**: A lo largo de los años de mantenimiento y desarrollo de sitios web había funciones concretas que quería añadir pero que no podía conseguir.
- **Visibilidad**: Si el webmaster nunca ha utilizado un WAF similar, resulta incómodo saber quién está accediendo al sitio y qué solicitudes se están realizando únicamente a partir de los logs o de nginx, apache, IIS, etc.

En resumen, el objetivo era crear una herramienta eficaz para la protección de sitios web o API, capaz de gestionar situaciones anómalas y garantizar el funcionamiento normal de los sitios web y las aplicaciones.

# Introducción al software
SamWaf es un firewall de aplicaciones web ligero y de código abierto para pequeñas empresas, estudios y sitios web personales. Admite un despliegue totalmente privado, cifra los datos almacenados localmente, es fácil de poner en marcha y es compatible con Linux, Windows de 64 bits y ARM64, con imágenes Docker disponibles. De forma predeterminada utiliza una base de datos SQLite cifrada e integrada, sin dependencias externas, y opcionalmente puede cambiarse a MySQL.

## Arquitectura

![Arquitectura de SamWaf](./docs/images_en/tecDesign.svg)

## Interfaz
![Vista general del firewall de aplicaciones web SamWaf](/docs/images_en/overview.png)

<table>
    <tr>
        <td align="center">Añadir host</td>
        <td align="center">Registro de ataques</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/add_host.png" alt="Añadir host"/></td>
        <td><img src="./docs/images_en/attacklog.png" alt="Registro de ataques"/></td>
    </tr>
    <tr>
        <td align="center">CC</td>
        <td align="center">Lista de bloqueo de IP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/cc.png" alt="CC"/></td>
        <td><img src="./docs/images_en/ipblock.png" alt="Lista de bloqueo de IP"/></td>
    </tr>
    <tr>
        <td align="center">Lista de permitidos de IP</td>
        <td align="center">LDP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/ipallow.png" alt="Lista de permitidos de IP"/></td>
        <td><img src="./docs/images_en/ldp.png" alt="LDP"/></td>
    </tr>
    <tr>
        <td align="center">Añadir script de regla desde el registro</td>
        <td align="center">Selección de registros</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/log_add_rule_script.png" alt="Añadir script de regla desde el registro"/></td>
        <td><img src="./docs/images_en/log_select.png" alt="Selección de registros"/></td>
    </tr>
    <tr>
        <td align="center">Detalles del registro</td>
        <td align="center">Regla manual</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/logdetail.png" alt="Detalles del registro"/></td>
        <td><img src="./docs/images_en/manual_rule.png" alt="Regla manual"/></td>
    </tr>
    <tr>
        <td align="center">Lista de bloqueo de URL</td>
        <td align="center">Lista de permitidos de URL</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/urlblock.png" alt="Lista de bloqueo de URL"/></td>
        <td><img src="./docs/images_en/urlallow.png" alt="Lista de permitidos de URL"/></td>
    </tr>
</table>

## Funciones principales

### Aspectos básicos
- Código completamente abierto (Apache 2.0)
- Despliegue totalmente privado; los datos se cifran y se almacenan únicamente en local
- Inicio con un clic desde un único archivo, ligero y sin dependencias de servicios de terceros (MySQL/Redis son opcionales)
- Motor totalmente independiente; la protección no depende de IIS ni de Nginx
- Compatibilidad con IPv6

### Acceso de tráfico
- Compatibilidad con HTTP/1.1, HTTP/2 y HTTP/3 (QUIC)
- Reenvío de WebSocket
- Proxy inverso con balanceo de carga (round-robin ponderado, hash de IP, menor número de conexiones); las comprobaciones de estado eliminan automáticamente los backends en mal estado
- Reglas de ruta: proxy inverso por ruta, archivos estáticos o redirección 301/302, con protocolo de backend y tiempo de espera de respuesta configurables
- Servicio de sitios estáticos
- Reenvío de túneles TCP/UDP de capa 4 (con control de acceso por IP y control por ventana de tiempo)
- Caché de páginas web
- Autenticación HTTP Basic para el acceso al sitio
- Página de bloqueo personalizable

### Protección contra ataques
- Detección de inyección SQL
- Detección de XSS (cross-site scripting)
- Detección de RCE (ejecución remota de comandos)
- Detección de herramientas de escaneo
- Detección de path traversal
- Detección en la subida de archivos (extensiones peligrosas, firmas de webshell, Content-Type falsificado)
- Protección CC / limitación de tasa
- Detección de crawlers/bots falsos (verificación por DNS inverso de los bots de motores de búsqueda)
- Anti-leech (protección contra hotlinking)
- Protección CSRF (validación de Origin/Referer por sitio)
- Filtrado de palabras sensibles
- Compatibilidad con el conjunto de reglas OWASP CRS (motor Coraza; las reglas se pueden habilitar/deshabilitar/sobrescribir)
- Reglas de protección personalizables, con edición tanto por script como mediante interfaz gráfica
- Verificación humana: CAPTCHA de clic y prueba de trabajo con Cap.js
- Modo solo registro: registra los ataques sin bloquearlos, útil para observar y ajustar las reglas

### Control de acceso
- Lista de permitidos / lista de bloqueo de IP
- Lista de permitidos / lista de bloqueo de URL
- Bloqueo geográfico (bases de datos offline integradas ip2region/GeoIP2, IPv4/IPv6)
- Bloqueo de IP vinculado al firewall del sistema operativo
- Bloqueo automático cuando el número de fallos de una IP alcanza un umbral
- Configuración global con un clic y estrategias de protección por sitio

### Seguridad de los datos
- Almacenamiento cifrado de registros
- Registros de comunicación cifrados
- Enmascaramiento de datos (DLP) con salida de privacidad para los datos designados
- Protección contra la manipulación de páginas web (aprendizaje de línea base + recuperación automática)
- Refuerzo de la seguridad de las cookies (HttpOnly/Secure/SameSite)

### Certificados SSL
- Solicitud y renovación automáticas de certificados SSL (ACME, multi-CA con soporte de EAB)
- HTTPS con múltiples certificados SNI y múltiples puertos
- Comprobación masiva de la caducidad de certificados SSL
- Carga automática de certificados

### Operación y gestión
- RBAC de cuentas, autenticación de dos factores OTP, registros de inicio de sesión y de operaciones
- Informes estadísticos y monitorización del sistema y de los hosts
- Política de retención de datos con particionado y archivado automáticos de los registros
- SQLite (cifrado) por defecto, MySQL opcional, con una herramienta integrada de migración SQLite→MySQL
- Actualización en línea con un clic, reinicio continuo sin tiempo de inactividad y reversión de versiones
- Tareas por lotes, tareas programadas y copia de seguridad de datos
- API abierta

### Notificaciones
- Canales de entrega por correo electrónico, DingTalk, Feishu, WeCom (WeChat Work), ServerChan, Webhook, Kafka, RabbitMQ y archivo de registro

# Instrucciones de uso
**Se recomienda encarecidamente realizar pruebas exhaustivas en un entorno de pruebas antes de desplegar en producción. Si surge algún problema, envíe sus comentarios lo antes posible.**
## Descargar la última versión
Gitee:  [https://gitee.com/samwaf/SamWaf/releases](https://gitee.com/samwaf/SamWaf/releases)

GitHub: [https://github.com/samwafgo/SamWaf/releases](https://github.com/samwafgo/SamWaf/releases)

AtomGit: [https://atomgit.com/SamSafe/SamWaf/releases](https://atomgit.com/SamSafe/SamWaf/releases)

## Inicio rápido

### Windows
- Iniciar directamente
```
SamWaf64.exe
```
- Ejecutar como servicio (requiere permisos de administrador)
```
//Install & Start
SamWaf64.exe install && SamWaf64.exe start

//Stop &  Uninstall 
SamWaf64.exe stop && SamWaf64.exe uninstall
``` 

### Linux
- instalar
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh install 
``` 

- desinstalar
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
Más detalles sobre Docker https://hub.docker.com/r/samwaf/samwaf

Etiquetas:
- **latest**: La última versión estable (recomendada para uso en producción).
- **beta**: La última versión de pruebas (permite probar nuevas funciones o correcciones de errores específicas).

### Herramientas de línea de comandos

| Comando | Descripción |
|---------|-------------|
| `install` / `uninstall` | Instalar / desinstalar el servicio del sistema |
| `start` / `stop` / `restart` | Iniciar / detener / reiniciar el servicio |
| `rolling-restart` | Reinicio continuo sin tiempo de inactividad (sustituye el worker sin interrumpir el tráfico) |
| `resetpwd` | Restablecer la contraseña del administrador |
| `resetotp` | Restablecer el código de seguridad (OTP) |
| `repairdb` | Reparar una base de datos dañada |
| `execsql` | Ejecutar sentencias SQL en una base de datos seleccionada |
| `migratedb` | Migración de base de datos sin conexión SQLite → MySQL (`--dry-run` para solo estimar, `--force` para sobrescribir) |
| `rollback` | Revertir a una versión de copia de seguridad anterior |

Ejemplo: `SamWaf64.exe resetpwd` (en Linux: `./SamWafLinux64 resetpwd`)

## Acceso inicial

http://127.0.0.1:26666

Cuenta predeterminada: admin  Contraseña inicial: las instalaciones nuevas generan automáticamente una contraseña aleatoria guardada en `data/initial_password.txt` (las instalaciones existentes conservan su contraseña anterior; cámbiela al iniciar sesión por primera vez)


## Guía de actualización

**Nota: el proceso de actualización detendrá el servicio; actualice durante las horas de menor tráfico.**

### Actualización automática
Si hay una nueva versión disponible, aparecerá un aviso de actualización para su confirmación, que le permitirá iniciar la actualización. La página se refrescará automáticamente una vez completada la actualización.

### Actualización manual
- Para el inicio directo:
    1. Cierre la aplicación.
    2. Descargue el programa más reciente y reemplace los archivos existentes; luego inícielo de nuevo manualmente.

- Para el modo servicio:
```
1. First, pause the service.

  Windows: SamWaf64.exe stop
  Linux: ./SamWafLinux64 stop
  
2. Replace with the latest application files.

3. Start the service:
Windows: SamWaf64.exe start
Linux: ./SamWafLinux64 start
```

**Nota**: Al actualizar el servicio de Windows se pueden activar reglas de seguridad de 360 o Huorong, lo que impide que los archivos nuevos se reemplacen con normalidad. En ese caso, puede reemplazar los archivos manualmente. Quienes estén familiarizados con este tema pueden ayudar a determinar el método de gestión correcto.

## Documentación en línea

[Documentación en línea](https://doc.samwaf.com/)

# Información del código
## Repositorio de código
- Gitee
[https://gitee.com/samwaf/SamWaf](https://gitee.com/samwaf/SamWaf)
- GitHub
[https://github.com/samwafgo/SamWaf](https://github.com/samwafgo/SamWaf)
- Atomgit
[https://atomgit.com/SamSafe/SamWaf](https://atomgit.com/SamSafe/SamWaf)

## Introducción y compilación
Cómo compilar
[Instrucciones de compilación](./docs/compile.md)

Manual de compilación en línea:
[https://doc.samwaf.com/en/dev/](https://doc.samwaf.com/en/dev/)

## Plataformas probadas y compatibles
[Plataformas probadas y compatibles](./docs/Tested_supported_systems.md)

## Otra información 

- [Actualizar la base de datos de IP](./docs/ipmodify.md)

## Resultados de las pruebas
[Resultados de las pruebas](./test/attackTest.md)

# Política de seguridad
[Política de seguridad](./SECURITY.md)

# Comentarios
SamWaf está en continua iteración. Agradecemos sus comentarios y sugerencias.

- [Issues en Gitee](https://gitee.com/samwaf/SamWaf/issues)
- [Issues en GitHub](https://github.com/samwafgo/SamWaf/issues)
- [Issues en Atomgit](https://atomgit.com/SamSafe/SamWaf/issues)
- Comentarios por correo electrónico: samwafgo@gmail.com

# Cuenta pública de WeChat

<img alt="SamWaf" width="400px"  src="./docs/images/mp_samwaf.png"> 

## Historial de estrellas

[![Gráfico del historial de estrellas](https://api.star-history.com/svg?repos=samwafgo/samwaf&type=Date)](https://star-history.com/#samwafgo/samwaf&Date)


#  Licencia
SamWaf está licenciado bajo la Apache License 2.0. Consulte [LICENSE](./LICENSE) para obtener más detalles.

Para el aviso sobre el uso de software de terceros, consulte [ThirdLicense](./ThirdLicense)

# Contribución
 ¡Gracias a los siguientes colaboradores!

<a href="https://github.com/samwafgo/SamWaf/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=samwafgo/SamWaf" />
</a>
