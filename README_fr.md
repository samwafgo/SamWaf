[English](README.md) | [简体中文](README_cn.md) | [Español](README_es.md) | [हिन्दी](README_hi.md) | [العربية](README_ar.md) | [Français](README_fr.md) | [Português](README_pt.md) | [Русский](README_ru.md) | [বাংলা](README_bn.md) | [اردو](README_ur.md) | [日本語](README_ja.md) | [Deutsch](README_de.md) | [Bahasa Indonesia](README_id.md) | [한국어](README_ko.md)


<div align="center">
 <img alt="SamWaf" width="100" src="./docs/images/logo.png"> 

Un pare-feu applicatif web léger et open source

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

  
## Motivation du développement :
- **Légèreté** : au départ, j'utilisais pour la protection des produits de sécurité basés sur des plugins nginx, apache et iis, mais cette forme de plugin présentait un fort couplage.
- **Privatisation** : par la suite, la plupart des services de protection cloud ont été adoptés, mais le déploiement privé n'est abordable que pour les moyennes et grandes entreprises, tandis que les petites sociétés et les studios le trouvent coûteux.
- **Chiffrement et confidentialité** : lors de la protection web, il est préférable de traiter les données en local sans les envoyer vers le cloud. L'objectif était de créer un outil qui chiffre les informations locales et les communications réseau de l'interface d'administration.
- **DIY** : au fil des années de maintenance et de développement de sites web, il y avait des fonctions précises que je souhaitais ajouter sans pouvoir y parvenir.
- **Visibilité** : si le webmaster n'a jamais utilisé de WAF similaire, il est peu pratique de comprendre qui accède au site et quelles requêtes sont effectuées en se basant uniquement sur les journaux ou sur nginx, apache, IIS, etc.

En résumé, l'objectif était de créer un outil efficace de protection des sites web ou des API, capable de gérer les situations anormales et d'assurer le fonctionnement normal des sites et des applications.

# Présentation du logiciel
SamWaf est un pare-feu applicatif web (WAF) léger et open source destiné aux petites entreprises, aux studios et aux sites web personnels. Il prend en charge un déploiement entièrement privé, chiffre les données stockées en local, se lance facilement et fonctionne sous Linux, Windows 64 bits et ARM64, avec des images Docker disponibles. Par défaut, il utilise une base de données SQLite embarquée et chiffrée, sans aucune dépendance externe, et peut en option basculer vers MySQL / PostgreSQL.

## Architecture

![Architecture de SamWaf](./docs/images_en/tecDesign.svg)

## Interface
![Vue d'ensemble du pare-feu applicatif web SamWaf](/docs/images_en/overview.png)

<table>
    <tr>
        <td align="center">Ajouter un hôte</td>
        <td align="center">Journal des attaques</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/add_host.png" alt="Ajouter un hôte"/></td>
        <td><img src="./docs/images_en/attacklog.png" alt="Journal des attaques"/></td>
    </tr>
    <tr>
        <td align="center">CC</td>
        <td align="center">Liste de blocage IP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/cc.png" alt="CC"/></td>
        <td><img src="./docs/images_en/ipblock.png" alt="Liste de blocage IP"/></td>
    </tr>
    <tr>
        <td align="center">Liste d'autorisation IP</td>
        <td align="center">LDP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/ipallow.png" alt="Liste d'autorisation IP"/></td>
        <td><img src="./docs/images_en/ldp.png" alt="LDP"/></td>
    </tr>
    <tr>
        <td align="center">Journal d'ajout de script de règle</td>
        <td align="center">Sélection des journaux</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/log_add_rule_script.png" alt="Journal d'ajout de script de règle"/></td>
        <td><img src="./docs/images_en/log_select.png" alt="Sélection des journaux"/></td>
    </tr>
    <tr>
        <td align="center">Détails du journal</td>
        <td align="center">Règle manuelle</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/logdetail.png" alt="Détails du journal"/></td>
        <td><img src="./docs/images_en/manual_rule.png" alt="Règle manuelle"/></td>
    </tr>
    <tr>
        <td align="center">Liste de blocage d'URL</td>
        <td align="center">Liste d'autorisation d'URL</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/urlblock.png" alt="Liste de blocage d'URL"/></td>
        <td><img src="./docs/images_en/urlallow.png" alt="Liste d'autorisation d'URL"/></td>
    </tr>
</table>

## Fonctionnalités principales

### Fondamentaux
- Code entièrement open source (Apache 2.0)
- Déploiement entièrement privé ; les données sont chiffrées et stockées uniquement en local
- Démarrage en un clic à partir d'un fichier unique, léger et sans dépendance à des services tiers (MySQL/Redis sont optionnels)
- Moteur totalement indépendant ; la protection ne repose ni sur IIS ni sur Nginx
- Prise en charge d'IPv6

### Accès au trafic
- Prise en charge de HTTP/1.1, HTTP/2 et HTTP/3 (QUIC)
- Transfert WebSocket
- Proxy inverse avec équilibrage de charge (round-robin pondéré, hachage d'IP, moindres connexions) ; les contrôles de santé retirent automatiquement les backends défaillants
- Règles de chemin : proxy inverse par chemin, fichiers statiques ou redirection 301/302, avec protocole backend et délai de réponse configurables
- Hébergement de sites statiques
- Transfert par tunnel de niveau 4 TCP/UDP (avec contrôle d'accès par IP et contrôle par plage horaire)
- Mise en cache des pages web
- Authentification HTTP Basic pour l'accès au site
- Page de blocage personnalisable

### Protection contre les attaques
- Détection des injections SQL
- Détection XSS (cross-site scripting)
- Détection RCE (exécution de commandes à distance)
- Détection des outils de scan
- Détection de la traversée de chemins
- Détection des téléversements de fichiers (extensions dangereuses, signatures de webshell, Content-Type falsifié)
- Protection CC / limitation de débit
- Détection des faux robots d'indexation (vérification par DNS inverse des robots des moteurs de recherche)
- Protection contre le hotlinking (anti-leech)
- Protection CSRF (validation Origin/Referer par site)
- Filtrage des mots sensibles
- Prise en charge du jeu de règles OWASP CRS (moteur Coraza ; les règles peuvent être activées, désactivées ou surchargées)
- Règles de protection personnalisables, éditables par script ou via l'interface graphique
- Vérification humaine : CAPTCHA par clic et preuve de travail Cap.js
- Mode journalisation seule : enregistre les attaques sans les bloquer, utile pour observer et affiner les règles

### Contrôle d'accès
- Liste d'autorisation / de blocage IP
- Liste d'autorisation / de blocage d'URL
- Blocage géographique (bases de données hors ligne intégrées ip2region/GeoIP2, IPv4/IPv6)
- Bannissement d'IP couplé au pare-feu du système d'exploitation
- Bannissement automatique lorsque le nombre d'échecs d'une IP atteint un seuil
- Configuration globale en un clic et stratégies de protection par site

### Sécurité des données
- Stockage chiffré des journaux
- Journaux de communication chiffrés
- Masquage des données (DLP) avec sortie désignée des données confidentielles
- Anti-falsification des pages web (apprentissage d'une base de référence + restauration automatique)
- Renforcement de la sécurité des cookies (HttpOnly/Secure/SameSite)

### Certificats SSL
- Demande et renouvellement automatiques des certificats SSL (ACME, multi-CA avec prise en charge d'EAB)
- Multi-certificats SNI et HTTPS multi-ports
- Vérification en masse de l'expiration des certificats SSL
- Chargement automatique des certificats

### Exploitation et administration
- RBAC pour les comptes, authentification à deux facteurs OTP, journaux de connexion et d'opérations
- Rapports statistiques et supervision du système et des hôtes
- Politique de conservation des données avec partitionnement et archivage automatiques des journaux
- SQLite (chiffré) par défaut, MySQL / PostgreSQL en option, avec un outil intégré de migration SQLite→MySQL / SQLite→PostgreSQL / MySQL→PostgreSQL
- Mise à niveau en ligne en un clic, redémarrage progressif sans interruption de service et retour à une version antérieure
- Tâches par lots, tâches planifiées et sauvegarde des données
- API ouverte

### Notifications
- Canaux de notification : e-mail, DingTalk, Feishu, WeCom (WeChat Work), ServerChan, Webhook, Kafka, RabbitMQ et fichier journal

# Instructions d'utilisation
**Il est fortement recommandé d'effectuer des tests approfondis dans un environnement de test avant tout déploiement en production. En cas de problème, merci de nous faire un retour rapidement.**
## Télécharger la dernière version
Gitee:  [https://gitee.com/samwaf/SamWaf/releases](https://gitee.com/samwaf/SamWaf/releases)

GitHub: [https://github.com/samwafgo/SamWaf/releases](https://github.com/samwafgo/SamWaf/releases)

AtomGit: [https://atomgit.com/SamSafe/SamWaf/releases](https://atomgit.com/SamSafe/SamWaf/releases)

## Démarrage rapide

### Windows
- Démarrage direct
```
SamWaf64.exe
```
- Exécution en tant que service (nécessite les droits d'administrateur)
```
//Install & Start
SamWaf64.exe install && SamWaf64.exe start

//Stop &  Uninstall 
SamWaf64.exe stop && SamWaf64.exe uninstall
``` 

### Linux
- installation
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh install 
``` 

- désinstallation
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
Plus de détails sur Docker : https://hub.docker.com/r/samwaf/samwaf

Tags :
- **latest** : la dernière version stable (recommandée pour un usage en production).
- **beta** : la dernière version de test (permet de tester de nouvelles fonctionnalités ou des correctifs de bugs spécifiques).

### Outils en ligne de commande

| Command | Description |
|---------|-------------|
| `install` / `uninstall` | Installer / désinstaller le service système |
| `start` / `stop` / `restart` | Démarrer / arrêter / redémarrer le service |
| `rolling-restart` | Redémarrage progressif sans interruption (remplace le worker sans interrompre le trafic) |
| `resetpwd` | Réinitialiser le mot de passe administrateur |
| `resetotp` | Réinitialiser le code de sécurité (OTP) |
| `repairdb` | Réparer une base de données corrompue |
| `execsql` | Exécuter des instructions SQL sur une base de données sélectionnée |
| `migratedb` | Migration hors ligne de la base de données SQLite → MySQL / SQLite → PostgreSQL / MySQL → PostgreSQL (`--dry-run` pour une simple estimation, `--force` pour écraser) |
| `rollback` | Revenir à une version de sauvegarde antérieure |

Exemple : `SamWaf64.exe resetpwd` (sous Linux : `./SamWafLinux64 resetpwd`)

## Accès après démarrage

http://127.0.0.1:26666

Compte par défaut : admin  Mot de passe initial : les nouvelles installations génèrent automatiquement un mot de passe aléatoire enregistré dans `data/initial_password.txt` (les installations existantes conservent leur mot de passe précédent ; veuillez le modifier dès la première connexion)


## Guide de mise à niveau

**Remarque : le processus de mise à niveau interrompt le service ; veuillez effectuer la mise à niveau pendant les heures creuses.**

### Mise à niveau automatique
Si une nouvelle version est disponible, une invite de mise à niveau s'affiche pour confirmation et vous permet de lancer la mise à niveau. La page se rafraîchit automatiquement une fois la mise à niveau terminée.

### Mise à niveau manuelle
- Pour un lancement direct :
    1. Fermez l'application.
    2. Téléchargez la dernière version du programme et remplacez les fichiers existants, puis redémarrez-la manuellement.

- Pour le mode service :
```
1. First, pause the service.

  Windows: SamWaf64.exe stop
  Linux: ./SamWafLinux64 stop
  
2. Replace with the latest application files.

3. Start the service:
Windows: SamWaf64.exe start
Linux: ./SamWafLinux64 start
```

**Remarque** : la mise à niveau du service Windows peut déclencher des règles de sécurité de 360 ou de Huorong, empêchant le remplacement normal des nouveaux fichiers. Dans ce cas, vous pouvez remplacer les fichiers manuellement. Les personnes familières de ce domaine sauront déterminer la méthode de traitement appropriée.

## Documentation en ligne

[Documentation en ligne](https://doc.samwaf.com/)

# Informations sur le code
## Dépôt de code
- Gitee
[https://gitee.com/samwaf/SamWaf](https://gitee.com/samwaf/SamWaf)
- GitHub
[https://github.com/samwafgo/SamWaf](https://github.com/samwafgo/SamWaf)
- Atomgit
[https://atomgit.com/SamSafe/SamWaf](https://atomgit.com/SamSafe/SamWaf)

## Présentation et compilation
Comment compiler
[Instructions de compilation](./docs/compile.md)

Manuel de compilation en ligne :
[https://doc.samwaf.com/en/dev/](https://doc.samwaf.com/en/dev/)

## Plateformes testées et prises en charge
[Plateformes testées et prises en charge](./docs/Tested_supported_systems.md)

## Autres informations 

- [Mettre à jour la base de données IP](./docs/ipmodify.md)

## Résultats des tests
[Résultats des tests](./test/attackTest.md)

# Politique de sécurité
[Politique de sécurité](./SECURITY.md)

# Retours
SamWaf évolue en permanence. Vos retours et suggestions sont les bienvenus.

- [Issues Gitee](https://gitee.com/samwaf/SamWaf/issues)
- [Issues GitHub](https://github.com/samwafgo/SamWaf/issues)
- [Issues Atomgit](https://atomgit.com/SamSafe/SamWaf/issues)
- Retour par e-mail : samwafgo@gmail.com

# Compte officiel WeChat

<img alt="SamWaf" width="400px"  src="./docs/images/mp_samwaf.png"> 

## Historique des stars

[![Graphique de l'historique des stars](https://api.star-history.com/svg?repos=samwafgo/samwaf&type=Date)](https://star-history.com/#samwafgo/samwaf&Date)


#  Licence
SamWaf est distribué sous licence Apache License 2.0. Consultez [LICENSE](./LICENSE) pour plus de détails.

Pour les mentions relatives à l'utilisation de logiciels tiers, voir [ThirdLicense](./ThirdLicense)

# Contribution
 Merci aux contributeurs suivants !

<a href="https://github.com/samwafgo/SamWaf/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=samwafgo/SamWaf" />
</a>
