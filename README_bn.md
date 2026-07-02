[English](README.md) | [简体中文](README_cn.md) | [Español](README_es.md) | [हिन्दी](README_hi.md) | [العربية](README_ar.md) | [Français](README_fr.md) | [Português](README_pt.md) | [Русский](README_ru.md) | [বাংলা](README_bn.md) | [اردو](README_ur.md) | [日本語](README_ja.md) | [Deutsch](README_de.md) | [Bahasa Indonesia](README_id.md) | [한국어](README_ko.md)


<div align="center">
 <img alt="SamWaf" width="100" src="./docs/images/logo.png"> 

একটি লাইটওয়েট ওপেন-সোর্স web application firewall

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

  
## ডেভেলপমেন্টের অনুপ্রেরণা:
- **লাইটওয়েট**: শুরুর দিকে আমি সুরক্ষার জন্য nginx, apache ও iis প্লাগইনভিত্তিক কিছু সিকিউরিটি প্রোডাক্ট ব্যবহার করতাম, কিন্তু প্লাগইন-নির্ভর এই রূপে কাপলিংয়ের মাত্রা ছিল অনেক বেশি।
- **প্রাইভেট ডিপ্লয়মেন্ট**: পরবর্তীতে বেশিরভাগ ক্ষেত্রে ক্লাউডভিত্তিক সুরক্ষা সেবা গ্রহণ করা হয়, কিন্তু প্রাইভেট ডিপ্লয়মেন্টের খরচ কেবল মাঝারি ও বড় প্রতিষ্ঠানের পক্ষেই বহনযোগ্য; ছোট কোম্পানি ও স্টুডিওর কাছে তা ব্যয়বহুল।
- **প্রাইভেসি এনক্রিপশন**: ওয়েব সুরক্ষার সময় ডেটা ক্লাউডে না পাঠিয়ে লোকালভাবে প্রক্রিয়া করাই শ্রেয়। লক্ষ্য ছিল এমন একটি টুল তৈরি করা, যা লোকাল তথ্য এনক্রিপ্ট করে এবং ম্যানেজমেন্ট প্রান্তের নেটওয়ার্ক যোগাযোগও এনক্রিপ্ট করে।
- **DIY**: বছরের পর বছর ধরে ওয়েবসাইট রক্ষণাবেক্ষণ ও ডেভেলপমেন্ট করতে গিয়ে এমন কিছু নির্দিষ্ট ফিচার যোগ করতে চেয়েছিলাম, যা তখন বাস্তবায়ন করা সম্ভব হয়নি।
- **সচেতনতা**: ওয়েবমাস্টার যদি আগে কখনো এ ধরনের WAF ব্যবহার না করে থাকেন, তাহলে শুধু লগ কিংবা nginx, apache, IIS ইত্যাদি থেকে কে সাইটে প্রবেশ করছে এবং কী ধরনের রিকোয়েস্ট করা হচ্ছে তা বোঝা বেশ অসুবিধাজনক।

সংক্ষেপে, লক্ষ্য ছিল ওয়েবসাইট বা API সুরক্ষার জন্য এমন একটি কার্যকর টুল তৈরি করা, যা অস্বাভাবিক পরিস্থিতি সামলে ওয়েবসাইট ও অ্যাপ্লিকেশনের স্বাভাবিক কার্যক্রম নিশ্চিত করে।

# সফটওয়্যার পরিচিতি
SamWaf হলো ছোট কোম্পানি, স্টুডিও ও ব্যক্তিগত ওয়েবসাইটের জন্য একটি লাইটওয়েট, ওপেন-সোর্স web application firewall। এটি সম্পূর্ণ প্রাইভেট ডিপ্লয়মেন্ট সমর্থন করে, ডেটা এনক্রিপ্ট করে লোকালভাবে সংরক্ষণ করে, সহজে চালু করা যায় এবং Linux, Windows 64-bit ও ARM64 সমর্থন করে; Docker ইমেজও রয়েছে। ডিফল্টভাবে এটি কোনো এক্সটার্নাল ডিপেন্ডেন্সি ছাড়াই এমবেডেড এনক্রিপ্টেড SQLite ডেটাবেস ব্যবহার করে, আর চাইলে ঐচ্ছিকভাবে MySQL-এ স্যুইচ করা যায়।

## আর্কিটেকচার

![SamWaf আর্কিটেকচার](./docs/images_en/tecDesign.svg)

## ইন্টারফেস
![SamWaf web application firewall ওভারভিউ](/docs/images_en/overview.png)

<table>
    <tr>
        <td align="center">হোস্ট যোগ করা</td>
        <td align="center">অ্যাটাক লগ</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/add_host.png" alt="হোস্ট যোগ করা"/></td>
        <td><img src="./docs/images_en/attacklog.png" alt="অ্যাটাক লগ"/></td>
    </tr>
    <tr>
        <td align="center">CC</td>
        <td align="center">IP ব্লকলিস্ট</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/cc.png" alt="CC"/></td>
        <td><img src="./docs/images_en/ipblock.png" alt="IP ব্লকলিস্ট"/></td>
    </tr>
    <tr>
        <td align="center">IP অ্যালাউলিস্ট</td>
        <td align="center">LDP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/ipallow.png" alt="IP অ্যালাউলিস্ট"/></td>
        <td><img src="./docs/images_en/ldp.png" alt="LDP"/></td>
    </tr>
    <tr>
        <td align="center">রুল স্ক্রিপ্ট লগ যোগ করা</td>
        <td align="center">লগ নির্বাচন</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/log_add_rule_script.png" alt="রুল স্ক্রিপ্ট লগ যোগ করা"/></td>
        <td><img src="./docs/images_en/log_select.png" alt="লগ নির্বাচন"/></td>
    </tr>
    <tr>
        <td align="center">লগের বিস্তারিত</td>
        <td align="center">ম্যানুয়াল রুল</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/logdetail.png" alt="লগের বিস্তারিত"/></td>
        <td><img src="./docs/images_en/manual_rule.png" alt="ম্যানুয়াল রুল"/></td>
    </tr>
    <tr>
        <td align="center">URL ব্লকলিস্ট</td>
        <td align="center">URL অ্যালাউলিস্ট</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/urlblock.png" alt="URL ব্লকলিস্ট"/></td>
        <td><img src="./docs/images_en/urlallow.png" alt="URL অ্যালাউলিস্ট"/></td>
    </tr>
</table>

## প্রধান বৈশিষ্ট্য

### বেসিক
- সম্পূর্ণ ওপেন-সোর্স কোড (Apache 2.0)
- সম্পূর্ণ প্রাইভেট ডিপ্লয়মেন্ট; ডেটা এনক্রিপ্ট করে শুধুমাত্র লোকালেই সংরক্ষণ করা হয়
- সিঙ্গেল-ফাইল এক-ক্লিক স্টার্ট, লাইটওয়েট — কোনো থার্ড-পার্টি সার্ভিস ডিপেন্ডেন্সি নেই (MySQL/Redis ঐচ্ছিক)
- সম্পূর্ণ স্বাধীন ইঞ্জিন; সুরক্ষা IIS বা Nginx-এর উপর নির্ভর করে না
- IPv6 সমর্থন

### ট্রাফিক অ্যাক্সেস
- HTTP/1.1, HTTP/2 এবং HTTP/3 (QUIC) সমর্থন
- WebSocket ফরওয়ার্ডিং
- লোড ব্যালেন্সিংসহ reverse proxy (weighted round-robin, IP hash, least connections); হেলথ চেকের মাধ্যমে সমস্যাযুক্ত ব্যাকএন্ড স্বয়ংক্রিয়ভাবে বাদ দেওয়া হয়
- পাথ রুল: পাথ-প্রতি reverse proxy, স্ট্যাটিক ফাইল অথবা 301/302 রিডাইরেক্ট; ব্যাকএন্ড প্রোটোকল ও রেসপন্স টাইমআউট কনফিগারযোগ্য
- স্ট্যাটিক সাইট সার্ভিং
- TCP/UDP লেয়ার-4 টানেল ফরওয়ার্ডিং (IP অ্যাক্সেস কন্ট্রোল ও টাইম-উইন্ডো নিয়ন্ত্রণসহ)
- ওয়েব পেজ ক্যাশিং
- সাইট অ্যাক্সেসের জন্য HTTP Basic Auth
- কাস্টমাইজযোগ্য ব্লকিং পেজ

### আক্রমণ থেকে সুরক্ষা
- SQL injection শনাক্তকরণ
- XSS (cross-site scripting) শনাক্তকরণ
- RCE (remote command execution) শনাক্তকরণ
- স্ক্যানার টুল শনাক্তকরণ
- Path traversal শনাক্তকরণ
- ফাইল আপলোড শনাক্তকরণ (বিপজ্জনক এক্সটেনশন, webshell সিগনেচার, স্পুফ করা Content-Type)
- CC / রেট-লিমিট সুরক্ষা
- ভুয়া ক্রলার / বট শনাক্তকরণ (সার্চ-ইঞ্জিন বটের reverse-DNS যাচাই)
- অ্যান্টি-লিচ (হটলিংক সুরক্ষা)
- CSRF সুরক্ষা (সাইট-প্রতি Origin/Referer যাচাই)
- সংবেদনশীল শব্দ ফিল্টারিং
- OWASP CRS রুল সেট সমর্থন (Coraza ইঞ্জিন; রুল চালু/বন্ধ/ওভাররাইড করা যায়)
- কাস্টমাইজযোগ্য সুরক্ষা রুল — স্ক্রিপ্ট ও GUI উভয় মাধ্যমেই সম্পাদনাযোগ্য
- হিউম্যান ভেরিফিকেশন: ক্লিক CAPTCHA এবং Cap.js proof-of-work
- লগ-অনলি মোড: ব্লক না করে আক্রমণ রেকর্ড করে; রুল পর্যবেক্ষণ ও টিউন করার জন্য উপযোগী

### অ্যাক্সেস নিয়ন্ত্রণ
- IP অ্যালাউলিস্ট / ব্লকলিস্ট
- URL অ্যালাউলিস্ট / ব্লকলিস্ট
- জিও ব্লকিং (বিল্ট-ইন অফলাইন ip2region/GeoIP2 ডেটাবেস, IPv4/IPv6)
- OS firewall-এর সাথে সংযুক্ত IP ব্যান
- কোনো IP-এর ব্যর্থতার সংখ্যা নির্দিষ্ট সীমায় পৌঁছালে স্বয়ংক্রিয় ব্যান
- গ্লোবাল এক-ক্লিক কনফিগারেশন এবং সাইট-প্রতি সুরক্ষা কৌশল

### ডেটা নিরাপত্তা
- এনক্রিপ্টেড লগ স্টোরেজ
- এনক্রিপ্টেড কমিউনিকেশন লগ
- ডেটা মাস্কিং (DLP) — নির্ধারিত ডেটা প্রাইভেসি আউটপুটসহ
- ওয়েব পেজ অ্যান্টি-ট্যাম্পার (বেসলাইন লার্নিং + স্বয়ংক্রিয় পুনরুদ্ধার)
- Cookie নিরাপত্তা হার্ডেনিং (HttpOnly/Secure/SameSite)

### SSL সার্টিফিকেট
- স্বয়ংক্রিয় SSL সার্টিফিকেট আবেদন ও নবায়ন (ACME, EAB সমর্থনসহ মাল্টি-CA)
- SNI মাল্টি-সার্টিফিকেট ও মাল্টি-পোর্ট HTTPS
- SSL সার্টিফিকেটের মেয়াদোত্তীর্ণতা বাল্ক আকারে যাচাই
- স্বয়ংক্রিয় সার্টিফিকেট লোডিং

### অপারেশন ও ম্যানেজমেন্ট
- অ্যাকাউন্ট RBAC, OTP টু-ফ্যাক্টর অথেনটিকেশন, লগইন/অপারেশন লগ
- পরিসংখ্যান রিপোর্ট এবং সিস্টেম/হোস্ট মনিটরিং
- স্বয়ংক্রিয় লগ শার্ডিং ও আর্কাইভিংসহ ডেটা রিটেনশন নীতি
- ডিফল্টভাবে SQLite (এনক্রিপ্টেড), ঐচ্ছিকভাবে MySQL; সাথে বিল্ট-ইন SQLite→MySQL মাইগ্রেশন টুল
- অনলাইন এক-ক্লিক আপগ্রেড, জিরো-ডাউনটাইম রোলিং রিস্টার্ট এবং ভার্সন রোলব্যাক
- ব্যাচ টাস্ক, শিডিউলড টাস্ক এবং ডেটা ব্যাকআপ
- ওপেন API

### নোটিফিকেশন
- ইমেইল, DingTalk, Feishu, WeCom (WeChat Work), ServerChan, Webhook, Kafka, RabbitMQ এবং লগ-ফাইল ডেলিভারি চ্যানেল

# ব্যবহারের নির্দেশনা
**প্রোডাকশনে ডিপ্লয় করার আগে টেস্ট এনভায়রনমেন্টে পুঙ্খানুপুঙ্খ পরীক্ষা চালানোর জোর সুপারিশ করা হচ্ছে। কোনো সমস্যা দেখা দিলে অনুগ্রহ করে দ্রুত ফিডব্যাক দিন।**
## সর্বশেষ সংস্করণ ডাউনলোড
Gitee:  [https://gitee.com/samwaf/SamWaf/releases](https://gitee.com/samwaf/SamWaf/releases)

GitHub: [https://github.com/samwafgo/SamWaf/releases](https://github.com/samwafgo/SamWaf/releases)

AtomGit: [https://atomgit.com/SamSafe/SamWaf/releases](https://atomgit.com/SamSafe/SamWaf/releases)

## দ্রুত শুরু

### Windows
- সরাসরি চালু করুন
```
SamWaf64.exe
```
- সার্ভিস হিসেবে চালান (Administrator প্রয়োজন)
```
//Install & Start
SamWaf64.exe install && SamWaf64.exe start

//Stop &  Uninstall 
SamWaf64.exe stop && SamWaf64.exe uninstall
``` 

### Linux
- ইনস্টল
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh install 
``` 

- আনইনস্টল
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
Docker সম্পর্কে আরও বিস্তারিত: https://hub.docker.com/r/samwaf/samwaf

ট্যাগ:
- **latest**: সর্বশেষ স্টেবল রিলিজ (প্রোডাকশনে ব্যবহারের জন্য সুপারিশকৃত)।
- **beta**: সর্বশেষ টেস্টিং সংস্করণ (নতুন ফিচার বা নির্দিষ্ট বাগ ফিক্স পরীক্ষা করা যায়)।

### কমান্ড-লাইন টুল

| Command | বিবরণ |
|---------|-------------|
| `install` / `uninstall` | সিস্টেম সার্ভিস ইনস্টল / আনইনস্টল করে |
| `start` / `stop` / `restart` | সার্ভিস চালু / বন্ধ / রিস্টার্ট করে |
| `rolling-restart` | জিরো-ডাউনটাইম রোলিং রিস্টার্ট (ট্রাফিকে ব্যাঘাত না ঘটিয়ে worker বদলে দেয়) |
| `resetpwd` | অ্যাডমিনিস্ট্রেটর পাসওয়ার্ড রিসেট করে |
| `resetotp` | সিকিউরিটি কোড (OTP) রিসেট করে |
| `repairdb` | ক্ষতিগ্রস্ত ডেটাবেস মেরামত করে |
| `execsql` | নির্বাচিত ডেটাবেসে SQL স্টেটমেন্ট চালায় |
| `migratedb` | অফলাইন ডেটাবেস মাইগ্রেশন SQLite → MySQL (শুধু আনুমানিক হিসাবের জন্য `--dry-run`, ওভাররাইট করার জন্য `--force`) |
| `rollback` | পূর্বের কোনো ব্যাকআপ সংস্করণে ফিরে যায় |

উদাহরণ: `SamWaf64.exe resetpwd` (Linux-এ: `./SamWafLinux64 resetpwd`)

## অ্যাক্সেস শুরু করুন

http://127.0.0.1:26666

ডিফল্ট অ্যাকাউন্ট: admin  ডিফল্ট পাসওয়ার্ড: admin868 (অনুগ্রহ করে প্রথম লগইনের সময়ই ডিফল্ট পাসওয়ার্ড পরিবর্তন করুন)


## আপগ্রেড গাইড

**দ্রষ্টব্য: আপগ্রেড প্রক্রিয়া চলাকালে সার্ভিস বন্ধ হয়ে যাবে, অনুগ্রহ করে অফ-পিক সময়ে আপগ্রেড করুন।**

### স্বয়ংক্রিয় আপগ্রেড
নতুন সংস্করণ পাওয়া গেলে নিশ্চিতকরণের জন্য একটি আপগ্রেড প্রম্পট আসবে, যার মাধ্যমে আপনি আপগ্রেড শুরু করতে পারবেন। আপগ্রেড সম্পন্ন হলে পেজটি স্বয়ংক্রিয়ভাবে রিফ্রেশ হবে।

### ম্যানুয়াল আপগ্রেড
- সরাসরি চালু করার ক্ষেত্রে:
    1. অ্যাপ্লিকেশনটি বন্ধ করুন।
    2. সর্বশেষ প্রোগ্রাম ডাউনলোড করে বিদ্যমান ফাইলগুলো প্রতিস্থাপন করুন, তারপর ম্যানুয়ালি আবার চালু করুন।

- সার্ভিস মোডের ক্ষেত্রে:
```
1. First, pause the service.

  Windows: SamWaf64.exe stop
  Linux: ./SamWafLinux64 stop
  
2. Replace with the latest application files.

3. Start the service:
Windows: SamWaf64.exe start
Linux: ./SamWafLinux64 start
```

**দ্রষ্টব্য**: Windows সার্ভিস আপগ্রেড করার সময় 360 বা Huorong-এর সিকিউরিটি রুল ট্রিগার হয়ে নতুন ফাইলগুলোর স্বাভাবিক প্রতিস্থাপন আটকে যেতে পারে। এ ক্ষেত্রে আপনি ম্যানুয়ালি ফাইলগুলো প্রতিস্থাপন করতে পারেন। এ বিষয়ে যাঁরা অভিজ্ঞ, তাঁরা সঠিক সমাধান নির্ধারণে সাহায্য করতে পারেন।

## অনলাইন ডকুমেন্টেশন

[অনলাইন ডকুমেন্টেশন](https://doc.samwaf.com/)

# কোড সংক্রান্ত তথ্য
## কোড রিপোজিটরি
- Gitee
[https://gitee.com/samwaf/SamWaf](https://gitee.com/samwaf/SamWaf)
- GitHub
[https://github.com/samwafgo/SamWaf](https://github.com/samwafgo/SamWaf)
- Atomgit
[https://atomgit.com/SamSafe/SamWaf](https://atomgit.com/SamSafe/SamWaf)

## পরিচিতি ও কম্পাইলেশন
কীভাবে কম্পাইল করবেন
[কম্পাইলেশন নির্দেশনা](./docs/compile.md)

কম্পাইলেশনের অনলাইন ম্যানুয়াল：
[https://doc.samwaf.com/en/dev/](https://doc.samwaf.com/en/dev/)

## পরীক্ষিত ও সমর্থিত প্ল্যাটফর্ম
[পরীক্ষিত ও সমর্থিত প্ল্যাটফর্ম](./docs/Tested_supported_systems.md)

## অন্যান্য তথ্য 

- [IP ডেটাবেস আপডেট](./docs/ipmodify.md)

## পরীক্ষার ফলাফল
[পরীক্ষার ফলাফল](./test/attackTest.md)

# নিরাপত্তা নীতি
[নিরাপত্তা নীতি](./SECURITY.md)

# ফিডব্যাক
SamWaf ধারাবাহিকভাবে উন্নত হচ্ছে। আমরা ফিডব্যাক ও পরামর্শ সাদরে গ্রহণ করি।

- [Gitee Issues](https://gitee.com/samwaf/SamWaf/issues)
- [GitHub Issues](https://github.com/samwafgo/SamWaf/issues)
- [Atomgit Issues](https://atomgit.com/SamSafe/SamWaf/issues)
- ইমেইল ফিডব্যাক: samwafgo@gmail.com

# WeChat পাবলিক অ্যাকাউন্ট

<img alt="SamWaf" width="400px"  src="./docs/images/mp_samwaf.png"> 

## স্টার হিস্টরি

[![স্টার হিস্টরি চার্ট](https://api.star-history.com/svg?repos=samwafgo/samwaf&type=Date)](https://star-history.com/#samwafgo/samwaf&Date)


#  লাইসেন্স
SamWaf Apache License 2.0-এর অধীনে লাইসেন্সকৃত। আরও বিস্তারিত জানতে [LICENSE](./LICENSE) দেখুন।

থার্ড-পার্টি সফটওয়্যার ব্যবহারের নোটিশের জন্য দেখুন [ThirdLicense](./ThirdLicense)

# অবদান
 নিচের অবদানকারীদের সবাইকে ধন্যবাদ!

<a href="https://github.com/samwafgo/SamWaf/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=samwafgo/SamWaf" />
</a>
