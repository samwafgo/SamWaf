[English](README.md) | [简体中文](README_cn.md) | [Español](README_es.md) | [हिन्दी](README_hi.md) | [العربية](README_ar.md) | [Français](README_fr.md) | [Português](README_pt.md) | [Русский](README_ru.md) | [বাংলা](README_bn.md) | [اردو](README_ur.md) | [日本語](README_ja.md) | [Deutsch](README_de.md) | [Bahasa Indonesia](README_id.md) | [한국어](README_ko.md)


<div align="center">
 <img alt="SamWaf" width="100" src="./docs/images/logo.png"> 

ایک ہلکی پھلکی اوپن سورس ویب ایپلیکیشن فائر وال

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

  
## ڈویلپمنٹ کا محرک:
- **ہلکا پھلکا**: ابتدا میں، میں نے تحفظ کے لیے nginx، apache اور iis پلگ اِنز پر مبنی کچھ سیکیورٹی پروڈکٹس استعمال کیں، لیکن پلگ اِن کی شکل میں کپلنگ (باہمی انحصار) کی سطح بہت زیادہ تھی۔
- **نجی تنصیب**: بعد ازاں زیادہ تر کلاؤڈ پروٹیکشن سروسز اپنائی گئیں، لیکن پرائیویٹ ڈیپلائمنٹ صرف درمیانے اور بڑے اداروں کے لیے قابلِ برداشت ہے، جبکہ چھوٹی کمپنیوں اور اسٹوڈیوز کے لیے یہ مہنگی ثابت ہوتی ہے۔
- **پرائیویسی انکرپشن**: ویب پروٹیکشن کے دوران بہتر یہی ہے کہ مقامی ڈیٹا کو کلاؤڈ پر بھیجے بغیر پروسیس کیا جائے۔ مقصد ایک ایسا ٹول بنانا تھا جو مقامی معلومات اور مینجمنٹ اینڈ کی نیٹ ورک کمیونیکیشن کو انکرپٹ کرے۔
- **DIY**: برسوں کی ویب سائٹ مینٹیننس اور ڈویلپمنٹ کے دوران کچھ مخصوص فیچرز ایسے تھے جنہیں میں شامل کرنا چاہتا تھا مگر نہیں کر پایا۔
- **آگاہی**: اگر ویب ماسٹر نے کبھی اس جیسا کوئی WAF استعمال نہ کیا ہو تو صرف لاگز یا nginx، apache، IIS وغیرہ کی مدد سے یہ سمجھنا مشکل ہوتا ہے کہ سائٹ تک کون رسائی حاصل کر رہا ہے اور کیسی درخواستیں بھیجی جا رہی ہیں۔

مختصراً، مقصد ویب سائٹ یا API کے تحفظ کے لیے ایک مؤثر ٹول بنانا تھا تاکہ غیر معمولی صورتِ حال سے نمٹا جا سکے اور ویب سائٹس اور ایپلیکیشنز کا معمول کے مطابق چلنا یقینی بنایا جا سکے۔

# سافٹ ویئر کا تعارف
SamWaf چھوٹی کمپنیوں، اسٹوڈیوز اور ذاتی ویب سائٹس کے لیے ایک ہلکی پھلکی، اوپن سورس ویب ایپلیکیشن فائر وال ہے۔ یہ مکمل طور پر نجی تنصیب کو سپورٹ کرتا ہے، ڈیٹا کو مقامی طور پر انکرپٹ کر کے محفوظ رکھتا ہے، آسانی سے شروع ہو جاتا ہے، اور Linux، Windows 64-bit اور ARM64 کو سپورٹ کرتا ہے؛ Docker امیجز بھی دستیاب ہیں۔ ڈیفالٹ طور پر یہ بغیر کسی بیرونی انحصار کے ایک ایمبیڈڈ انکرپٹڈ SQLite ڈیٹابیس استعمال کرتا ہے، اور اختیاری طور پر MySQL پر منتقل ہو سکتا ہے۔

## آرکیٹیکچر

![SamWaf آرکیٹیکچر](./docs/images_en/tecDesign.svg)

## انٹرفیس
![SamWaf ویب ایپلیکیشن فائر وال کا جائزہ](/docs/images_en/overview.png)

<table>
    <tr>
        <td align="center">ہوسٹ شامل کریں</td>
        <td align="center">حملوں کا لاگ</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/add_host.png" alt="ہوسٹ شامل کریں"/></td>
        <td><img src="./docs/images_en/attacklog.png" alt="حملوں کا لاگ"/></td>
    </tr>
    <tr>
        <td align="center">CC</td>
        <td align="center">IP بلاک لسٹ</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/cc.png" alt="CC"/></td>
        <td><img src="./docs/images_en/ipblock.png" alt="IP بلاک لسٹ"/></td>
    </tr>
    <tr>
        <td align="center">IP الاؤ لسٹ</td>
        <td align="center">LDP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/ipallow.png" alt="IP الاؤ لسٹ"/></td>
        <td><img src="./docs/images_en/ldp.png" alt="LDP"/></td>
    </tr>
    <tr>
        <td align="center">رول اسکرپٹ لاگ شامل کریں</td>
        <td align="center">لاگ منتخب کریں</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/log_add_rule_script.png" alt="رول اسکرپٹ لاگ شامل کریں"/></td>
        <td><img src="./docs/images_en/log_select.png" alt="لاگ منتخب کریں"/></td>
    </tr>
    <tr>
        <td align="center">لاگ کی تفصیلات</td>
        <td align="center">دستی رول</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/logdetail.png" alt="لاگ کی تفصیلات"/></td>
        <td><img src="./docs/images_en/manual_rule.png" alt="دستی رول"/></td>
    </tr>
    <tr>
        <td align="center">URL بلاک لسٹ</td>
        <td align="center">URL الاؤ لسٹ</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/urlblock.png" alt="URL بلاک لسٹ"/></td>
        <td><img src="./docs/images_en/urlallow.png" alt="URL الاؤ لسٹ"/></td>
    </tr>
</table>

## اہم خصوصیات

### بنیادی خصوصیات
- مکمل طور پر اوپن سورس کوڈ (Apache 2.0)
- مکمل نجی تنصیب؛ ڈیٹا انکرپٹ ہو کر صرف مقامی طور پر محفوظ ہوتا ہے
- سنگل فائل، ون کلک آغاز؛ ہلکا پھلکا اور کسی تھرڈ پارٹی سروس پر انحصار نہیں (MySQL/Redis اختیاری ہیں)
- مکمل طور پر خودمختار انجن؛ تحفظ IIS یا Nginx پر منحصر نہیں
- IPv6 سپورٹ

### ٹریفک رسائی
- HTTP/1.1، HTTP/2 اور HTTP/3 (QUIC) سپورٹ
- WebSocket فارورڈنگ
- لوڈ بیلنسنگ کے ساتھ ریورس پراکسی (ویٹڈ راؤنڈ رابن، IP ہیش، کم ترین کنکشنز)؛ ہیلتھ چیکس غیر صحت مند بیک اینڈز کو خودکار طور پر ہٹا دیتے ہیں
- پاتھ رولز: ہر پاتھ کے لیے ریورس پراکسی، اسٹیٹک فائلیں، یا 301/302 ری ڈائریکٹ، قابلِ ترتیب بیک اینڈ پروٹوکول اور رسپانس ٹائم آؤٹ کے ساتھ
- اسٹیٹک سائٹ سرونگ
- TCP/UDP لیئر-4 ٹنل فارورڈنگ (IP رسائی کنٹرول اور ٹائم ونڈو کنٹرول کے ساتھ)
- ویب پیج کیشنگ
- سائٹ تک رسائی کے لیے HTTP Basic Auth
- حسبِ ضرورت بلاکنگ پیج

### حملوں سے تحفظ
- SQL انجیکشن کی شناخت
- XSS (کراس سائٹ اسکرپٹنگ) کی شناخت
- RCE (ریموٹ کمانڈ ایگزیکیوشن) کی شناخت
- اسکینر ٹولز کی شناخت
- پاتھ ٹریورسل کی شناخت
- فائل اپ لوڈ کی جانچ (خطرناک ایکسٹینشنز، ویب شیل سگنیچرز، جعلی Content-Type)
- CC / ریٹ لمٹ تحفظ
- جعلی کرالر / بوٹ کی شناخت (سرچ انجن بوٹس کی ریورس DNS تصدیق)
- اینٹی لیچ (ہاٹ لنک سے تحفظ)
- CSRF تحفظ (ہر سائٹ کے لیے Origin/Referer کی توثیق)
- حساس الفاظ کی فلٹرنگ
- OWASP CRS رول سیٹ سپورٹ (Coraza انجن؛ رولز کو فعال/غیر فعال/اووررائیڈ کیا جا سکتا ہے)
- حسبِ ضرورت تحفظی رولز، اسکرپٹ اور GUI دونوں طرح کی ایڈیٹنگ کے ساتھ
- انسانی تصدیق: کلک CAPTCHA اور Cap.js پروف آف ورک
- صرف لاگ موڈ: حملوں کو بلاک کیے بغیر ریکارڈ کریں؛ رولز کے مشاہدے اور ٹیوننگ کے لیے مفید

### رسائی کنٹرول
- IP الاؤ لسٹ / بلاک لسٹ
- URL الاؤ لسٹ / بلاک لسٹ
- جیو بلاکنگ (بلٹ اِن آف لائن ip2region/GeoIP2 ڈیٹابیسز، IPv4/IPv6)
- آپریٹنگ سسٹم کے فائر وال سے منسلک IP پابندی
- کسی IP کی ناکامیوں کی تعداد مقررہ حد تک پہنچنے پر خودکار پابندی
- گلوبل ون کلک کنفیگریشن اور ہر سائٹ کے لیے الگ تحفظی حکمتِ عملی

### ڈیٹا سیکیورٹی
- انکرپٹڈ لاگ اسٹوریج
- انکرپٹڈ کمیونیکیشن لاگز
- ڈیٹا ماسکنگ (DLP) مخصوص ڈیٹا پرائیویسی آؤٹ پٹ کے ساتھ
- ویب پیج کی چھیڑ چھاڑ سے حفاظت (بیس لائن لرننگ + خودکار بحالی)
- کوکی سیکیورٹی ہارڈننگ (HttpOnly/Secure/SameSite)

### SSL سرٹیفکیٹس
- خودکار SSL سرٹیفکیٹ درخواست اور تجدید (ACME، EAB سپورٹ کے ساتھ ملٹی CA)
- SNI ملٹی سرٹیفکیٹ اور ملٹی پورٹ HTTPS
- SSL سرٹیفکیٹس کی میعاد ختم ہونے کی بلک جانچ
- خودکار سرٹیفکیٹ لوڈنگ

### آپریشنز اور مینجمنٹ
- اکاؤنٹ RBAC، OTP دو مرحلہ تصدیق، لاگ اِن/آپریشن لاگز
- شماریاتی رپورٹس اور سسٹم/ہوسٹ مانیٹرنگ
- خودکار لاگ شارڈنگ اور آرکائیونگ کے ساتھ ڈیٹا ریٹینشن پالیسی
- ڈیفالٹ طور پر SQLite (انکرپٹڈ)، اختیاری MySQL، اور بلٹ اِن SQLite→MySQL مائیگریشن ٹول
- آن لائن ون کلک اپ گریڈ، زیرو ڈاؤن ٹائم رولنگ ری اسٹارٹ، اور ورژن رول بیک
- بیچ ٹاسکس، شیڈولڈ ٹاسکس، اور ڈیٹا بیک اپ
- اوپن API

### اطلاعات
- ای میل، DingTalk، Feishu، WeCom (WeChat Work)، ServerChan، Webhook، Kafka، RabbitMQ اور لاگ فائل ڈیلیوری چینلز

# استعمال کی ہدایات
**پرزور سفارش کی جاتی ہے کہ پروڈکشن میں تعینات کرنے سے پہلے ٹیسٹ ماحول میں مکمل جانچ کر لیں۔ کوئی مسئلہ پیش آئے تو براہِ کرم فوری طور پر فیڈ بیک دیں۔**
## تازہ ترین ورژن ڈاؤن لوڈ کریں
Gitee:  [https://gitee.com/samwaf/SamWaf/releases](https://gitee.com/samwaf/SamWaf/releases)

GitHub: [https://github.com/samwafgo/SamWaf/releases](https://github.com/samwafgo/SamWaf/releases)

AtomGit: [https://atomgit.com/SamSafe/SamWaf/releases](https://atomgit.com/SamSafe/SamWaf/releases)

## فوری آغاز

### Windows
- براہِ راست شروع کریں
```
SamWaf64.exe
```
- بطور سروس چلائیں (Administrator اختیارات درکار ہیں)
```
//Install & Start
SamWaf64.exe install && SamWaf64.exe start

//Stop &  Uninstall 
SamWaf64.exe stop && SamWaf64.exe uninstall
``` 

### Linux
- انسٹال کریں
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh install 
``` 

- اَن انسٹال کریں
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
Docker کی مزید تفصیلات: https://hub.docker.com/r/samwaf/samwaf

ٹیگز:
- **latest**: تازہ ترین مستحکم ریلیز (پروڈکشن استعمال کے لیے تجویز کردہ)۔
- **beta**: تازہ ترین ٹیسٹنگ ورژن (نئے فیچرز یا مخصوص بگ فکسز کی جانچ کی سہولت دیتا ہے)۔

### کمانڈ لائن ٹولز

| Command | تفصیل |
|---------|-------------|
| `install` / `uninstall` | سسٹم سروس انسٹال / اَن انسٹال کریں |
| `start` / `stop` / `restart` | سروس شروع / بند / دوبارہ شروع کریں |
| `rolling-restart` | زیرو ڈاؤن ٹائم رولنگ ری اسٹارٹ (ٹریفک میں خلل ڈالے بغیر ورکر تبدیل کرتا ہے) |
| `resetpwd` | ایڈمنسٹریٹر پاس ورڈ ری سیٹ کریں |
| `resetotp` | سیکیورٹی کوڈ (OTP) ری سیٹ کریں |
| `repairdb` | خراب ڈیٹابیس کی مرمت کریں |
| `execsql` | منتخب ڈیٹابیس پر SQL اسٹیٹمنٹس چلائیں |
| `migratedb` | آف لائن ڈیٹابیس مائیگریشن SQLite → MySQL (صرف تخمینے کے لیے `--dry-run`، اوور رائٹ کرنے کے لیے `--force`) |
| `rollback` | پچھلے بیک اپ ورژن پر واپس جائیں |

مثال: `SamWaf64.exe resetpwd` (Linux پر: `./SamWafLinux64 resetpwd`)

## رسائی کا آغاز

http://127.0.0.1:26666

ڈیفالٹ اکاؤنٹ: admin  ڈیفالٹ پاس ورڈ: admin868 (براہِ کرم پہلی بار لاگ اِن کرتے ہی ڈیفالٹ پاس ورڈ تبدیل کر لیں)


## اپ گریڈ گائیڈ

**نوٹ: اپ گریڈ کے عمل کے دوران سروس بند ہو جائے گی، براہِ کرم کم رش کے اوقات میں اپ گریڈ کریں۔**

### خودکار اپ گریڈ
اگر نیا ورژن دستیاب ہو تو تصدیق کے لیے اپ گریڈ کا پرامپٹ ظاہر ہوگا، جس سے آپ اپ گریڈ شروع کر سکتے ہیں۔ اپ گریڈ مکمل ہونے کے بعد صفحہ خودکار طور پر ریفریش ہو جائے گا۔

### دستی اپ گریڈ
- براہِ راست چلانے کی صورت میں:
    1. ایپلیکیشن بند کریں۔
    2. تازہ ترین پروگرام ڈاؤن لوڈ کر کے موجودہ فائلوں کو تبدیل کریں، پھر اسے دوبارہ دستی طور پر شروع کریں۔

- سروس موڈ کی صورت میں:
```
1. First, pause the service.

  Windows: SamWaf64.exe stop
  Linux: ./SamWafLinux64 stop
  
2. Replace with the latest application files.

3. Start the service:
Windows: SamWaf64.exe start
Linux: ./SamWafLinux64 start
```

**نوٹ**: Windows سروس کو اپ گریڈ کرنے پر 360 یا Huorong کے سیکیورٹی رولز متحرک ہو سکتے ہیں، جس کی وجہ سے نئی فائلیں معمول کے مطابق تبدیل نہیں ہو پاتیں۔ ایسی صورت میں آپ فائلیں دستی طور پر تبدیل کر سکتے ہیں۔ اس شعبے سے واقفیت رکھنے والے افراد درست طریقۂ کار کے تعین میں مدد کر سکتے ہیں۔

## آن لائن دستاویزات

[آن لائن دستاویزات](https://doc.samwaf.com/)

# کوڈ کی معلومات
## کوڈ ریپوزٹری
- Gitee
[https://gitee.com/samwaf/SamWaf](https://gitee.com/samwaf/SamWaf)
- GitHub
[https://github.com/samwafgo/SamWaf](https://github.com/samwafgo/SamWaf)
- Atomgit
[https://atomgit.com/SamSafe/SamWaf](https://atomgit.com/SamSafe/SamWaf)

## تعارف اور کمپائلیشن
کمپائل کرنے کا طریقہ
[کمپائلیشن ہدایات](./docs/compile.md)

کمپائلیشن کا آن لائن مینوئل：
[https://doc.samwaf.com/en/dev/](https://doc.samwaf.com/en/dev/)

## آزمودہ اور سپورٹ شدہ پلیٹ فارمز
[آزمودہ اور سپورٹ شدہ پلیٹ فارمز](./docs/Tested_supported_systems.md)

## دیگر معلومات 

- [IP ڈیٹابیس اپ ڈیٹ کریں](./docs/ipmodify.md)

## جانچ کے نتائج
[جانچ کے نتائج](./test/attackTest.md)

# سیکیورٹی پالیسی
[سیکیورٹی پالیسی](./SECURITY.md)

# فیڈ بیک
SamWaf مسلسل ارتقا پذیر ہے۔ ہم فیڈ بیک اور تجاویز کا خیرمقدم کرتے ہیں۔

- [Gitee Issues](https://gitee.com/samwaf/SamWaf/issues)
- [GitHub Issues](https://github.com/samwafgo/SamWaf/issues)
- [Atomgit Issues](https://atomgit.com/SamSafe/SamWaf/issues)
- ای میل فیڈ بیک: samwafgo@gmail.com

# WeChat پبلک اکاؤنٹ

<img alt="SamWaf" width="400px"  src="./docs/images/mp_samwaf.png"> 

## اسٹار ہسٹری

[![اسٹار ہسٹری چارٹ](https://api.star-history.com/svg?repos=samwafgo/samwaf&type=Date)](https://star-history.com/#samwafgo/samwaf&Date)


#  لائسنس
SamWaf کو Apache License 2.0 کے تحت لائسنس دیا گیا ہے۔ مزید تفصیلات کے لیے [LICENSE](./LICENSE) ملاحظہ کریں۔

تھرڈ پارٹی سافٹ ویئر کے استعمال سے متعلق نوٹس کے لیے [ThirdLicense](./ThirdLicense) دیکھیں

# شراکت
 درج ذیل معاونین کا شکریہ!

<a href="https://github.com/samwafgo/SamWaf/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=samwafgo/SamWaf" />
</a>
