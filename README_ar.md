[English](README.md) | [简体中文](README_cn.md) | [Español](README_es.md) | [हिन्दी](README_hi.md) | [العربية](README_ar.md) | [Français](README_fr.md) | [Português](README_pt.md) | [Русский](README_ru.md) | [বাংলা](README_bn.md) | [اردو](README_ur.md) | [日本語](README_ja.md) | [Deutsch](README_de.md) | [Bahasa Indonesia](README_id.md) | [한국어](README_ko.md)


<div align="center">
 <img alt="SamWaf" width="100" src="./docs/images/logo.png"> 

جدار حماية خفيف ومفتوح المصدر لتطبيقات الويب

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

  
## دوافع التطوير:
- **خفيف الوزن**: في البداية استخدمتُ بعض المنتجات الأمنية القائمة على إضافات nginx وapache وiis للحماية، لكن صيغة الإضافات كانت تعاني من درجة اقتران عالية.
- **النشر الخاص**: لاحقًا جرى اعتماد معظم خدمات الحماية السحابية، غير أن النشر الخاص ليس في المتناول إلا للمؤسسات المتوسطة والكبيرة، بينما تجده الشركات الصغيرة والاستوديوهات مكلفًا.
- **تشفير الخصوصية**: أثناء حماية الويب، يُفضَّل معالجة البيانات المحلية دون إرسالها إلى السحابة. كان الهدف إنشاء أداة تُشفِّر المعلومات المحلية والاتصالات الشبكية الخاصة بواجهة الإدارة.
- **التخصيص الذاتي (DIY)**: على مدى سنوات من صيانة المواقع وتطويرها، كانت هناك وظائف محددة أردت إضافتها لكنني لم أتمكن من تحقيقها.
- **الإدراك**: إذا لم يسبق لمدير الموقع استخدام WAF مماثل، فمن الصعب معرفة مَن يصل إلى الموقع وما الطلبات المُرسَلة بالاعتماد فقط على السجلات أو على nginx أو apache أو IIS وغيرها.

باختصار، كان الهدف إنشاء أداة فعّالة لحماية المواقع أو واجهات API من أجل التعامل مع الحالات غير الطبيعية وضمان التشغيل السليم للمواقع والتطبيقات.

# نبذة عن البرنامج
SamWaf هو جدار حماية خفيف ومفتوح المصدر لتطبيقات الويب موجَّه للشركات الصغيرة والاستوديوهات والمواقع الشخصية. يدعم النشر الخاص بالكامل، ويُشفِّر البيانات المخزَّنة محليًا، ويسهل بدء تشغيله، ويدعم Linux وWindows بمعمارية 64 بت وARM64، مع توفر صور Docker. يستخدم افتراضيًا قاعدة بيانات SQLite مضمَّنة ومشفَّرة دون أي اعتماديات خارجية، ويمكن اختياريًا التبديل إلى MySQL.

## البنية المعمارية

![البنية المعمارية لـ SamWaf](./docs/images_en/tecDesign.svg)

## الواجهة
![نظرة عامة على جدار حماية تطبيقات الويب SamWaf](/docs/images_en/overview.png)

<table>
    <tr>
        <td align="center">إضافة مضيف</td>
        <td align="center">سجل الهجمات</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/add_host.png" alt="إضافة مضيف"/></td>
        <td><img src="./docs/images_en/attacklog.png" alt="سجل الهجمات"/></td>
    </tr>
    <tr>
        <td align="center">CC</td>
        <td align="center">قائمة حظر عناوين IP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/cc.png" alt="CC"/></td>
        <td><img src="./docs/images_en/ipblock.png" alt="قائمة حظر عناوين IP"/></td>
    </tr>
    <tr>
        <td align="center">قائمة سماح عناوين IP</td>
        <td align="center">LDP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/ipallow.png" alt="قائمة سماح عناوين IP"/></td>
        <td><img src="./docs/images_en/ldp.png" alt="LDP"/></td>
    </tr>
    <tr>
        <td align="center">إضافة سكربت قاعدة من السجل</td>
        <td align="center">اختيار السجل</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/log_add_rule_script.png" alt="إضافة سكربت قاعدة من السجل"/></td>
        <td><img src="./docs/images_en/log_select.png" alt="اختيار السجل"/></td>
    </tr>
    <tr>
        <td align="center">تفاصيل السجل</td>
        <td align="center">قاعدة يدوية</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/logdetail.png" alt="تفاصيل السجل"/></td>
        <td><img src="./docs/images_en/manual_rule.png" alt="قاعدة يدوية"/></td>
    </tr>
    <tr>
        <td align="center">قائمة حظر عناوين URL</td>
        <td align="center">قائمة سماح عناوين URL</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/urlblock.png" alt="قائمة حظر عناوين URL"/></td>
        <td><img src="./docs/images_en/urlallow.png" alt="قائمة سماح عناوين URL"/></td>
    </tr>
</table>

## الميزات الرئيسية

### الأساسيات
- شيفرة مفتوحة المصدر بالكامل (Apache 2.0)
- نشر خاص بالكامل؛ البيانات مشفَّرة ومخزَّنة محليًا فقط
- تشغيل بنقرة واحدة من ملف واحد، خفيف الوزن دون الاعتماد على خدمات طرف ثالث (MySQL/Redis اختياريان)
- محرك مستقل تمامًا؛ الحماية لا تعتمد على IIS أو Nginx
- دعم IPv6

### استقبال حركة المرور
- دعم HTTP/1.1 وHTTP/2 وHTTP/3 (QUIC)
- تمرير WebSocket
- وكيل عكسي مع موازنة الحمل (التوزيع الدوري الموزون، وتجزئة IP، وأقل عدد اتصالات)؛ وتُزيل فحوصات السلامة الخوادم الخلفية غير السليمة تلقائيًا
- قواعد المسارات: وكيل عكسي لكل مسار، أو ملفات ثابتة، أو إعادة توجيه 301/302، مع إمكانية ضبط بروتوكول الخادم الخلفي ومهلة الاستجابة
- تقديم المواقع الثابتة
- تمرير أنفاق TCP/UDP على الطبقة الرابعة (مع التحكم في الوصول حسب عناوين IP والتحكم بالنوافذ الزمنية)
- تخزين مؤقت لصفحات الويب
- مصادقة HTTP Basic للوصول إلى الموقع
- صفحة حظر قابلة للتخصيص

### الحماية من الهجمات
- كشف حقن SQL
- كشف XSS (البرمجة النصية عبر المواقع)
- كشف RCE (تنفيذ الأوامر عن بُعد)
- كشف أدوات المسح
- كشف اجتياز المسارات
- فحص الملفات المرفوعة (الامتدادات الخطرة، وبصمات webshell، وانتحال Content-Type)
- حماية من هجمات CC / تقييد معدل الطلبات
- كشف الزواحف والروبوتات المزيفة (التحقق من روبوتات محركات البحث عبر DNS العكسي)
- منع سرقة الروابط (الحماية من الربط المباشر)
- حماية من CSRF (التحقق من Origin/Referer لكل موقع)
- تصفية الكلمات الحساسة
- دعم مجموعة قواعد OWASP CRS (محرك Coraza؛ يمكن تفعيل القواعد أو تعطيلها أو تجاوزها)
- قواعد حماية قابلة للتخصيص، مع دعم التحرير بالسكربتات وعبر الواجهة الرسومية
- التحقق البشري: اختبار CAPTCHA بالنقر وإثبات العمل عبر Cap.js
- وضع التسجيل فقط: تسجيل الهجمات دون حظرها، وهو مفيد لمراقبة القواعد وضبطها

### التحكم في الوصول
- قوائم السماح / الحظر لعناوين IP
- قوائم السماح / الحظر لعناوين URL
- الحظر الجغرافي (قواعد بيانات ip2region/GeoIP2 مدمجة تعمل دون اتصال، بدعم IPv4/IPv6)
- حظر عناوين IP بالربط مع جدار حماية نظام التشغيل
- حظر تلقائي عند بلوغ عدد مرات فشل عنوان IP حدًّا معيّنًا
- إعداد شامل بنقرة واحدة واستراتيجيات حماية لكل موقع على حدة

### أمان البيانات
- تخزين مشفَّر للسجلات
- سجلات اتصالات مشفَّرة
- إخفاء البيانات (DLP) مع إخراج مخصَّص لخصوصية البيانات
- منع التلاعب بصفحات الويب (تعلُّم خط الأساس + الاستعادة التلقائية)
- تعزيز أمان ملفات تعريف الارتباط (HttpOnly/Secure/SameSite)

### شهادات SSL
- طلب شهادات SSL وتجديدها تلقائيًا (ACME، مع دعم جهات إصدار متعددة وEAB)
- شهادات متعددة عبر SNI وHTTPS متعدد المنافذ
- فحص جماعي لانتهاء صلاحية شهادات SSL
- تحميل تلقائي للشهادات

### التشغيل والإدارة
- صلاحيات الحسابات وفق RBAC، ومصادقة ثنائية عبر OTP، وسجلات تسجيل الدخول والعمليات
- تقارير إحصائية ومراقبة النظام والمضيفين
- سياسة الاحتفاظ بالبيانات مع تجزئة السجلات وأرشفتها تلقائيًا
- SQLite (مشفَّرة) افتراضيًا مع خيار MySQL، وأداة مدمجة للترحيل من SQLite إلى MySQL
- ترقية عبر الإنترنت بنقرة واحدة، وإعادة تشغيل متدرجة دون انقطاع الخدمة، والرجوع إلى إصدارات سابقة
- مهام دفعية، ومهام مجدولة، ونسخ احتياطي للبيانات
- واجهة API مفتوحة

### الإشعارات
- قنوات إرسال عبر البريد الإلكتروني وDingTalk وFeishu وWeCom (WeChat Work) وServerChan وWebhook وKafka وRabbitMQ وملفات السجل

# تعليمات الاستخدام
**يوصى بشدة بإجراء اختبارات شاملة في بيئة اختبار قبل النشر في بيئة الإنتاج. وفي حال ظهور أي مشكلات، يُرجى تقديم ملاحظاتكم في أقرب وقت.**
## تنزيل أحدث إصدار
Gitee:  [https://gitee.com/samwaf/SamWaf/releases](https://gitee.com/samwaf/SamWaf/releases)

GitHub: [https://github.com/samwafgo/SamWaf/releases](https://github.com/samwafgo/SamWaf/releases)

AtomGit: [https://atomgit.com/SamSafe/SamWaf/releases](https://atomgit.com/SamSafe/SamWaf/releases)

## البدء السريع

### Windows
- التشغيل المباشر
```
SamWaf64.exe
```
- التشغيل كخدمة (يتطلب صلاحيات المسؤول)
```
//Install & Start
SamWaf64.exe install && SamWaf64.exe start

//Stop &  Uninstall 
SamWaf64.exe stop && SamWaf64.exe uninstall
``` 

### Linux
- التثبيت
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh install 
``` 

- إلغاء التثبيت
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
لمزيد من التفاصيل حول Docker: https://hub.docker.com/r/samwaf/samwaf

الوسوم:
- **latest**: أحدث إصدار مستقر (يوصى به للاستخدام في بيئة الإنتاج).
- **beta**: أحدث إصدار اختباري (يتيح تجربة الميزات الجديدة أو إصلاحات محددة للأخطاء).

### أدوات سطر الأوامر

| Command | الوصف |
|---------|-------------|
| `install` / `uninstall` | تثبيت خدمة النظام / إلغاء تثبيتها |
| `start` / `stop` / `restart` | بدء الخدمة / إيقافها / إعادة تشغيلها |
| `rolling-restart` | إعادة تشغيل متدرجة دون توقف (تبديل عملية العامل دون انقطاع حركة المرور) |
| `resetpwd` | إعادة تعيين كلمة مرور المسؤول |
| `resetotp` | إعادة تعيين رمز الأمان (OTP) |
| `repairdb` | إصلاح قاعدة بيانات تالفة |
| `execsql` | تنفيذ عبارات SQL على قاعدة بيانات محددة |
| `migratedb` | ترحيل قاعدة البيانات دون اتصال من SQLite إلى MySQL (`--dry-run` للتقدير فقط، و`--force` للاستبدال) |
| `rollback` | الرجوع إلى نسخة احتياطية سابقة |

مثال: `SamWaf64.exe resetpwd` (على Linux: `./SamWafLinux64 resetpwd`)

## بدء الوصول

http://127.0.0.1:26666

الحساب الافتراضي: admin  كلمة المرور الأولية: تُنشئ عمليات التثبيت الجديدة كلمة مرور عشوائية تلقائيًا وتُحفظ في `data/initial_password.txt` (تحتفظ عمليات التثبيت الحالية بكلمة مرورها السابقة؛ يُرجى تغييرها عند أول تسجيل دخول)


## دليل الترقية

**ملاحظة: ستؤدي عملية الترقية إلى إيقاف الخدمة، لذا يُرجى إجراء الترقية خارج أوقات الذروة.**

### الترقية التلقائية
عند توفر إصدار جديد، ستظهر نافذة منبثقة لتأكيد الترقية تتيح لك بدء عملية الترقية، وسيجري تحديث الصفحة تلقائيًا بعد اكتمال الترقية.

### الترقية اليدوية
- في حالة التشغيل المباشر:
    1. أغلق التطبيق.
    2. نزِّل أحدث نسخة من البرنامج واستبدل الملفات الحالية، ثم شغِّله يدويًا من جديد.

- في حالة وضع الخدمة:
```
1. First, pause the service.

  Windows: SamWaf64.exe stop
  Linux: ./SamWafLinux64 stop
  
2. Replace with the latest application files.

3. Start the service:
Windows: SamWaf64.exe start
Linux: ./SamWafLinux64 start
```

**ملاحظة**: قد تؤدي ترقية خدمة Windows إلى تفعيل قواعد أمنية لدى برنامجي 360 أو Huorong، مما يمنع استبدال الملفات الجديدة بصورة طبيعية. في هذه الحالة يمكنك استبدال الملفات يدويًا. ويمكن لذوي الدراية بهذا المجال المساعدة في تحديد طريقة المعالجة الصحيحة.

## الوثائق عبر الإنترنت

[الوثائق عبر الإنترنت](https://doc.samwaf.com/)

# معلومات الشيفرة
## مستودع الشيفرة
- Gitee
[https://gitee.com/samwaf/SamWaf](https://gitee.com/samwaf/SamWaf)
- GitHub
[https://github.com/samwafgo/SamWaf](https://github.com/samwafgo/SamWaf)
- Atomgit
[https://atomgit.com/SamSafe/SamWaf](https://atomgit.com/SamSafe/SamWaf)

## المقدمة والترجمة البرمجية
كيفية الترجمة البرمجية
[تعليمات الترجمة البرمجية](./docs/compile.md)

دليل الترجمة البرمجية عبر الإنترنت:
[https://doc.samwaf.com/en/dev/](https://doc.samwaf.com/en/dev/)

## المنصات المختبَرة والمدعومة
[المنصات المختبَرة والمدعومة](./docs/Tested_supported_systems.md)

## معلومات أخرى 

- [تحديث قاعدة بيانات IP](./docs/ipmodify.md)

## نتائج الاختبارات
[نتائج الاختبارات](./test/attackTest.md)

# سياسة الأمان
[سياسة الأمان](./SECURITY.md)

# الملاحظات والاقتراحات
يتطور SamWaf باستمرار، ونرحب بالملاحظات والاقتراحات.

- [المشكلات على Gitee](https://gitee.com/samwaf/SamWaf/issues)
- [المشكلات على GitHub](https://github.com/samwafgo/SamWaf/issues)
- [المشكلات على Atomgit](https://atomgit.com/SamSafe/SamWaf/issues)
- الملاحظات عبر البريد الإلكتروني: samwafgo@gmail.com

# الحساب الرسمي على WeChat

<img alt="SamWaf" width="400px"  src="./docs/images/mp_samwaf.png"> 

## سجل النجوم

[![مخطط سجل النجوم](https://api.star-history.com/svg?repos=samwafgo/samwaf&type=Date)](https://star-history.com/#samwafgo/samwaf&Date)


#  الترخيص
SamWaf مرخَّص بموجب رخصة Apache License 2.0. راجع [LICENSE](./LICENSE) لمزيد من التفاصيل.

للاطلاع على إشعار استخدام برمجيات الأطراف الثالثة، راجع [ThirdLicense](./ThirdLicense)

# المساهمة
 شكرًا للمساهمين التالية أسماؤهم!

<a href="https://github.com/samwafgo/SamWaf/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=samwafgo/SamWaf" />
</a>
