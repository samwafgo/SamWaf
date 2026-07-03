[English](README.md) | [简体中文](README_cn.md) | [Español](README_es.md) | [हिन्दी](README_hi.md) | [العربية](README_ar.md) | [Français](README_fr.md) | [Português](README_pt.md) | [Русский](README_ru.md) | [বাংলা](README_bn.md) | [اردو](README_ur.md) | [日本語](README_ja.md) | [Deutsch](README_de.md) | [Bahasa Indonesia](README_id.md) | [한국어](README_ko.md)


<div align="center">
 <img alt="SamWaf" width="100" src="./docs/images/logo.png"> 

एक हल्का ओपन-सोर्स वेब एप्लिकेशन फ़ायरवॉल

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

  
## विकास की प्रेरणा:
- **हल्कापन**: शुरुआत में मैंने सुरक्षा के लिए nginx, apache और iis प्लगइन्स पर आधारित कुछ सुरक्षा उत्पादों का उपयोग किया, लेकिन प्लगइन स्वरूप में coupling बहुत अधिक थी।
- **निजीकरण**: बाद में ज़्यादातर क्लाउड सुरक्षा सेवाएँ अपनाई गईं, लेकिन प्राइवेट डिप्लॉयमेंट केवल मध्यम और बड़े उद्यमों के लिए ही किफ़ायती है, जबकि छोटी कंपनियों और स्टूडियो को यह महँगा पड़ता है।
- **प्राइवेसी एन्क्रिप्शन**: वेब सुरक्षा के दौरान बेहतर यही है कि लोकल डेटा को क्लाउड पर भेजे बिना ही प्रोसेस किया जाए। लक्ष्य एक ऐसा टूल बनाना था जो लोकल जानकारी और मैनेजमेंट एंड के नेटवर्क संचार को एन्क्रिप्ट करे।
- **DIY**: वर्षों के वेबसाइट रखरखाव और विकास के दौरान कुछ ऐसी खास सुविधाएँ थीं जिन्हें मैं जोड़ना चाहता था, लेकिन जोड़ नहीं पाता था।
- **जागरूकता**: यदि वेबमास्टर ने कभी ऐसा कोई WAF इस्तेमाल नहीं किया है, तो केवल लॉग या nginx, apache, IIS आदि से यह समझना असुविधाजनक होता है कि साइट को कौन एक्सेस कर रहा है और कौन-सी requests की जा रही हैं।

संक्षेप में, लक्ष्य वेबसाइट या API सुरक्षा के लिए एक प्रभावी टूल बनाना था, ताकि असामान्य स्थितियों से निपटा जा सके और वेबसाइटों तथा एप्लिकेशनों का सामान्य संचालन सुनिश्चित किया जा सके।

# सॉफ़्टवेयर परिचय
SamWaf छोटी कंपनियों, स्टूडियो और व्यक्तिगत वेबसाइटों के लिए एक हल्का, ओपन-सोर्स वेब एप्लिकेशन फ़ायरवॉल है। यह पूरी तरह प्राइवेट डिप्लॉयमेंट का समर्थन करता है, डेटा को एन्क्रिप्ट करके लोकल रूप से संग्रहीत करता है, शुरू करना आसान है, और Linux, Windows 64-bit तथा ARM64 का समर्थन करता है; Docker इमेज भी उपलब्ध हैं। डिफ़ॉल्ट रूप से यह शून्य बाहरी निर्भरताओं वाले एम्बेडेड एन्क्रिप्टेड SQLite डेटाबेस का उपयोग करता है, और वैकल्पिक रूप से MySQL पर स्विच किया जा सकता है।

## आर्किटेक्चर

![SamWaf आर्किटेक्चर](./docs/images_en/tecDesign.svg)

## इंटरफ़ेस
![SamWaf वेब एप्लिकेशन फ़ायरवॉल अवलोकन](/docs/images_en/overview.png)

<table>
    <tr>
        <td align="center">होस्ट जोड़ें</td>
        <td align="center">अटैक लॉग</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/add_host.png" alt="होस्ट जोड़ें"/></td>
        <td><img src="./docs/images_en/attacklog.png" alt="अटैक लॉग"/></td>
    </tr>
    <tr>
        <td align="center">CC</td>
        <td align="center">IP ब्लॉकलिस्ट</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/cc.png" alt="CC"/></td>
        <td><img src="./docs/images_en/ipblock.png" alt="IP ब्लॉकलिस्ट"/></td>
    </tr>
    <tr>
        <td align="center">IP अलाउलिस्ट</td>
        <td align="center">LDP</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/ipallow.png" alt="IP अलाउलिस्ट"/></td>
        <td><img src="./docs/images_en/ldp.png" alt="LDP"/></td>
    </tr>
    <tr>
        <td align="center">लॉग से रूल स्क्रिप्ट जोड़ें</td>
        <td align="center">लॉग चुनें</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/log_add_rule_script.png" alt="लॉग से रूल स्क्रिप्ट जोड़ें"/></td>
        <td><img src="./docs/images_en/log_select.png" alt="लॉग चुनें"/></td>
    </tr>
    <tr>
        <td align="center">लॉग विवरण</td>
        <td align="center">मैनुअल रूल</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/logdetail.png" alt="लॉग विवरण"/></td>
        <td><img src="./docs/images_en/manual_rule.png" alt="मैनुअल रूल"/></td>
    </tr>
    <tr>
        <td align="center">URL ब्लॉकलिस्ट</td>
        <td align="center">URL अलाउलिस्ट</td>
    </tr>
    <tr>
        <td><img src="./docs/images_en/urlblock.png" alt="URL ब्लॉकलिस्ट"/></td>
        <td><img src="./docs/images_en/urlallow.png" alt="URL अलाउलिस्ट"/></td>
    </tr>
</table>

## मुख्य विशेषताएँ

### बुनियादी बातें
- पूरी तरह ओपन-सोर्स कोड (Apache 2.0)
- पूर्णतः प्राइवेट डिप्लॉयमेंट; डेटा एन्क्रिप्ट होकर केवल लोकल रूप से संग्रहीत होता है
- सिंगल-फ़ाइल वन-क्लिक स्टार्ट, हल्का और बिना किसी थर्ड-पार्टी सर्विस निर्भरता के (MySQL/Redis वैकल्पिक हैं)
- पूरी तरह स्वतंत्र इंजन; सुरक्षा IIS या Nginx पर निर्भर नहीं करती
- IPv6 समर्थन

### ट्रैफ़िक एक्सेस
- HTTP/1.1, HTTP/2 और HTTP/3 (QUIC) समर्थन
- WebSocket फ़ॉरवर्डिंग
- लोड बैलेंसिंग के साथ रिवर्स प्रॉक्सी (weighted round-robin, IP hash, least connections); हेल्थ चेक अनहेल्दी बैकएंड को स्वचालित रूप से हटा देते हैं
- पाथ रूल्स: प्रत्येक पाथ के लिए रिवर्स प्रॉक्सी, स्टैटिक फ़ाइलें या 301/302 रीडायरेक्ट, कॉन्फ़िगर करने योग्य बैकएंड प्रोटोकॉल और रिस्पॉन्स टाइमआउट के साथ
- स्टैटिक साइट सर्विंग
- TCP/UDP लेयर-4 टनल फ़ॉरवर्डिंग (IP एक्सेस कंट्रोल और टाइम-विंडो कंट्रोल के साथ)
- वेब पेज कैशिंग
- साइट एक्सेस के लिए HTTP Basic Auth
- कस्टमाइज़ करने योग्य ब्लॉकिंग पेज

### हमलों से सुरक्षा
- SQL injection डिटेक्शन
- XSS (क्रॉस-साइट स्क्रिप्टिंग) डिटेक्शन
- RCE (रिमोट कमांड एग्ज़िक्यूशन) डिटेक्शन
- स्कैनर टूल डिटेक्शन
- Path traversal डिटेक्शन
- फ़ाइल अपलोड डिटेक्शन (खतरनाक एक्सटेंशन, webshell सिग्नेचर, नकली Content-Type)
- CC / रेट-लिमिट सुरक्षा
- नकली क्रॉलर / बॉट डिटेक्शन (सर्च-इंजन बॉट्स का reverse-DNS सत्यापन)
- एंटी-लीच (हॉटलिंक सुरक्षा)
- CSRF सुरक्षा (प्रति-साइट Origin/Referer सत्यापन)
- संवेदनशील शब्द फ़िल्टरिंग
- OWASP CRS रूल सेट समर्थन (Coraza इंजन; रूल्स को enable/disable/override किया जा सकता है)
- कस्टमाइज़ करने योग्य सुरक्षा रूल्स, स्क्रिप्ट और GUI दोनों से संपादन का समर्थन
- ह्यूमन वेरिफ़िकेशन: क्लिक CAPTCHA और Cap.js proof-of-work
- केवल-लॉग मोड: ब्लॉक किए बिना हमलों को रिकॉर्ड करें, रूल्स के अवलोकन और ट्यूनिंग के लिए उपयोगी

### एक्सेस कंट्रोल
- IP अलाउलिस्ट / ब्लॉकलिस्ट
- URL अलाउलिस्ट / ब्लॉकलिस्ट
- जियो ब्लॉकिंग (बिल्ट-इन ऑफ़लाइन ip2region/GeoIP2 डेटाबेस, IPv4/IPv6)
- OS फ़ायरवॉल से जुड़ी IP बैनिंग
- IP विफलता संख्या के थ्रेशहोल्ड तक पहुँचने पर स्वचालित बैन
- ग्लोबल वन-क्लिक कॉन्फ़िगरेशन और प्रति-साइट सुरक्षा रणनीतियाँ

### डेटा सुरक्षा
- एन्क्रिप्टेड लॉग स्टोरेज
- एन्क्रिप्टेड कम्युनिकेशन लॉग
- निर्दिष्ट डेटा प्राइवेसी आउटपुट के साथ डेटा मास्किंग (DLP)
- वेब पेज एंटी-टैम्पर (बेसलाइन लर्निंग + स्वचालित रिकवरी)
- Cookie सुरक्षा हार्डनिंग (HttpOnly/Secure/SameSite)

### SSL सर्टिफ़िकेट
- स्वचालित SSL सर्टिफ़िकेट आवेदन और नवीनीकरण (ACME, EAB समर्थन के साथ मल्टी-CA)
- SNI मल्टी-सर्टिफ़िकेट और मल्टी-पोर्ट HTTPS
- बल्क SSL सर्टिफ़िकेट एक्सपायरी जाँच
- स्वचालित सर्टिफ़िकेट लोडिंग

### संचालन और प्रबंधन
- अकाउंट RBAC, OTP टू-फ़ैक्टर ऑथेंटिकेशन, लॉगिन/ऑपरेशन लॉग
- सांख्यिकी रिपोर्ट और सिस्टम/होस्ट मॉनिटरिंग
- स्वचालित लॉग शार्डिंग और आर्काइविंग के साथ डेटा रिटेंशन नीति
- डिफ़ॉल्ट रूप से SQLite (एन्क्रिप्टेड), वैकल्पिक MySQL, बिल्ट-इन SQLite→MySQL माइग्रेशन टूल के साथ
- ऑनलाइन वन-क्लिक अपग्रेड, ज़ीरो-डाउनटाइम रोलिंग रीस्टार्ट और वर्ज़न रोलबैक
- बैच टास्क, शेड्यूल्ड टास्क और डेटा बैकअप
- Open API

### नोटिफ़िकेशन
- ईमेल, DingTalk, Feishu, WeCom (WeChat Work), ServerChan, Webhook, Kafka, RabbitMQ और लॉग-फ़ाइल डिलीवरी चैनल

# उपयोग निर्देश
**प्रोडक्शन में डिप्लॉय करने से पहले टेस्ट एनवायरनमेंट में गहन परीक्षण करने की पुरज़ोर अनुशंसा की जाती है। यदि कोई समस्या आए, तो कृपया तुरंत फ़ीडबैक दें।**
## नवीनतम संस्करण डाउनलोड करें
Gitee:  [https://gitee.com/samwaf/SamWaf/releases](https://gitee.com/samwaf/SamWaf/releases)

GitHub: [https://github.com/samwafgo/SamWaf/releases](https://github.com/samwafgo/SamWaf/releases)

AtomGit: [https://atomgit.com/SamSafe/SamWaf/releases](https://atomgit.com/SamSafe/SamWaf/releases)

## त्वरित शुरुआत

### Windows
- सीधे शुरू करें
```
SamWaf64.exe
```
- सेवा के रूप में चलाएँ (Administrator आवश्यक)
```
//Install & Start
SamWaf64.exe install && SamWaf64.exe start

//Stop &  Uninstall 
SamWaf64.exe stop && SamWaf64.exe uninstall
``` 

### Linux
- इंस्टॉल करें
```
curl -sSO https://update.samwaf.com/latest/install_samwaf.sh && bash install_samwaf.sh install 
``` 

- अनइंस्टॉल करें
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
Docker के बारे में अधिक विवरण https://hub.docker.com/r/samwaf/samwaf

टैग्स:
- **latest**: नवीनतम स्थिर रिलीज़ (प्रोडक्शन उपयोग के लिए अनुशंसित)।
- **beta**: नवीनतम परीक्षण संस्करण (नई सुविधाओं या विशिष्ट बग फ़िक्स के परीक्षण की सुविधा देता है)।

### कमांड-लाइन टूल्स

| Command | विवरण |
|---------|-------------|
| `install` / `uninstall` | सिस्टम सेवा इंस्टॉल / अनइंस्टॉल करें |
| `start` / `stop` / `restart` | सेवा शुरू / बंद / पुनः आरंभ करें |
| `rolling-restart` | ज़ीरो-डाउनटाइम रोलिंग रीस्टार्ट (ट्रैफ़िक बाधित किए बिना worker को बदल देता है) |
| `resetpwd` | एडमिनिस्ट्रेटर पासवर्ड रीसेट करें |
| `resetotp` | सुरक्षा कोड (OTP) रीसेट करें |
| `repairdb` | करप्ट डेटाबेस की मरम्मत करें |
| `execsql` | चुने गए डेटाबेस पर SQL स्टेटमेंट निष्पादित करें |
| `migratedb` | ऑफ़लाइन डेटाबेस माइग्रेशन SQLite → MySQL (`--dry-run` केवल अनुमान के लिए, `--force` ओवरराइट करने के लिए) |
| `rollback` | पिछले बैकअप संस्करण पर रोलबैक करें |

उदाहरण: `SamWaf64.exe resetpwd` (Linux पर: `./SamWafLinux64 resetpwd`)

## एक्सेस शुरू करें

http://127.0.0.1:26666

डिफ़ॉल्ट अकाउंट: admin  प्रारंभिक पासवर्ड: नई इंस्टॉलेशन पर स्वतः एक यादृच्छिक पासवर्ड बनकर `data/initial_password.txt` में सहेजा जाता है (मौजूदा इंस्टॉलेशन अपना पिछला पासवर्ड बनाए रखती हैं; कृपया पहले लॉगिन पर ही इसे बदल लें)


## अपग्रेड गाइड

**नोट: अपग्रेड प्रक्रिया सेवा को समाप्त कर देगी, कृपया कम ट्रैफ़िक वाले समय में अपग्रेड करें।**

### स्वचालित अपग्रेड
यदि कोई नया संस्करण उपलब्ध है, तो पुष्टि के लिए एक अपग्रेड प्रॉम्प्ट दिखाई देगा, जिससे आप अपग्रेड शुरू कर सकते हैं। अपग्रेड पूरा होने के बाद पेज अपने आप रिफ़्रेश हो जाएगा।

### मैनुअल अपग्रेड
- सीधे शुरू करने की स्थिति में:
    1. एप्लिकेशन बंद करें।
    2. नवीनतम प्रोग्राम डाउनलोड करें और मौजूदा फ़ाइलों को बदल दें, फिर उसे मैन्युअल रूप से दोबारा शुरू करें।

- सर्विस मोड की स्थिति में:
```
1. First, pause the service.

  Windows: SamWaf64.exe stop
  Linux: ./SamWafLinux64 stop
  
2. Replace with the latest application files.

3. Start the service:
Windows: SamWaf64.exe start
Linux: ./SamWafLinux64 start
```

**नोट**: Windows सेवा को अपग्रेड करने पर 360 या Huorong के सुरक्षा नियम ट्रिगर हो सकते हैं, जिससे नई फ़ाइलें सामान्य रूप से बदली नहीं जा पातीं। ऐसी स्थिति में आप फ़ाइलों को मैन्युअल रूप से बदल सकते हैं। इस क्षेत्र से परिचित लोग सही तरीका तय करने में मदद कर सकते हैं।

## ऑनलाइन दस्तावेज़

[ऑनलाइन दस्तावेज़](https://doc.samwaf.com/)

# कोड जानकारी
## कोड रिपॉज़िटरी
- Gitee
[https://gitee.com/samwaf/SamWaf](https://gitee.com/samwaf/SamWaf)
- GitHub
[https://github.com/samwafgo/SamWaf](https://github.com/samwafgo/SamWaf)
- Atomgit
[https://atomgit.com/SamSafe/SamWaf](https://atomgit.com/SamSafe/SamWaf)

## परिचय और कंपाइलेशन
कंपाइल कैसे करें
[कंपाइलेशन निर्देश](./docs/compile.md)

कंपाइल ऑनलाइन मैनुअल：
[https://doc.samwaf.com/en/dev/](https://doc.samwaf.com/en/dev/)

## परीक्षित और समर्थित प्लेटफ़ॉर्म
[परीक्षित और समर्थित प्लेटफ़ॉर्म](./docs/Tested_supported_systems.md)

## अन्य जानकारी 

- [IP डेटाबेस अपडेट करें](./docs/ipmodify.md)

## परीक्षण परिणाम
[परीक्षण परिणाम](./test/attackTest.md)

# सुरक्षा नीति
[सुरक्षा नीति](./SECURITY.md)

# फ़ीडबैक
SamWaf में लगातार सुधार हो रहा है। हम फ़ीडबैक और सुझावों का स्वागत करते हैं।

- [Gitee Issues](https://gitee.com/samwaf/SamWaf/issues)
- [GitHub Issues](https://github.com/samwafgo/SamWaf/issues)
- [Atomgit Issues](https://atomgit.com/SamSafe/SamWaf/issues)
- ईमेल फ़ीडबैक: samwafgo@gmail.com

# WeChat पब्लिक अकाउंट

<img alt="SamWaf" width="400px"  src="./docs/images/mp_samwaf.png"> 

## स्टार हिस्ट्री

[![स्टार हिस्ट्री चार्ट](https://api.star-history.com/svg?repos=samwafgo/samwaf&type=Date)](https://star-history.com/#samwafgo/samwaf&Date)


#  लाइसेंस
SamWaf को Apache License 2.0 के तहत लाइसेंस दिया गया है। अधिक विवरण के लिए [LICENSE](./LICENSE) देखें।

थर्ड-पार्टी सॉफ़्टवेयर उपयोग सूचना के लिए [ThirdLicense](./ThirdLicense) देखें

# योगदान
 निम्नलिखित योगदानकर्ताओं को धन्यवाद!

<a href="https://github.com/samwafgo/SamWaf/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=samwafgo/SamWaf" />
</a>
