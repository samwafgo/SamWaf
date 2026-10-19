package global

// GLOBAL_DEFAULT_NOT_MATCH_WEBSITE 未匹配网站时的内置响应页面。
const GLOBAL_DEFAULT_NOT_MATCH_WEBSITE = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>网站尚未接入</title>
<style>
:root{color-scheme:light;--primary:#0052d9;--bg:#f3f5f8;--surface:#fff;--text:#1f2329;--muted:#646a73;--line:#dcdfe6;--soft:#edf3ff}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:40px 16px;background:var(--bg);color:var(--text);font:14px/1.8 "Segoe UI","Microsoft YaHei",sans-serif}
.card{width:100%;max-width:660px;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:36px;display:grid;gap:22px;box-shadow:0 8px 32px #162d5010}
h1,h2,p{margin:0}h1{font-size:28px;line-height:1.4;text-wrap:balance}h2{font-size:15px}.muted{color:var(--muted)}.eyebrow{font-size:12px;letter-spacing:1px;margin-bottom:8px}.summary{margin-top:12px}
.domain{padding:15px 18px;background:var(--bg);border-radius:6px;overflow-wrap:anywhere}.domain p{font-size:12px;margin-bottom:4px}.domain code{font:16px/1.8 Consolas,monospace}
.steps{border-top:1px solid var(--line);padding-top:22px}.steps ol{padding-left:22px;margin:12px 0 0}.footer{border-top:1px solid var(--line);padding-top:16px;font-size:12px;color:var(--muted)}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--primary:#8ab4ff;--bg:#141923;--surface:#1e2531;--text:#edf0f5;--muted:#b2bccb;--line:#384355;--soft:#263956}}
:root[data-theme="dark"]{color-scheme:dark;--primary:#8ab4ff;--bg:#141923;--surface:#1e2531;--text:#edf0f5;--muted:#b2bccb;--line:#384355;--soft:#263956}
@media(max-width:600px){body{padding-block:24px}.card{padding:24px}h1{font-size:24px}}
</style>
</head>
<body><main class="card">
<div><p class="muted eyebrow">SAMWAF · 403</p><h1>网站尚未接入</h1><p class="muted summary">当前访问地址未匹配到已配置的网站，暂时无法提供访问。</p></div>
<div class="domain"><p class="muted">当前访问域名</p><code>[[.SAMWAF_HOST]]</code></div>
<section class="steps"><h2>如果你是网站管理员</h2><ol><li>登录 SamWaf 管理后台，进入「网站防护」。</li><li>点击「新建」，添加当前访问域名对应的主机。</li><li>核对域名、监听端口和协议，保存后重新访问。</li></ol></section>
<p class="muted">如果你是网站访客，请联系网站管理员处理。</p>
<footer class="footer">SamWaf 网站防护</footer>
</main></body></html>`
