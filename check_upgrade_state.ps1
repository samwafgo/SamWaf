# 升级现场观测脚本 —— 用来确认 Windows 自升级 "Access is denied" 的根因。
#
#   powershell -File check_upgrade_state.ps1
#   powershell -File check_upgrade_state.ps1 -TryDelete
#
# 三项观测：
#   1) SamWaf64 进程及其映像路径 —— 升级一次后，Supervisor 的 Path 会变成
#      .SamWaf64.exe.old（rename 只改目录项，进程仍映射同一个文件对象）
#   2) .SamWaf64.exe.old* 残留清单与 HIDDEN 属性
#   3) -TryDelete 时手工删一次 .old，预期"拒绝访问"
#
# 本脚本只读（除非显式加 -TryDelete），不会动任何进程。

param(
    [string] $Dir = (Join-Path $PSScriptRoot 'release\testupdate'),
    [switch] $TryDelete
)

$ErrorActionPreference = 'Continue'
$resolved = Resolve-Path -LiteralPath $Dir -ErrorAction SilentlyContinue
if (-not $resolved) {
    Write-Host "目录不存在: $Dir  请先跑 build_test_upgrade_twice.bat" -ForegroundColor Red
    exit 1
}
$Dir = $resolved.Path

Write-Host ''
Write-Host "=== 观测目录: $Dir ===" -ForegroundColor Cyan

# --- 1) 进程与映像路径 -------------------------------------------------
Write-Host ''
Write-Host '[1] SamWaf64 进程（关注 Path 是不是 .old）' -ForegroundColor Yellow
$procs = Get-Process -Name SamWaf64 -ErrorAction SilentlyContinue |
         Where-Object { $_.Path -and $_.Path.StartsWith($Dir, 'OrdinalIgnoreCase') }
if (-not $procs) {
    Write-Host '    (无) 该目录下没有运行中的 SamWaf64'
} else {
    foreach ($p in $procs) {
        $name = Split-Path $p.Path -Leaf
        $pinned = $name -like '*.old*'
        $tag = if ($pinned) { '  <== 钉住了 .old，第二次升级会失败' } else { '' }
        $line = '    pid={0,-6} started={1}  {2}{3}' -f $p.Id, $p.StartTime.ToString('HH:mm:ss'), $p.Path, $tag
        if ($pinned) { Write-Host $line -ForegroundColor Red } else { Write-Host $line }
    }
}

# --- 2) 残留文件 -------------------------------------------------------
Write-Host ''
Write-Host '[2] .SamWaf64.exe.* 残留（-Force 才看得到 HIDDEN）' -ForegroundColor Yellow
$leftovers = Get-ChildItem -Force -LiteralPath $Dir -Filter '.SamWaf64.exe.*' -ErrorAction SilentlyContinue
if (-not $leftovers) {
    Write-Host '    (无)'
} else {
    foreach ($f in $leftovers) {
        $line = '    {0,-40} {1,12:N0} bytes  attrs={2}  {3}' -f `
                $f.Name, $f.Length, $f.Attributes, $f.LastWriteTime.ToString('MM-dd HH:mm:ss')
        Write-Host $line -ForegroundColor Red
    }
}

# --- 3) 当前更新服务器指向的版本 ---------------------------------------
$manifest = Join-Path (Split-Path $Dir -Parent) 'web\samwaf_update\windows-amd64.json'
Write-Host ''
Write-Host '[3] 本地更新服务器当前发布的版本' -ForegroundColor Yellow
if (Test-Path -LiteralPath $manifest) {
    $j = Get-Content -Raw -LiteralPath $manifest | ConvertFrom-Json
    Write-Host ('    Version={0}  Desc={1}  UpdateTime={2}' -f $j.Version, $j.Desc, $j.UpdateTime)
} else {
    Write-Host '    (未发布)'
}

# --- 4) 可选：手工删 .old，验证"拒绝访问" -----------------------------
if ($TryDelete -and $leftovers) {
    Write-Host ''
    Write-Host '[4] 手工删除 .old（预期：拒绝访问）' -ForegroundColor Yellow
    foreach ($f in $leftovers) {
        try {
            Remove-Item -Force -LiteralPath $f.FullName -ErrorAction Stop
            Write-Host ('    {0} -> 删除成功（说明没被进程钉住）' -f $f.Name) -ForegroundColor Green
        } catch {
            Write-Host ('    {0} -> {1}' -f $f.Name, $_.Exception.Message) -ForegroundColor Red
        }
    }
}

Write-Host ''
Write-Host '判据：升级一次后若 [1] 出现红色的 .old 路径、[2] 有 HIDDEN 残留、' -ForegroundColor Cyan
Write-Host '      且 -TryDelete 报拒绝访问，则第二次升级必然 Access is denied。' -ForegroundColor Cyan
Write-Host ''
