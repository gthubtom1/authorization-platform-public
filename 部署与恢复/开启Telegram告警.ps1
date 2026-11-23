# 开启 Telegram 告警（把本机填好的两个值推上去，并当场发一条测试消息）
#
# 用法：右键"用 PowerShell 运行"，或在这个文件夹里执行：
#   powershell -ExecutionPolicy Bypass -File .\开启Telegram告警.ps1
#
# 前提：灾备钥匙包\08-Telegram告警\ 下面已经有两个填好的文件：
#   telegram-bot-token.txt   （@BotFather 给你的令牌）
#   telegram-chat-id.txt    （你的聊天 ID）
#
# 这个脚本只做三件事：把两个文件放到服务器的密钥目录、去掉"关闭"标记、发一条测试消息。
# 它不会重启任何服务，不会改任何业务配置。

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$keyDir = Join-Path $root '08-Telegram告警'
$tokenFile = Join-Path $keyDir 'telegram-bot-token.txt'
$chatFile  = Join-Path $keyDir 'telegram-chat-id.txt'

foreach ($f in @($tokenFile, $chatFile)) {
  if (-not (Test-Path $f)) { Write-Host "缺少文件: $f`n先照 08-Telegram告警\README.md 填好这两个文件。" -ForegroundColor Red; exit 1 }
}
$token = (Get-Content $tokenFile -Raw).Trim()
$chat  = (Get-Content $chatFile  -Raw).Trim()
if (-not $token -or -not $chat) { Write-Host '两个文件里有空的，请填完整。' -ForegroundColor Red; exit 1 }
if ($token -notmatch '^\d+:[\w-]{20,}$') { Write-Host '令牌格式看起来不对（应该是 1234567890:AA... 这种）。' -ForegroundColor Red; exit 1 }

$target = Read-Host '推到哪台？直接回车 = 正式站(legacy.example.com)，输入 test = 测试站'
if ($target -eq 'test') { $host_ = '192.0.2.12'; $label = '测试站' } else { $host_ = '192.0.2.11'; $label = '正式站' }

$sshKey = Join-Path $env:USERPROFILE '.ssh\ai_vps_ed25519'
if (-not (Test-Path $sshKey)) { Write-Host "找不到 SSH 私钥: $sshKey" -ForegroundColor Red; exit 1 }

Write-Host "`n把两个文件放到 $label ..." -ForegroundColor Cyan
$tokenB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($token))
$chatB64  = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($chat))
$script = @"
set -eu
umask 077
K=/var/lib/authorization-platform-backup/keys
mkdir -p "`$K"
echo '$tokenB64' | base64 -d > "`$K/telegram-bot-token.txt"
echo '$chatB64'  | base64 -d > "`$K/telegram-chat-id.txt"
chmod 600 "`$K/telegram-bot-token.txt" "`$K/telegram-chat-id.txt"
chown root:10001 "`$K/telegram-bot-token.txt" "`$K/telegram-chat-id.txt"
rm -f "`$K/telegram-disabled"
echo '文件已就位，关闭标记已移除:'
ls -l "`$K" | grep telegram | awk '{print "  "`$1" "`$5" 字节 " `$9}'
"@
$outer = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($script))
& ssh -i $sshKey -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 "root@$host_" "echo $outer | base64 -d | bash"
if ($LASTEXITCODE -ne 0) { Write-Host '推送失败' -ForegroundColor Red; exit 1 }

Write-Host "`n当场发一条测试消息，看你手机能不能收到 ..." -ForegroundColor Cyan
$msg = "【授权平台】告警已开启。这是测试消息，看到即表示以后机器出问题都会这样通知你。发送时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
& curl.exe -sS --max-time 15 -X POST --data-urlencode "chat_id=$chat" --data-urlencode "text=$msg" "https://api.telegram.org/bot$token/sendMessage"
Write-Host "`n看到 {`"ok`":true} 就是成功了。以后备份失败、磁盘满、程序假死，都会这样找你。" -ForegroundColor Green
