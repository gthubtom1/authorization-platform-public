# 开启 Telegram 备份副本（把本机填好的两个值推上去，并当场发一份测试备份）
#
# 用法：在这个文件夹里执行
#   powershell -ExecutionPolicy Bypass -File .\开启Telegram备份.ps1
#
# 前提：灾备钥匙包\09-Telegram备份副本\ 下已填好两个文件：
#   telegram-backup-bot-token.txt   （@BotFather 给的令牌）
#   telegram-backup-channel-id.txt  （私有频道的 chat id）
#
# 它做三件事：把两个文件放到服务器密钥目录、去掉"关闭"标记、立刻上传一份现有备份做验证。
# 不重启服务、不改任何业务配置。

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$keyDir = Join-Path $root '09-Telegram备份副本'
$tokenFile = Join-Path $keyDir 'telegram-backup-bot-token.txt'
$chatFile  = Join-Path $keyDir 'telegram-backup-channel-id.txt'

foreach ($f in @($tokenFile, $chatFile)) {
  if (-not (Test-Path $f)) { Write-Host "缺少文件: $f`n先照 09-Telegram备份副本\README.md 填好这两个文件。" -ForegroundColor Red; exit 1 }
}
$token = (Get-Content $tokenFile -Raw).Trim()
$chat  = (Get-Content $chatFile  -Raw).Trim()
if (-not $token -or -not $chat) { Write-Host '两个文件里有空的，请填完整。' -ForegroundColor Red; exit 1 }
if ($token -notmatch '^\d+:[\w-]{20,}$') { Write-Host '令牌格式不对（应是 1234567890:AA... 这种）。' -ForegroundColor Red; exit 1 }
if ($chat -notmatch '^-?\d+$') { Write-Host '频道号应该是一串数字（形如 -1001234567890）。' -ForegroundColor Red; exit 1 }

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
echo '$tokenB64' | base64 -d > "`$K/telegram-backup-bot-token.txt"
echo '$chatB64'  | base64 -d > "`$K/telegram-backup-channel-id.txt"
chmod 600 "`$K/telegram-backup-bot-token.txt" "`$K/telegram-backup-channel-id.txt"
chown root:10001 "`$K/telegram-backup-bot-token.txt" "`$K/telegram-backup-channel-id.txt"
rm -f "`$K/telegram-backup-disabled"
echo '凭据已就位:'
ls -l "`$K" | grep telegram-backup | awk '{print "  "`$1" "`$5" 字节 " `$9}'
echo '现在上传一份现有备份做验证（约 12 MB，请稍等）...'
bash /opt/authorization-platform/deploy/backup/telegram_backup_copy.sh "`$(ls -t /var/lib/authorization-platform-backup/downloads/*.enc | head -1)" 7
echo '日志尾部:'
tail -2 /var/lib/authorization-platform-backup/backup.log | sed 's/^/  /'
"@
$outer = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($script))
& ssh -i $sshKey -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=20 "root@$host_" "echo $outer | base64 -d | bash"
if ($LASTEXITCODE -ne 0) { Write-Host '推送失败' -ForegroundColor Red; exit 1 }

Write-Host "`n去你的 Telegram 频道看一眼：应该已经躺着一条备份文件。" -ForegroundColor Green
Write-Host '以后每天全量备份做完都会自动发一份，只留最近 7 份。' -ForegroundColor Green
Write-Host '上传失败不会影响服务器上的备份（只是少一份异地副本），日志里能看到。' -ForegroundColor DarkGray
