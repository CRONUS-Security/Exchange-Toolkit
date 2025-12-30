# === Exchange Remote PowerShell Connection Script ===
# Please replace $username and $password with actual credentials
# For domain accounts, use format: DOMAIN\Username or user@domain.com

# === Force console output to use UTF-8 encoding ===
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Exchange administrator credentials
$username = "admin@example.com"
$password = "password123" | ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username, $password)
# $credential = New-Object System.Management.Automation.PSCredential("admin@example.com", $password)

# Create session options (supports Basic / NTLM)
$sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

try {
    Write-Host "Connecting to Exchange Remote PowerShell..." -ForegroundColor Yellow

    $session = New-PSSession -ConfigurationName Microsoft.Exchange `
        -ConnectionUri "https://mail.example.com/powershell" `
        -Credential $credential `
        -Authentication Basic `
        -SessionOption $sessionOption `
        -ErrorAction Stop `
        -Verbose

    Import-PSSession $session -DisableNameChecking -AllowClobber | Out-Null

    Write-Host "[+] Successfully connected to Exchange Server!" -ForegroundColor Green

    # 定义需要获得完整访问权限的邮箱地址列表
    $mailboxList = @(
        "user1@example.com",
        "user2@example.com",
        "user3@example.com"
    )

    # 循环遍历列表，为每个邮箱分配权限
    foreach ($mailbox in $mailboxList) {
        Add-MailboxPermission -Identity $mailbox -User $username -AccessRights FullAccess -InheritanceType All
    }

}
catch {
    Write-Host "[x] Connection failed: $_" -ForegroundColor Red
}
finally {
    # Optional: remove session when done
    # if ($session) { Remove-PSSession $session }
}