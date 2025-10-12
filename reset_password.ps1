param (
    [Parameter(Mandatory=$true)][ValidatePattern('^(\d{1,3}\.){3}\d{1,3}$')][string]$vm_ip,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9._@\\-]{1,64}$')][string]$username,
    [Parameter(Mandatory=$true)][string]$old_password,
    [Parameter(Mandatory=$true)][string]$new_password,
    [Parameter(Mandatory=$true)][string]$admin_user
)

# Logging setup for PS script – matches screenshot structure
$log_dir = "logs"
if (!(Test-Path $log_dir)) { New-Item -ItemType Directory -Path $log_dir -Force }
$ps_log_file = Join-Path $log_dir "reset_password.log"  # Exact name from screenshot

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $log_entry = "$timestamp - [$Level] - $Message"
    # Write to console (stdout for app capture)
    Write-Output $log_entry
    # Append to PS-specific log file in logs/
    Add-Content -Path $ps_log_file -Value $log_entry
}

try {
    # 1️⃣ Read admin password securely from stdin
    $admin_pass_plain = [Console]::In.ReadLine()
    if (-not $admin_pass_plain) {
        throw "Admin password was not provided via stdin."
    }

    $secure_admin_pass = ConvertTo-SecureString $admin_pass_plain -AsPlainText -Force

    # 2️⃣ Create credential object
    $cred = New-Object System.Management.Automation.PSCredential($admin_user, $secure_admin_pass)

    # 3️⃣ Optional: Verify connectivity to remote VM
    if (-not (Test-Connection -ComputerName $vm_ip -Count 1 -Quiet)) {
        throw "Cannot reach VM at $vm_ip. Check network or firewall."
    }

    Write-Log -Level "INFO" -Message "Starting password reset for user '$username' on VM '$vm_ip'"
    Write-Log -Level "DEBUG" -Message "Checking network connectivity to $vm_ip..."
    Write-Log -Level "DEBUG" -Message "Checking WinRM configuration on $vm_ip..."
    $wsmanTest = Test-WSMan -ComputerName $vm_ip -ErrorAction SilentlyContinue
    if ($wsmanTest) {
        Write-Log -Level "DEBUG" -Message "WinRM service reachable: $($wsmanTest.ProductVendor) - OS: $($wsmanTest.ProductVersion) SP: $($wsmanTest.ProductVersion) Stack: $($wsmanTest.ProtocolVersion)"
    } else {
        throw "WinRM not reachable on $vm_ip."
    }

    $secure_old_pass = ConvertTo-SecureString $old_password -AsPlainText -Force
    $oldCred = New-Object System.Management.Automation.PSCredential($username, $secure_old_pass)

    Write-Log -Level "DEBUG" -Message "Verifying old password for $username..."
    Write-Log -Level "DEBUG" -Message "Attempting Basic authentication for old password verification..."

    try {
        # Harmless command to test login with old password
        Invoke-Command -ComputerName $vm_ip -Credential $oldCred -ScriptBlock { whoami } -Authentication Basic -ErrorAction Stop | Out-Null
        Write-Log -Level "DEBUG" -Message "Old password verified successfully with Basic."
    }
    catch {
        Write-Log -Level "ERROR" -Message "Old password is incorrect."
        exit 1
    }

    Write-Log -Level "DEBUG" -Message "Verifying admin credentials for $admin_user..."
    Write-Log -Level "DEBUG" -Message "Admin password received: [Redacted for logging]"
    Write-Log -Level "DEBUG" -Message "Attempting Basic authentication for admin verification..."

    try {
        # Admin verification with explicit Basic auth
        Invoke-Command -ComputerName $vm_ip -Credential $cred -ScriptBlock { whoami } -Authentication Basic -ErrorAction Stop | Out-Null
        Write-Log -Level "DEBUG" -Message "Admin verified successfully with Basic."
    }
    catch {
        Write-Log -Level "ERROR" -Message "Basic authentication failed for admin verification: $($_.Exception.Message)"
        Write-Log -Level "ERROR" -Message "Password reset failed: Admin credentials verification failed with Basic authentication. Check admin username/password or WinRM config."
        exit 1
    }

    # 4️⃣ Run password reset remotely
    Invoke-Command -ComputerName $vm_ip -Credential $cred -ScriptBlock {
        param($username, $new_password)

        try {
            # Reset user password
            net user $username $new_password

            if ($LASTEXITCODE -eq 0) {
                Write-Output "Password reset successfully!"
            }
            else {
                throw "Password reset command failed with exit code $LASTEXITCODE."
            }
        }
        catch {
            Write-Error "Error: $($_.Exception.Message)"
            exit 1
        }
    } -ArgumentList $username, $new_password -Authentication Basic -ErrorAction Stop

    Write-Log -Level "INFO" -Message "Password reset successful for user '$username' on VM '$vm_ip'"
}
catch {
    Write-Log -Level "ERROR" -Message "$($_.Exception.Message)"
    exit 1
}