param (
    [string]$vm_ip,
    [string]$username,
    [string]$old_password,
    [string]$new_password,
    [string]$admin_user
)

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
    } -ArgumentList $username, $new_password -ErrorAction Stop
}
catch {
    Write-Error "Error: $($_.Exception.Message)"
    exit 1
}
