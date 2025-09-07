param (
    [string]$vmIP,
    [string]$username,
    [string]$oldPassword,
    [string]$newPassword,
    [string]$adminUser,
    [string]$adminPass
)

try {
    # Step 1: Verify old password by trying to connect with user credentials
    $secureOldPass = ConvertTo-SecureString $oldPassword -AsPlainText -Force
    $userCredential = New-Object System.Management.Automation.PSCredential($username, $secureOldPass)
    
    # Try a simple command to verify credentials
    $testResult = Invoke-Command -ComputerName $vmIP -Credential $userCredential -ScriptBlock {
        Get-Date  # Simple dummy command
    } -ErrorAction Stop
    
    # If we reach here, old password is correct
    
    # Step 2: Reset password using admin credentials
    $secureAdminPass = ConvertTo-SecureString $adminPass -AsPlainText -Force
    $adminCredential = New-Object System.Management.Automation.PSCredential($adminUser, $secureAdminPass)
    
    Invoke-Command -ComputerName $vmIP -Credential $adminCredential -ScriptBlock {
        param($user, $pass)
        net user $user $pass
    } -ArgumentList $username, $newPassword
    
    Write-Output "Password reset successfully for $username on $vmIP"
}
catch {
    Write-Error "Error: Old password incorrect, or connection failed: $_"
    exit 1
}