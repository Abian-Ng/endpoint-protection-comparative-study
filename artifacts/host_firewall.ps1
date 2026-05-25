# Windows PowerShell Block: Network Isolation Protocol for Arm B Execution
# Run with administrative privileges to isolate execution VMs from cloud telemetry mirrors

Function Set-ExperimentalArm {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Online", "Offline")]
        $ArmState
    )
    
    If ($ArmState -eq "Offline") {
        Write-Host "[*] Applying Air-Gapped Topology: Severing outbound network interfaces..." -ForegroundColor Yellow
        New-NetFirewallRule -DisplayName "EPS_Study_Offline_Block" `
                            -Direction Outbound `
                            -Action Block `
                            -Enabled True `
                            -Description "Blocks outbound telemetry validation frames for Arm B."
    } Else {
        Write-Host "[+] Applying Hybrid Cloud Topology: Permitting outbound network communication..." -ForegroundColor Green
        Remove-NetFirewallRule -DisplayName "EPS_Study_Offline_Block" -ErrorAction SilentlyContinue
    }
}
