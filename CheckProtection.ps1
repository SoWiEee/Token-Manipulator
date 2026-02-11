<#
.SYNOPSIS
    Windows Kernel Security Auditor (Fixed Version)
.DESCRIPTION
    Analyzes Windows security features relevant to Kernel Exploitation, Rootkits, and LPE.
    Fixed compatibility for PowerShell 5.1 and 7+.
#>

# --- Helper Function for Colors ---
function Write-Color {
    param([string]$Text, [string]$Color = "White", [switch]$NoNewline)
    
    # 防呆機制：如果顏色是空的，強制設為白色，避免報錯
    if ([string]::IsNullOrWhiteSpace($Color)) { $Color = "White" }

    $params = @{ ForegroundColor = $Color }
    if ($NoNewline) { $params.Add("NoNewline", $true) }
    Write-Host $Text @params
}

function Get-StatusColor {
    param([bool]$Enabled, [bool]$Inverse = $false) # Inverse for things like "Vulnerable"
    
    # 修正：使用標準 PowerShell 語法，分開 return
    if ($Inverse) {
        if ($Enabled) { return "Red" } else { return "Green" }
    } else {
        if ($Enabled) { return "Green" } else { return "Red" }
    }
}

# --- ASCII Art ---
Write-Color @"
 _    _  _____  ____  _   _  _____  _      
| |  | ||  ___||  _ \| \ | ||  ___|| |     
| |  | || |__  | |_) |  \| || |__  | |     
| |/\| ||  __| |  _ <| . ` ||  __| | |     
\  /\  /| |___ | |_) | |\  || |___ | |____ 
 \/  \/ \____/ |____/|_| \_|\____/ \_____/ 
 Kernel Security Auditor v2.1 (Fixed)
"@ -Color Cyan
Write-Host ""

# --- 1. Gather System Info ---
Write-Color "[*] Gathering System Information..." -Color Yellow
$OSParams = Get-CimInstance -ClassName Win32_OperatingSystem
Write-Host "OS Version      : $($OSParams.Caption) (Build $($OSParams.BuildNumber))"

# --- 2. Security Feature Checks ---

# 2.1 Secure Boot (Rootkit Prevention)
$SecureBoot = $false
try {
    # 增加錯誤處理，避免在某些舊 BIOS 機器上紅字
    $sbCmd = Get-SecureBootUEFI -ErrorAction SilentlyContinue
    if ($sbCmd) { $SecureBoot = $true }
} catch { $SecureBoot = $false }

# 2.2 Device Guard / VBS / HVCI
try {
    $DeviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($DeviceGuard) {
        $VBS_Status = $DeviceGuard.VirtualizationBasedSecurityStatus # 2 = Running
        $HVCI_Status = $DeviceGuard.SecurityServicesRunning -contains 2
        $CredGuard_Status = $DeviceGuard.SecurityServicesRunning -contains 1
        $SMM_Status = $DeviceGuard.SecurityServicesRunning -contains 4
    } else {
        $VBS_Status = 0
        $HVCI_Status = $false
        $CredGuard_Status = $false
    }
} catch {
    $VBS_Status = 0; $HVCI_Status = $false; $CredGuard_Status = $false
}

# 2.3 Kernel DMA Protection
try {
    $DMA_Status = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DMAProtection' -Name 'DmaSecurityLevel' -ErrorAction SilentlyContinue).DmaSecurityLevel -ge 1
} catch { $DMA_Status = $false }

# 2.4 Vulnerable Driver Blocklist
try {
    $Blocklist_Status = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name 'VulnerableDriverBlocklistEnable' -ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable -eq 1
} catch { $Blocklist_Status = $false }

# 2.5 Tamper Protection (Defender)
try {
    $DefenderInfo = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($DefenderInfo) {
        $Tamper_Status = $DefenderInfo.IsTamperProtected
    } else { $Tamper_Status = $false }
} catch { $Tamper_Status = $false }

# 2.6 Kernel CET (Shadow Stacks)
try {
    $KCET_Status = (Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\ControlSet001\Control\DeviceGuard\Scenarios\KernelShadowStacks\' -Name Enabled -ErrorAction SilentlyContinue) -eq 1
} catch { $KCET_Status = $false }

# 2.7 SMEP (Assuming True for modern OS)
$SMEP_Status = $true 

# --- 3. Status Table ---
Write-Host "`n=== Security Mitigation Status ===" -ForegroundColor Magenta

$Results = @()
$Results += [PSCustomObject]@{ Feature = "Secure Boot"; Enabled = $SecureBoot; Note = "Prevents unsigned bootloaders (Bootkits)" }
$Results += [PSCustomObject]@{ Feature = "Virtualization-based Security (VBS)"; Enabled = ($VBS_Status -eq 2); Note = "Hypervisor Ring -1 Active" }
$Results += [PSCustomObject]@{ Feature = "HVCI (Memory Integrity)"; Enabled = $HVCI_Status; Note = "Blocks Kernel Code Injection & unsigned drivers" }
$Results += [PSCustomObject]@{ Feature = "Credential Guard"; Enabled = $CredGuard_Status; Note = "Isolates LSASS secrets" }
$Results += [PSCustomObject]@{ Feature = "Kernel DMA Protection"; Enabled = $DMA_Status; Note = "Prevents DMA hardware attacks" }
$Results += [PSCustomObject]@{ Feature = "Vulnerable Driver Blocklist"; Enabled = $Blocklist_Status; Note = "Blocks known bad drivers (BYOVD defense)" }
$Results += [PSCustomObject]@{ Feature = "Defender Tamper Protection"; Enabled = $Tamper_Status; Note = "Prevents disabling AV via Registry/PowerShell" }
$Results += [PSCustomObject]@{ Feature = "Kernel Shadow Stacks (KCET)"; Enabled = $KCET_Status; Note = "Prevents ROP (Return-Oriented Programming)" }
$Results += [PSCustomObject]@{ Feature = "SMEP (Supervisor Mode Exec Prev)"; Enabled = $SMEP_Status; Note = "Prevents executing User-Mode code in Kernel" }

# Render Table
foreach ($item in $Results) {
    Write-Color $item.Feature.PadRight(35) -NoNewline
    $color = Get-StatusColor -Enabled $item.Enabled
    $statusText = if ($item.Enabled) { "ON" } else { "OFF" }
    Write-Color $statusText.PadRight(10) -Color $color -NoNewline
    Write-Host "| $($item.Note)"
}

# --- 4. Hacker's Perspective (Attack Surface Analysis) ---
Write-Host "`n=== Exploitation Feasibility Analysis (Hacker View) ===" -ForegroundColor Magenta

# Logic 1: Token Patching (DKOM)
$Feasibility_Patching = if ($HVCI_Status) { "Hard (BSOD Risk)" } else { "High (DKOM possible)" }
$Color_Patching = Get-StatusColor -Enabled ($HVCI_Status) -Inverse $true

# Logic 2: Token Stealing (Pointer Swapping)
$Feasibility_Stealing = if ($HVCI_Status) { "Medium (Data-only attack required)" } else { "High (Standard shellcode works)" }
$Color_Stealing = if ($HVCI_Status) { "Yellow" } else { "Red" }

# Logic 3: BYOVD (Bring Your Own Vulnerable Driver)
$Feasibility_BYOVD = if ($Blocklist_Status) { "Hard (Must find 0-day driver)" } else { "High (Load known bad driver)" }
$Color_BYOVD = Get-StatusColor -Enabled ($Blocklist_Status) -Inverse $true

# Logic 4: Mimikatz (LSASS Dump)
$Feasibility_Mimikatz = if ($CredGuard_Status) { "Impossible (Secrets Isolated)" } else { "High (Standard Dump)" }
$Color_Mimikatz = Get-StatusColor -Enabled ($CredGuard_Status) -Inverse $true

# Logic 5: Bootkit
$Feasibility_Bootkit = if ($SecureBoot) { "Hard (Need UEFI exploit)" } else { "High (Modify Bootloader)" }
$Color_Bootkit = Get-StatusColor -Enabled ($SecureBoot) -Inverse $true

Write-Host "1. Token Patching (DKOM)      : " -NoNewline; Write-Color $Feasibility_Patching -Color $Color_Patching
Write-Host "2. Token Stealing (Swap)      : " -NoNewline; Write-Color $Feasibility_Stealing -Color $Color_Stealing
Write-Host "3. BYOVD Attack               : " -NoNewline; Write-Color $Feasibility_BYOVD -Color $Color_BYOVD
Write-Host "4. LSASS Dump (Mimikatz)      : " -NoNewline; Write-Color $Feasibility_Mimikatz -Color $Color_Mimikatz
Write-Host "5. Bootkit Persistence        : " -NoNewline; Write-Color $Feasibility_Bootkit -Color $Color_Bootkit

Write-Host "`n[*] Analysis Complete." -ForegroundColor Gray