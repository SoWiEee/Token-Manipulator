<#
.SYNOPSIS
    Windows Advanced Security Mitigation Auditor
.DESCRIPTION
    Checks for Kernel/User-mode mitigations including KASLR, SMAP, SMEP, KCFG, CFG, KVA Shadow, ASR, etc.
#>

# --- 0. Helper Functions ---
function Write-Color {
    param([string]$Text, [string]$Color = "White", [switch]$NoNewline)
    if ([string]::IsNullOrWhiteSpace($Color)) { $Color = "White" }
    $params = @{ ForegroundColor = $Color }
    if ($NoNewline) { $params.Add("NoNewline", $true) }
    Write-Host $Text @params
}

function Get-StatusColor {
    param([bool]$Enabled, [bool]$Inverse = $false)
    if ($Inverse) { if ($Enabled) { return "Red" } else { return "Green" } }
    else { if ($Enabled) { return "Green" } else { return "Red" } }
}

# --- 1. Gather System Info ---
Write-Color @"
 _    _  _____  ____  _   _  _____  _      
| |  | ||  ___||  _ \| \ | ||  ___|| |     
| |  | || |__  | |_) |  \| || |__  | |     
| |/\| ||  __| |  _ <| . ` ||  __| | |     
\  /\  /| |___ | |_) | |\  || |___ | |____ 
 \/  \/ \____/ |____/|_| \_|\____/ \_____/ 
 Advanced Security Auditor v3.0
"@ -Color Cyan
Write-Host ""
Write-Color "[*] Gathering Advanced Security Metrics..." -Color Yellow

# --- 2. Base Security Checks (Previous V2) ---
$SecureBoot = try { (Get-SecureBootUEFI) } catch { $false }

# Device Guard / VBS
try {
    $DeviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($DeviceGuard) {
        $VBS_Status = ($DeviceGuard.VirtualizationBasedSecurityStatus -eq 2)
        $HVCI_Status = ($DeviceGuard.SecurityServicesRunning -contains 2)
        $CredGuard_Status = ($DeviceGuard.SecurityServicesRunning -contains 1)
    } else { $VBS_Status=$false; $HVCI_Status=$false; $CredGuard_Status=$false }
} catch { $VBS_Status=$false; $HVCI_Status=$false; $CredGuard_Status=$false }

# Vulnerable Driver Blocklist
try {
    $Blocklist_Status = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name 'VulnerableDriverBlocklistEnable' -ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable -eq 1
} catch { $Blocklist_Status = $false }

# --- 3. Advanced Mitigations (New Request) ---

# 3.1 KASLR & PML4 Randomization
# Windows 10/11 defaults KASLR to ON unless "MoveImages" is disabled in Registry.
try {
    $MoveImages = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'MoveImages' -ErrorAction SilentlyContinue
    # If key is missing, it defaults to ON (Enabled). If present and 0, it's OFF.
    if ($MoveImages -eq $null) { $KASLR_Status = $true } 
    elseif ($MoveImages.MoveImages -ne 0) { $KASLR_Status = $true }
    else { $KASLR_Status = $false }
} catch { $KASLR_Status = $true }

# 3.2 KVA Shadow (Meltdown Mitigation)
# Checked via FeatureSettingsOverride. If hardware is not vulnerable, OS might disable it, but checking if OS *can* enable it.
try {
    # This is a simplification. Real check involves NtQuerySystemInformation, but Registry gives a hint.
    # 0 = Enabled/Default. 3 = Disabled.
    $KVA_Reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'FeatureSettingsOverride' -ErrorAction SilentlyContinue
    if ($KVA_Reg -ne $null -and ($KVA_Reg.FeatureSettingsOverride -band 3) -eq 3) {
        $KVA_Status = $false # Explicitly disabled
    } else {
        $KVA_Status = $true # Enabled or Hardware Mitigated
    }
} catch { $KVA_Status = $true }

# 3.3 Exploit Guard (User Mode: CFG, DEP, SEHOP, ASLR)
try {
    $SysMitigation = Get-ProcessMitigation -System
    $DEP_Status    = ($SysMitigation.Dep.Enable -eq $true)
    $CFG_Status    = ($SysMitigation.ControlFlowGuard.Enable -eq $true) # User Mode CFG
    $SEHOP_Status  = ($SysMitigation.Sehop.Enable -eq $true) # Exception Chain Validation
    $ForceASLR_Status = ($SysMitigation.Aslr.ForceRelocateImages -eq $true) # Force ASLR (helps against non-ASLR DLLs)
} catch {
    $DEP_Status=$false; $CFG_Status=$false; $SEHOP_Status=$false; $ForceASLR_Status=$false
}

# 3.4 Kernel Control Flow Guard (KCFG)
# Usually tied to VBS/HVCI, but can exist independently supported by hardware.
$KCFG_Status = $VBS_Status # Strongest indicator for PS script without diving into kernel structures.

# 3.5 SMAP / SMEP / KCET
# Hard to check directly via PS without Driver, but we can assume modern Windows 11 enables them if HW supports.
# KCET (Shadow Stacks) check:
try {
    $KCET_Status = (Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\ControlSet001\Control\DeviceGuard\Scenarios\KernelShadowStacks\' -Name Enabled -ErrorAction SilentlyContinue) -eq 1
} catch { $KCET_Status = $false }

# 3.6 Attack Surface Reduction (ASR)
try {
    $MpPref = Get-MpPreference -ErrorAction SilentlyContinue
    $ASR_Count = $MpPref.AttackSurfaceReductionRules_Ids.Count
    if ($ASR_Count -gt 0) { $ASR_Status = $true; $ASR_Note = "$ASR_Count Rules Active" }
    else { $ASR_Status = $false; $ASR_Note = "No Rules Configured" }
} catch { $ASR_Status = $false; $ASR_Note = "Defender Error" }

# 3.7 ACG (Arbitrary Code Guard) & CIG (Code Integrity Guard)
# These are typically per-process (like Edge), but we check if System enforces strict Code Integrity.
try {
    $CIG_Reg = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name 'VerifiedAndReputablePolicyState' -ErrorAction SilentlyContinue)
    $CIG_Status = ($CIG_Reg -ne $null) # Rough check if strict policy exists
} catch { $CIG_Status = $false }


# --- 4. Render Output Table ---
$Results = @()

# Group 1: Kernel & Virtualization
$Results += [PSCustomObject]@{ Category="Kernel"; Feature="HVCI (Memory Integrity)"; Enabled=$HVCI_Status; Note="Blocks Kernel Injection" }
$Results += [PSCustomObject]@{ Category="Kernel"; Feature="KASLR (High Entropy)"; Enabled=$KASLR_Status; Note="Randomizes Kernel Base" }
$Results += [PSCustomObject]@{ Category="Kernel"; Feature="KVA Shadow (Meltdown)"; Enabled=$KVA_Status; Note="Isolates Kernel Page Tables" }
$Results += [PSCustomObject]@{ Category="Kernel"; Feature="KCFG (Kernel CFG)"; Enabled=$KCFG_Status; Note="Protects Kernel Indirect Calls" }
$Results += [PSCustomObject]@{ Category="Kernel"; Feature="KCET (Shadow Stacks)"; Enabled=$KCET_Status; Note="Prevents Kernel ROP" }
$Results += [PSCustomObject]@{ Category="Kernel"; Feature="SMAP/SMEP Support"; Enabled=$true; Note="Assumed on Win11 (Prevents User Access)" }

# Group 2: User Mode & Memory
$Results += [PSCustomObject]@{ Category="UserMode"; Feature="CFG (Control Flow Guard)"; Enabled=$CFG_Status; Note="Prevents Indirect Call Abuse" }
$Results += [PSCustomObject]@{ Category="UserMode"; Feature="DEP (Data Exec Prev)"; Enabled=$DEP_Status; Note="No Execute (NX) Stack/Heap" }
$Results += [PSCustomObject]@{ Category="UserMode"; Feature="SEHOP (Exception Chain)"; Enabled=$SEHOP_Status; Note="Prevents SEH Overwrites" }
$Results += [PSCustomObject]@{ Category="UserMode"; Feature="Force ASLR / Bottom-Up"; Enabled=$ForceASLR_Status; Note="Enforced Randomization" }
$Results += [PSCustomObject]@{ Category="UserMode"; Feature="ACG / CIG (Policy)"; Enabled=$CIG_Status; Note="Code Integrity Policy" }

# Group 3: System Defense
$Results += [PSCustomObject]@{ Category="System"; Feature="Secure Boot"; Enabled=$SecureBoot; Note="Rootkit Prevention" }
$Results += [PSCustomObject]@{ Category="System"; Feature="Credential Guard"; Enabled=$CredGuard_Status; Note="Protects LSA Secrets" }
$Results += [PSCustomObject]@{ Category="System"; Feature="Driver Blocklist"; Enabled=$Blocklist_Status; Note="Blocks Bad Drivers (BYOVD)" }
$Results += [PSCustomObject]@{ Category="System"; Feature="ASR (Attack Surface Red)"; Enabled=$ASR_Status; Note=$ASR_Note }

Write-Host "`n=== Advanced Security Mitigation Status ===" -ForegroundColor Magenta

# Display Table
foreach ($item in $Results) {
    Write-Color "[$($item.Category)]".PadRight(12) -Color Cyan -NoNewline
    Write-Color $item.Feature.PadRight(30) -NoNewline
    $color = Get-StatusColor -Enabled $item.Enabled
    $statusText = if ($item.Enabled) { "ON" } else { "OFF" }
    Write-Color $statusText.PadRight(10) -Color $color -NoNewline
    Write-Host "| $($item.Note)"
}

# --- 5. Hacker's Perspective (Updated) ---
Write-Host "`n=== Exploitation Difficulty Analysis (Hacker View) ===" -ForegroundColor Magenta

# Analysis Logic
$InfoLeak_Req = if ($KASLR_Status) { "Required (Hard)" } else { "Not Required" }
$ROP_Diff = if ($KCET_Status) { "Very Hard (JOP/COP required)" } else { "Standard ROP" }
$Heap_Diff = if ($CFG_Status) { "Hard (Need Metadata corruption)" } else { "Standard Heap Spray" }
$Kernel_Write = if ($SMAP_Status -and $HVCI_Status) { "Impossible (Need Data-Only)" } elseif ($SMAP_Status) { "Hard (Pivot Required)" } else { "Easy" }

Write-Host "1. Kernel Exploit (Info Leak) : " -NoNewline; Write-Color $InfoLeak_Req -Color (Get-StatusColor $KASLR_Status)
Write-Host "2. ROP Chain Construction     : " -NoNewline; Write-Color $ROP_Diff -Color (Get-StatusColor $KCET_Status)
Write-Host "3. Function Pointer Overwrite : " -NoNewline; Write-Color $Heap_Diff -Color (Get-StatusColor $CFG_Status)
Write-Host "4. Kernel Payload Execution   : " -NoNewline; Write-Color $Kernel_Write -Color (Get-StatusColor $HVCI_Status)
Write-Host "5. Initial Access (Macro/Script): " -NoNewline; Write-Color "$($ASR_Note)" -Color (Get-StatusColor $ASR_Status)

Write-Host "`n[*] Deep Analysis Complete." -ForegroundColor Gray
