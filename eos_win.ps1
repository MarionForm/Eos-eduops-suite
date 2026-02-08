# eos_win.ps1
# EOS – EduOps Suite (Windows 10/11)
# Motor PowerShell robusto: SIEMPRE devuelve JSON {ok,mode,apply,data,errors}

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("inventory","diagnostics","security","fix")]
    [string]$Mode,

    [switch]$Apply
)

Set-StrictMode -Version Latest
$global:ProgressPreference = "SilentlyContinue"

try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new() } catch { }

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    } catch { return $false }
}

function Has-Prop {
    param(
        [Parameter(Mandatory=$true)]$Obj,
        [Parameter(Mandatory=$true)][string]$Prop
    )
    try { return $null -ne $Obj.PSObject.Properties[$Prop] }
    catch { return $false }
}

function Safe-Run {
    param([Parameter(Mandatory=$true)][scriptblock]$Block)
    try { & $Block }
    catch { return [PSCustomObject]@{ __eos_error = ($_ | Out-String) } }
}

# ✅ FIX: ahora acepta null sin explotar
function As-Array {
    param($Obj)
    if ($null -eq $Obj) { return @() }
    if (Has-Prop $Obj "__eos_error") { return $Obj } # devolvemos error tal cual
    return @($Obj)
}

function Get-EOSInventory {
    $os   = Safe-Run { Get-CimInstance Win32_OperatingSystem }
    $cs   = Safe-Run { Get-CimInstance Win32_ComputerSystem }
    $bios = Safe-Run { Get-CimInstance Win32_BIOS }
    $cpu  = Safe-Run { Get-CimInstance Win32_Processor | Select-Object -First 1 }

    $disks = Safe-Run {
        Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
            [PSCustomObject]@{
                Drive      = $_.DeviceID
                FileSystem = $_.FileSystem
                SizeGB     = [math]::Round($_.Size/1GB, 2)
                FreeGB     = [math]::Round($_.FreeSpace/1GB, 2)
                FreePct    = if ($_.Size -gt 0) { [math]::Round(($_.FreeSpace / $_.Size)*100, 1) } else { $null }
            }
        }
    }

    $nics = Safe-Run {
        Get-NetAdapter -Physical | Where-Object { $_.Status -ne "Disabled" } | ForEach-Object {
            $ip = Safe-Run { Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 | Select-Object -First 1 }
            [PSCustomObject]@{
                Name      = $_.Name
                Status    = $_.Status
                Mac       = $_.MacAddress
                LinkSpeed = $_.LinkSpeed
                IPv4      = if (Has-Prop $ip "__eos_error") { $null } else { $ip.IPAddress }
            }
        }
    }

    $hotfixCount = Safe-Run { (Get-HotFix | Measure-Object).Count }

    $installed = Safe-Run {
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
            Where-Object { $_.PSObject.Properties["DisplayName"] -and $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Sort-Object DisplayName
    }

    $osObj = if (Has-Prop $os "__eos_error") { $os } else {
        [PSCustomObject]@{
            Caption     = $os.Caption
            Version     = $os.Version
            BuildNumber = $os.BuildNumber
            LastBoot    = $os.LastBootUpTime
        }
    }

    $hwObj = if ((Has-Prop $cs "__eos_error") -or (Has-Prop $bios "__eos_error") -or (Has-Prop $cpu "__eos_error")) {
        [PSCustomObject]@{ cs=$cs; bios=$bios; cpu=$cpu }
    } else {
        [PSCustomObject]@{
            Manufacturer = $cs.Manufacturer
            Model        = $cs.Model
            Serial       = $bios.SerialNumber
            BIOSVersion  = $bios.SMBIOSBIOSVersion
            CPU          = $cpu.Name
            RAM_GB       = [math]::Round($cs.TotalPhysicalMemory/1GB, 2)
        }
    }

    return [PSCustomObject]@{
        ComputerName      = $env:COMPUTERNAME
        User              = $env:USERNAME
        IsAdmin           = (Test-IsAdmin)
        OS                = $osObj
        Hardware          = $hwObj
        Storage           = (As-Array $disks)
        Network           = (As-Array $nics)
        HotfixCount       = $hotfixCount
        InstalledSoftware = (As-Array $installed)
    }
}

function Get-EOSDiagnostics {
    $gateway = $null
    $gwObj = Safe-Run {
        (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).IPv4DefaultGateway.NextHop
    }
    if (-not (Has-Prop $gwObj "__eos_error")) { $gateway = $gwObj }

    $targets = @()
    if ($gateway) { $targets += $gateway }
    $targets += @("1.1.1.1","8.8.8.8","www.microsoft.com")

    $pings = @()
    foreach ($t in $targets) {
        $r = Safe-Run { Test-Connection -ComputerName $t -Count 3 }
        if (Has-Prop $r "__eos_error") {
            $pings += [PSCustomObject]@{ Target=$t; Success=$false; AvgMs=$null; Error=$r.__eos_error }
        } else {
            $avg = $null
            try { $avg = [math]::Round((($r | Measure-Object -Property ResponseTime -Average).Average), 1) } catch { }
            $pings += [PSCustomObject]@{ Target=$t; Success=$true; AvgMs=$avg }
        }
    }

    $topCpu = Safe-Run { Get-Process | Sort-Object CPU -Descending | Select-Object -First 8 Name, Id, CPU, WorkingSet }

    $services = @()
    $svcNames = @("Spooler","wuauserv","BITS","WinDefend")
    foreach ($s in $svcNames) {
        $sv = Safe-Run { Get-Service -Name $s }
        if (Has-Prop $sv "__eos_error") {
            $services += [PSCustomObject]@{ Name=$s; Status="UNKNOWN"; StartType="UNKNOWN"; Error=$sv.__eos_error }
        } else {
            $services += [PSCustomObject]@{ Name=$sv.Name; Status=$sv.Status; StartType=$sv.StartType }
        }
    }

    return [PSCustomObject]@{
        DefaultGateway = $gateway
        Ping           = $pings
        TopCPU         = $topCpu
        Services       = $services
    }
}

function Get-EOSSecurity {
    $fwProfiles = Safe-Run { Get-NetFirewallProfile | Select-Object Name, Enabled }

    $mp = Safe-Run { Get-MpComputerStatus }
    $def = if (Has-Prop $mp "__eos_error") {
        [PSCustomObject]@{ __eos_error = $mp.__eos_error }
    } else {
        [PSCustomObject]@{
            AMServiceEnabled = $mp.AMServiceEnabled
            AntivirusEnabled = $mp.AntivirusEnabled
            RealTimeProtectionEnabled = $mp.RealTimeProtectionEnabled
            NISEnabled = $mp.NISEnabled
            SignatureAge = $mp.AntispywareSignatureAge
        }
    }

    # BitLocker puede devolver null si no está disponible / sin permisos / sin módulo
    $bit = Safe-Run { Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage }

    $rdp = Safe-Run {
        $v = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections).fDenyTSConnections
        if ($v -eq 0) { "ENABLED" } else { "DISABLED" }
    }

    $smb1 = Safe-Run { (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State }
    $listening = Safe-Run { Get-NetTCPConnection -State Listen | Select-Object -First 25 LocalAddress, LocalPort, OwningProcess }

    return [PSCustomObject]@{
        FirewallProfiles = (As-Array $fwProfiles)
        Defender         = $def
        BitLocker        = (As-Array $bit)          # ✅ ya no rompe si es null
        RDP              = $rdp
        SMB1             = $smb1
        ListeningTCP     = (As-Array $listening)
    }
}

function Invoke-EOSFixes {
    param([switch]$Apply)

    $isAdmin = Test-IsAdmin
    $actions = @()

    function Add-Action($name, $needsAdmin, $plan, [scriptblock]$doIt) {
        $canRun = (-not $needsAdmin) -or $isAdmin
        $status = if ($Apply -and $canRun) { "APPLIED" } else { "PLANNED" }
        $note = if ($needsAdmin -and (-not $isAdmin)) { "Requiere admin. Ejecutar PowerShell como administrador." } else { "" }

        $err = $null
        if ($Apply -and $canRun) {
            $r = Safe-Run { & $doIt | Out-Null }
            if ($r -and (Has-Prop $r "__eos_error")) { $err = $r.__eos_error }
        }

        $actions += [PSCustomObject]@{
            Name       = $name
            NeedsAdmin = $needsAdmin
            CanRunNow  = $canRun
            Mode       = if ($Apply) { "apply" } else { "dry-run" }
            Status     = $status
            Plan       = $plan
            Note       = $note
            Error      = $err
        }
    }

    Add-Action "Red: limpiar caché DNS" $true "ipconfig /flushdns" { ipconfig /flushdns }
    Add-Action "Red: reset Winsock (requiere reinicio)" $true "netsh winsock reset" { netsh winsock reset }
    Add-Action "Windows Update: reiniciar servicios (WU/BITS)" $true "Restart-Service wuauserv, BITS" { Restart-Service wuauserv -Force; Restart-Service BITS -Force }
    Add-Action "Impresión: reiniciar Spooler" $true "Restart-Service Spooler" { Restart-Service Spooler -Force }
    Add-Action "Sistema: limpiar temporales de usuario (7 días)" $false "Borrar %TEMP% antiguos" {
        $temp = $env:TEMP
        Get-ChildItem $temp -Recurse -Force | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force -Recurse
    }

    return [PSCustomObject]@{
        IsAdmin           = $isAdmin
        Apply             = [bool]$Apply
        Actions           = $actions
        RebootRecommended = $true
    }
}

# MAIN envelope
$errors = @()
$data = $null

try {
    switch ($Mode) {
        "inventory"   { $data = Get-EOSInventory }
        "diagnostics" { $data = Get-EOSDiagnostics }
        "security"    { $data = Get-EOSSecurity }
        "fix"         { $data = Invoke-EOSFixes -Apply:$Apply }
        default       { throw "Modo no soportado: $Mode" }
    }
} catch {
    $errors += ($_ | Out-String)
}

[PSCustomObject]@{
    ok     = ($errors.Count -eq 0)
    mode   = $Mode
    apply  = [bool]$Apply
    data   = $data
    errors = $errors
} | ConvertTo-Json -Depth 10
