# READ-ONLY: Identificacion del SSD ADATA SU650 sin privilegios elevados
# Ejecutar: powershell.exe -ExecutionPolicy Bypass -File identify_ssd.ps1

$LogFile = "C:\SM2258XT_MPTool\log\identify_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
New-Item -ItemType Directory -Path (Split-Path $LogFile) -Force -ErrorAction SilentlyContinue | Out-Null
Start-Transcript -Path $LogFile -Append

Write-Host "=== IDENTIFICACION SSD ADATA SU650 ==="
Write-Host "Fecha: $(Get-Date)"
Write-Host ""

# 1. Discos fisicos
Write-Host "[1] DISCOS FISICOS DETECTADOS:"
Get-PhysicalDisk | ForEach-Object {
    Write-Host ("  DeviceID: " + $_.DeviceId)
    Write-Host ("  FriendlyName: " + $_.FriendlyName)
    Write-Host ("  SerialNumber: " + $_.SerialNumber)
    Write-Host ("  MediaType: " + $_.MediaType)
    Write-Host ("  BusType: " + $_.BusType)
    Write-Host ("  Size: " + $_.Size + " bytes (" + [math]::Round($_.Size/1GB,2) + " GB)")
    Write-Host ("  HealthStatus: " + $_.HealthStatus)
    Write-Host ""
}

# 2. Discos WMI (mas detalle)
Write-Host "[2] DISCOS WMI:"
Get-WmiObject Win32_DiskDrive | ForEach-Object {
    Write-Host ("  Index: " + $_.Index)
    Write-Host ("  Model: " + $_.Model)
    Write-Host ("  InterfaceType: " + $_.InterfaceType)
    Write-Host ("  MediaType: " + $_.MediaType)
    Write-Host ("  Size: " + $_.Size)
    Write-Host ("  SerialNumber: " + $_.SerialNumber)
    Write-Host ("  FirmwareRevision: " + $_.FirmwareRevision)
    Write-Host ("  PNPDeviceID: " + $_.PNPDeviceID)
    Write-Host ""
}

# 3. Controladoras de almacenamiento
Write-Host "[3] CONTROLADORAS ALMACENAMIENTO:"
Get-WmiObject Win32_SCSIController | ForEach-Object {
    Write-Host ("  Name: " + $_.Name)
    Write-Host ("  DeviceID: " + $_.DeviceID)
    Write-Host ("  Manufacturer: " + $_.Manufacturer)
    Write-Host ""
}

# 4. Intentar Smart (solo lectura, algunos drivers lo permiten sin admin)
Write-Host "[4] INTENTO SMART (solo lectura):"
try {
    $smart = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ErrorAction Stop
    foreach ($s in $smart) {
        Write-Host ("  InstanceName: " + $s.InstanceName)
        Write-Host ("  PredictFailure: " + $s.PredictFailure)
        Write-Host ("  Reason: " + $s.Reason)
    }
} catch {
    Write-Host ("  SMART no accesible sin admin: " + $_.Exception.Message)
}

# 5. Identificar PhysicalDrive para el ADATA
Write-Host "[5] MAPEO PHYSICALDRIVE:"
$adata = Get-WmiObject Win32_DiskDrive | Where-Object { $_.Model -like "*ADATA*" }
if ($adata) {
    $driveNum = $adata.Index
    Write-Host ("  ADATA SU650 encontrado en: PhysicalDrive" + $driveNum)
    Write-Host ("  Modelo exacto: " + $adata.Model)
    Write-Host ("  Tamaño: " + $adata.Size + " bytes")
    
    # Guardar para uso posterior
    $driveNum | Out-File -FilePath "C:\SM2258XT_MPTool\target_drive.txt" -Encoding ASCII
    Write-Host ("  Guardado: C:\SM2258XT_MPTool\target_drive.txt = " + $driveNum)
} else {
    Write-Host "  ERROR: No se encontro ADATA SU650"
}

Write-Host ""
Write-Host "=== FIN IDENTIFICACION ==="
Write-Host "Log guardado en: $LogFile"
Stop-Transcript
