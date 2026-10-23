# Exporta los inicios de sesion de los ultimos 30 dias 
# 4624 inicio correcto (OK) 4625 inicio fallido (FAIL)
$salida =  "$PSScriptRoot\..\archivos_logs\eventos_windows.csv"   #Donde se guardan los logs exportados

#Pide a windows los eventos 4624 y 4625 de los ultimos 30 dias 
$eventos = Get-WinEvent  -FilterHashtable @{
    LogName  = 'Security'
    Id       = 4624, 4625
    StartTime = (Get-Date).AddDays(-30)
} -ErrorAction SilentlyContinue

#Convierte cada evento en una fila con las columnas de CSV
$filas = foreach ($e in $eventos) {
    if ($e.Id -eq 4624) {
        $estado = "OK"
        $ip = $e.Properties[18].Value
    }else {
        $estado = "FAIL"
        $ip = $e.Properties[19].Value
    }
    [PSCustomObject]@{
        ip_address = $ip
        Usuario    = $e.Properties[5].Value
        Estado     = $estado
        Fecha      = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
    }
}
# Solo reemplaza el archivo si encontro eventos  asi no se borra el que ya existe 
if ($filas) {
    $filas | Export-Csv $salida -NoTypeInformation -Encoding  UTF8
    Write-Output "Eventos exportados: $($filas.Count)" 
} else {
    Write-Output "No se encontraron eventos, no se cambio el archivo"
}

    