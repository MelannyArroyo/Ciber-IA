#Es una vogilancia automatica que analiza los logs y envia las alertas
#sin abrir la app, se ejecuta el programador de tareas de windows cada cierto tiempo
# Hace lo mismo que la app a la hora de iniciar sesion en guardar db y enviar alertas pendientes
#pero sin la interfaz
import os
import subprocess #Conecta con powershell para poder exportar los eventos
from datetime import datetime
from Ingest_modulo1 import ingestar_logs, ingestar_firewall, guardar_en_db, ruta_archivo, ruta_firewall
from notificaciones import enviar_alertas_pendientes
from pathlib import Path # Maneja rutas de archivos

#Ruta del script de PowerShell
RUTA_SCRIPT = Path(__file__).parent / "exportar_eventos.ps1"
#Archivo donde queda el registro en cada ejecucion 
RUTA_REGISTRO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vigilancia.log")

def exportar_eventos():
    """Ejecuta el script de PowerShell que actualiza eventos_windows.csv"""
    resultado = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(RUTA_SCRIPT)],
        capture_output=True, #Guarda lo que imprime el script
        text=True #Lo devuelve como texto no como bytes
    )
    #Si salio bien devuelve el mensaje, si fallo devuelve el error
    return resultado.stdout.strip() or resultado.stderr.strip()

def vigilar():
    """Lee los logs, guarda los eventos nuevos y envia las alertas pendientes"""
    exportacion = exportar_eventos() #Actualiza el archivo automaticamente
    logs_csv = ingestar_logs(ruta_archivo) # Lee el archivo nuevo     exportacion = exportar_eventos
    logs_fw = ingestar_firewall(ruta_firewall)
    nuevos = guardar_en_db(logs_csv, logs_fw)
    enviadas = enviar_alertas_pendientes()


    linea = f"[{datetime.now(): %Y-%m-%d %H:%M:%S}] Eventos nuevos: {nuevos} │ Alertas enviadas: {enviadas} │ Exportacion: {exportacion}"
    print(linea)
    #Guarda la linea al final del archivo de registro 
    with open(RUTA_REGISTRO, "a", encoding="utf-8-sig") as archivo:
        archivo.write(linea + "\n")

if __name__ == "__main__":
    vigilar()

    