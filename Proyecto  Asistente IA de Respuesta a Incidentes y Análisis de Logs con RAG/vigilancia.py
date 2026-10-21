#Es una vogilancia automatica que analiza los logs y envia las alertas
#sin abrir la app, se ejecuta el programador de tareas de windows cada cierto tiempo
# Hace lo mismo que la app a la hora de iniciar sesion en guardar db y enviar alertas pendientes
#pero sin la interfaz
import os
from datetime import datetime
from Ingest_modulo1 import ingestar_logs, ingestar_firewall, guardar_en_db, ruta_archivo, ruta_firewall
from notificaciones import enviar_alertas_pendientes

#Archivo donde queda el registro en cada ejecucion 
RUTA_REGISTRO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vigilancia.log")

def vigilar():
    """Lee los logs, guarda los eventos nuevos y envia las alertas pendientes"""
    logs_csv = ingestar_logs(ruta_archivo)
    logs_fw = ingestar_firewall(ruta_firewall)
    nuevos = guardar_en_db(logs_csv, logs_fw)
    enviadas = enviar_alertas_pendientes()

    linea = f"[{datetime.now(): %Y-%m-%d %H:%M:%S}] Eventos nuevos: {nuevos} │ Alertas enviadas: {enviadas}"
    print(linea)
    #Guarda la linea al final del archivo de registro 
    with open(RUTA_REGISTRO, "a", encoding="utf-8-sig") as archivo:
        archivo.write(linea + "\n")

if __name__ == "__main__":
    vigilar()

    