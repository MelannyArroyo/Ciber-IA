import csv
import os
from collections import Counter #Para poder Contar OK,FAIL,DENY y fallos por ip
from datetime import datetime, timedelta

#Ruta hacia el archivo de logs 
ruta_archivo = os.path.join(os.path.dirname(__file__), "..", "archivos_logs", "sample_logs.csv")
ruta_firewall = os.path.join(os.path.dirname(__file__), "..", "archivos_logs", "pfirewall.log")
COLUMNAS = ["ip_address", "Usuario", "Estado"]#Columnas que debe de tener obligatoriamente
#Cuantos fallos hace a una ip sospechosa 
VENTANA_SEGUNDOS = 60
FALLOS_EN_VENTANA = 5
UMBRAL_FALLOS = 10


def ingestar_logs(ruta):
    """Lee el CSV limpia cada fila y devuelve una lista de registros."""
    registros = []
    descartadas = 0

    try: 
        with open(ruta, mode='r', encoding='utf-8') as archivo:
            lector = csv.DictReader(archivo)
            #Revisa que existan todas las columnas 
            faltan = [c for c in COLUMNAS if c not in (lector.fieldnames or [])]
            if faltan:
                print(f"Error: Faltan columnas en CSV: {faltan}")
                return []
            for fila in lector:
                #Va a limpiar espacios y poner el estado en mayuscula
                ip = (fila.get("ip_address") or "").strip()
                usuario = (fila.get("Usuario")or "").strip()
                estado = (fila.get("Estado")or "").strip().upper()
                texto_fecha = (fila.get("Fecha") or "").strip()
                try:
                    tiempo = datetime.strptime(texto_fecha, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    tiempo = None

                #si falta algun dato descarta la fila
                if not ip or not usuario or not estado:
                    descartadas += 1
                    continue
                registros.append({"ip": ip, "usuario": usuario, "estado": estado, "tiempo": tiempo})
    except FileNotFoundError:
        print(f"Error no se encontro el archivo en {ruta}")

    except PermissionError:
        print("Error: no hay permiso para leer el archivo.")

    except UnicodeDecodeError:
        print("Error: el archivo tiene una codificacion no valida.")
        
    print(f"Registros validos: {len(registros)}   │ Descartados: {descartadas}")
    return registros

def resumen_por_estado(registros):
    """Cuenta cuantos eventos hay de cada estado (OK,FAIL,DENY)."""
    return dict(Counter(r["estado"] for r in registros))
def detectar_sospechosos(registros, umbral=UMBRAL_FALLOS):
    """Devuelve las IPs con muchos fallos o bloqueos"""
    fallos = Counter(r["ip"] for r in registros if r["estado"] in ("FAIL", "DENY"))
    return {ip: n for ip, n in fallos.items() if n >= umbral}
def hay_rafaga(lista,ventana,minimo):
    lista.sort()
    for i in range(len(lista) - minimo + 1):
        if lista[i + minimo - 1] - lista[i] <= timedelta(seconds=ventana):
            return True
        return False
def detectar_ataques(registros, ventana=VENTANA_SEGUNDOS, minimo=FALLOS_EN_VENTANA):
    tiempos = {} 
    for r in registros:
        if r["estado"] in ("FAIL", "DENY") and r["tiempo"]:
            tiempos.setdefault(r["ip"], []).append(r["tiempo"])

    resultado = {}
    for ip, lista in tiempos.items():

        if hay_rafaga(lista,ventana,minimo):
            resultado[ip] = "ATAQUE AUTOMATIZADO"
        else:
            resultado[ip] =  "Error humano aislado"
            return resultado

        

def interpretar_linea(linea):
    partes = linea.split()
    if len(partes) < 5:
        return None
    fecha,hora,accion,protocolo, ip = partes [:5]
    if ip in ("127.0.0.1", "::1"):
        return None

    if accion == "ALLOW":
        estado = "OK"
    elif accion == "DROP":
        estado= "DENY"
    else:
        return None
    try:
        tiempo = datetime.strptime(f"{fecha} {hora}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        tiempo = None

    
    return{"ip":ip, "usuario": "firewall", "estado": estado, "tiempo": tiempo}

def ingestar_firewall(ruta):
    registros = []
    try:
        with open(ruta,mode='r', encoding='utf-8') as archivo:
            for linea in archivo:
                linea = linea.strip()
                if not linea or linea.startswith("#"):
                    continue
                registro = interpretar_linea(linea)
                if registro:
                    registros.append(registro)
    except FileNotFoundError:
        print("No se encontro pfirewall.log (se omite)")
    except PermissionError:
        print("No hay permiso para leer pfirewall.log")
    print(f"Eventos del firewall: {len(registros)}")
    return registros

#Solo va a correr si ejecuta este archivo directamente
if __name__ == "__main__":
    print("=" * 50)
    print("  INGESTA DE LOGS - MODULO 1")

    logs_csv = ingestar_logs(ruta_archivo)
    logs_fw = ingestar_firewall(ruta_firewall)
    datos = logs_csv + logs_fw 

    #Muestra cada evento 
    print("\n--- Eventos de CSV---")
    for numero, r in enumerate(logs_csv, start=1):
        print(f"Evento {numero}: IP={r['ip']}, Usuario={r['usuario']}, Estado={r['estado']}")

    print("\n--- Eventos del firewall ---") 
    for numero, r in enumerate(logs_csv, start=1):
        print(f"Evento {numero}: IP={r['ip']}, Usuario={r['usuario']}, Estado={r['estado']}")
    
    

    #resumen por estado
    print("Resumen por estado:" , resumen_por_estado(datos))

    #IPs sospechosas
    sospechosos= detectar_sospechosos(datos)
   

    if sospechosos:
        print("\nIPs sospechosas: ")
        for ip, cantidad in sospechosos.items():
            print(f"   - {ip}: {cantidad}  intentos fallidos")
    else:
        print("\n No se detectaron IPs sospechosas. ")
        print(detectar_ataques(datos))
    
    print("\nAnalisis por ventana de tiempo:    ")
    for ip, tipo in detectar_ataques(datos).items():
        print(f"  -{ip}: {tipo}")
    print(f"\n    INGESTA FINALIZADA CON EXITO: {len(datos)}  registros procesados   ")






   

        