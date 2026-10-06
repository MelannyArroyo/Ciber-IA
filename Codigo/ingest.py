import csv
import os
from collections import Counter #Para poder Contar OK,FAIL,DENY y fallos por ip

#Ruta hacia el archivo de logs 
ruta_archivo = os.path.join(os.path.dirname(__file__), "..", "archivos_logs", "sample_logs.csv")
COLUMNAS = ["ip_address", "Usuario", "Estado"]#Columnas que debe de tener obligatoriamente
#Cuantos fallos hace a una ip sospechosa 
UMBRAL_FALLOS = 3

def ingresar_logs(ruta):
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

                #si falta algun dato descarta la fila
                if not ip or not usuario or not estado:
                    descartadas += 1
                    continue
                registros.append({"ip": ip, "usuario": usuario, "estado": estado})
    except FileNotFoundError:
        print(f"Error no se encontro el archivo en {ruta}")

    except PermissionError:
        print("Error: no hay permiso para leer el archivo.")

    except UnicodeDecodeError:
        print("Error: el archivo tiene una codificacion no valida.")
        
    print(f"Registros validos: {len(registros)}   │ Descartados: {descartadas}")
    return registros


   

        