import csv
import os
#Ruta hacia el archivo de logs 
ruta_archivo = os.path.join(os.path.dirname(__file__), "..", "archivos_logs", "sample_logs.csv")

print("--- INICIANDO INGESTA DE DATOS --")
try: 
     with open(ruta_archivo, mode='r', encoding='utf-8') as archivo:
        lector = csv.DictReader(archivo)
        contador = 0

        for fila in lector: 

            contador += 1
            print(f"Evento {contador}: IP={fila.get('ip_address')}, Usuario={fila.get('Usuario')}, Estado={fila.get('Estado')}")

        print(f"\n-- INGESTA FINALIZADA CON EXITO: {contador} registros procesados ---")

except FileNotFoundError:
    print(f"Error: No se encontro el archivo en la ruta {ruta_archivo}. Revisa la ruta ")