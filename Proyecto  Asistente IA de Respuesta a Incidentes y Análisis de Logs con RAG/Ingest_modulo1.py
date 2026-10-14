import csv
import os
from collections import Counter #Para poder Contar OK,FAIL,DENY y fallos por ip
from datetime import datetime, timedelta
import statistics
from db import crear_tablas,guardar_eventos,guardar_alerta_unica


#Ruta hacia el archivo de logs 
ruta_archivo = os.path.join(os.path.dirname(__file__), "..", "archivos_logs", "sample_logs.csv")
ruta_firewall = os.path.join(os.path.dirname(__file__), "..", "archivos_logs", "pfirewall.log")
#Se agrega mas formatos de fecha 
FORMATOS_FECHA = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y/%m/%dT%H:%M:%S",
    "%d/%m/%Y %H:%M:%S",

]
COLUMNAS = ["ip_address", "Usuario", "Estado"]#Columnas que debe de tener obligatoriamente
#Cuantos fallos hace a una ip sospechosa 
VENTANA_SEGUNDOS = 60
FALLOS_EN_VENTANA = 5
UMBRAL_FALLOS = 5
PUERTOS_EN_VENTANA = 10

#se añade un def para que lea la fecha 
def leer_fecha(texto):
    texto= (texto or "").strip()
    for formato in FORMATOS_FECHA:
        try:
            return datetime.strptime(texto, formato)
        except ValueError:
            continue
    return None


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
                tiempo = leer_fecha(fila.get("Fecha"))
                    

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
    puerto = partes[7] if len(partes) > 7 and partes[7].isdigit() else None 
    if ip in ("127.0.0.1", "::1"):
        return None

    if accion == "ALLOW":
        estado = "OK"
    elif accion == "DROP":
        estado= "DENY"
    else:
        return None
    tiempo = leer_fecha(f"{fecha} {hora}")

    
    return{"ip":ip, "usuario": "firewall", "estado": estado, "tiempo": tiempo, "puerto":puerto}

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

#Funcion para detectar escaneos en puertos
def detectar_escaneos(registros, umbral=PUERTOS_EN_VENTANA, ventana=VENTANA_SEGUNDOS):
    """Va a marcar IPs que bloqueadas tocan muchos puertos dsitintos en poco tiempo"""
    eventos = {}
    for r in registros:
        if r.get("puerto") and r["tiempo"] and r["estado"] == "DENY":
            eventos.setdefault(r["ip"], []).append((r["tiempo"], r["puerto"]))
    escaneos= []
    for ip, lista in eventos.items():
        lista.sort()
        for inicio, _ in lista:
            puertos = {p for t,p in lista if inicio <= t <= inicio + timedelta(seconds = ventana)}
            if len(puertos)>=umbral:
                escaneos.append(ip)
                break
    return escaneos 

#Correlacion de eventos 
def correlacionar(registros,venntana_segundos=600):
    """Va a marcar IPs con fallos seguidos de un acceso OK dentro de la ventana de tiempo"""
    eventos = {}
    #Agrupa los eventos por IP, descarta los que no tiene fecha
    for r in registros:
            if r["tiempo"] is not None:
                eventos.setdefault(r["ip"], []).append((r["tiempo"], r["estado"]))
    alertas = set()
    #Ordena cada IP por tiempo y busca cada fallo
    for ip, lista in eventos.items():
        lista.sort()
        for i, (t_fallo, estado) in enumerate(lista):
            if estado not in ("FAIL", "DENY"):
                continue
            # ve los eventos siguientes hasta que se acaba la ventana de 10min, si aparece OK la IP entra a la lista
            for t_ok, estado_ok in lista[i +1:]:
                if (t_ok - t_fallo).total_seconds() > venntana_segundos:
                    break
                if estado_ok == "OK":
                    alertas.add(ip)
                    break
                if ip in alertas:
                    break
    return sorted(alertas)

#Calcula cuantas cuentas distintas intento usar 
def usuarios_atacados(registros, ips):
    """Funciona para cada IP sospechosa, devuelve (usuario mas atacado, intentos, cuentas distintas)."""

    intentos = {}
    #Cuenta cuantas veces cada IP fallo con cada usuario
    for r in registros:
        if r["ip"] in ips and r["estado"] in ("FAIL", "DENY"):
            cuentas = intentos.setdefault(r["ip"], {})
            cuentas[r["usuario"]] = cuentas.get(r["usuario"], 0) + 1

    resultado = {}
    #Cada IP toma la cuenta con mas intentos y cuenta cuantas cuentas distintas probo
    for ip, cuentas in intentos.items():
        usuario, n = max(cuentas.items(), key=lambda x: x[1])
        resultado[ip] = (usuario, n, len(cuentas))
    return resultado

#Contar eventos de cada hora y marcar las que salen mucho del promedio
def detectar_anomalias_horarias(registros, factor=1.5):
    """Va a marcar las horas con mas eventos de lo normal"""
    conteo = {}
    #Agrupa eventos por hora, quitando los minutos y segundos
    for r in registros:
        if r["tiempo"] is not None:
            hora = r["tiempo"].replace(minute=0, second=0, microsecond=0)
            conteo[hora] = conteo.get(hora, 0) + 1

    if len(conteo) < 2:
        return []
 #Calcula la media y desviacion de los conteos
    valores = list(conteo.values())
    limite = statistics.mean(valores) + factor * statistics.pstdev(valores)
    #Decuelve las horas si el conteo supera el limite, ordenadas por fecha
    return sorted((hora, n) for hora, n in conteo.items() if n > limite)

def calcular_estadisticas(registros):
    sospechosos = detectar_sospechosos(registros)
    top= dict(sorted(sospechosos.items(), key=lambda x: x[1], reverse=True) [:10])
    ataques = [ip for ip, tipo in detectar_ataques(registros).items()
            if tipo == "ATAQUE AUTOMATIZADO"]
    return {
        "total": len(registros),
        "por_estado": resumen_por_estado(registros),
        "sospechosos": top,
        "ataques": ataques, 
        "escaneos" : detectar_escaneos(registros),  #Incluye el resultado en las estadisticas 
        "correlaciones" : correlacionar(registros),
        "usuarios" : usuarios_atacados(registros, list(top)),
        "anomalias" : detectar_anomalias_horarias(registros),
        
    }

def generar_resumen(registros):
    est = calcular_estadisticas(registros)
    lineas = [ 
        f"Total de eventos analizados: {est['total']}" ,
        f"Eventos por estado: {est['por_estado']}"
    ]
    if est["sospechosos"]:
        lineas.append("IP sospechosas (con mas fallos):")
        for ip, n in est["sospechosos"].items():
            lineas.append(f"- {ip}: {n} fallos")
    else:
            lineas.append("No hay IPs sospechosas. ")

    if est["ataques"]:
        lineas.append("IPs con ataque automatizado " + " ," .join(est["ataques"]))
    else:
        lineas.append("No se detectaron ataques automatizados. ")
    return "\n".join(lineas)

def a_esquema_rag(registro):
    """Convierte un registro del modulo 1 al formato que espera el modulo 2"""
    tiempo = registro["tiempo"]
    return { 
        "timestamp": tiempo.isoformat() if tiempo else "N/A",
        "event": f"Acceso{registro['estado']}",
        "src_ip": registro["ip"],
        "dst_ip": "N/A",
        "user": registro["usuario"],
        "status": registro["estado"],
    }
def _texto(t):
    return t.strftime("%Y-%m-%d %H:M:%S") if t else None 

def guardar_en_db(logs_csv, logs_fw):
    crear_tablas()
    filas = [(r["ip"], r["usuario"], r["estado"], _texto(r["tiempo"]), "csv") for r in logs_csv]
    filas +=  [(r["ip"], r["usuario"], r["estado"], _texto(r["tiempo"]), "firewall") for r in logs_fw]
    nuevos = guardar_eventos(filas)

    est = calcular_estadisticas(logs_csv + logs_fw)
    for ip in est["ataques"]:
        guardar_alerta_unica("ATAQUE_AUTOMATIZADO", ip, "Rafaga de fallos en poco tiempo")
    for ip in set(est["escaneos"]):
        guardar_alerta_unica("ESCANEO_PUERTOS", ip, "Muchos puertos bloqueados en la ventana")
    for ip in est["correlaciones"]:
        guardar_alerta_unica("POSIBLE_COMPROMISO",ip, "Fallos seguidos de acceso OK")
    return nuevos
 

#Solo va a correr si ejecuta este archivo directamente
if __name__ == "__main__":
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
        print(leer_fecha("2026-10-06T10:15:30Z"), leer_fecha("08/10/2026 9:06:00"), leer_fecha("basura"))
    print("\n---RESUMEN PARA LA IA---")
    print(generar_resumen(datos))
    


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

    
    print("\nAnalisis por ventana de tiempo:    ")
    for ip, tipo in detectar_ataques(datos).items():
        print(f"  -{ip}: {tipo}")
    print(f"\n    INGESTA FINALIZADA CON EXITO: {len(datos)}  registros procesados   ")
    datos_rag = [a_esquema_rag(r) for r in datos]
    print("\n---Ejemplo de registro de formato RAG---")
    print(datos_rag[0])

   

    
    
                


             


