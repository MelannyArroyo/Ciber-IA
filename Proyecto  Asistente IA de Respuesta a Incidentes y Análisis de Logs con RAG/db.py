import os
import sqlite3
from datetime import datetime

DIAS_RETENCION = 90 # Dias que se guardan los eventos antes de borrarlos


RUTA_DB= os.path.join(os.path.dirname(os.path.abspath(__file__)), "soc.db")
#Abre la base como abrir un archivo de excel antes de escribir en el 
def conectar(): 
    """Va a abrir la conexion a la base y permite leer las filas por nombre de columna"""
    conexion = sqlite3.connect(RUTA_DB)
    conexion.row_factory = sqlite3.Row
    return conexion

def crear_tablas(): #escribe en el lenguaje SQL, las cuatro tablas cada una es como una hoja con columnas 
    """Crea las tablas si todavia no existen. Se puede ejecutar varias veces sin borrar datos"""
    
    with conectar() as con:
        #El "IF NOT EXISTS" sirve para que si la tabla ya existe no la borre ni la cree de nuevo
        con.executescript("""
            CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre_usuario TEXT NOT NULL UNIQUE,
            contrasena_hash TEXT NOT NULL,
            rol TEXT NOT NULL DEFAULT 'analista',
            creado TEXT DEFAULT (datetime('now', 'localtime'))
            );

            CREATE TABLE IF NOT EXISTS eventos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            usuario TEXT,
            estado TEXT,
            tiempo TEXT,
            fuente TEXT,
            puerto TEXT,
            original TEXT,
            UNIQUE (ip, usuario, estado, tiempo, fuente,puerto, original)     
            );

            CREATE TABLE IF NOT EXISTS alertas ( 
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            creada TEXT DEFAULT (datetime('now', 'localtime')),
            tipo TEXT NOT NULL,
            ip TEXT,
            detalle TEXT,
            enviada INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS informes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            creado TEXT DEFAULT (datetime('now', 'localtime')),
            nombre_archivo TEXT,
            contenido BLOB
            );

            CREATE TABLE IF NOT EXISTS cuentas_web (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            correo_principal TEXT NOT NULL,
            clave_hash BLOB NOT NULL
            ); 

            CREATE TABLE IF NOT EXISTS accesos_web (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tiempo TEXT DEFAULT (datetime('now','localtime')),
            usuario TEXT,
            correo_principal TEXT,
            ip TEXT,
            dispositivo TEXT,
            user_agent TEXT,
            estado TEXT, 
            motivo TEXT,
            sistema TEXT DEFAULT 'WEB'
            );

            CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            creado TEXT DEFAULT (datetime('now', 'localtime')),
            actualizado TEXT,
            tipo TEXT NOT NULL,
            correo_contacto TEXT NOT NULL,
            usuario TEXT,
            ip TEXT,
            descripcion TEXT NOT NULL,
            estado TEXT NOT NULL DEFAULT 'abierto',
            respuesta TEXT
            );

        

        """)
        # Si la tabla ya existia, no le agrega columnas se agrega en esta funcion 
        columnas = [c["name"] for c in con.execute("PRAGMA table_info(accesos_web)")] # Devuelve la lista de columnas de una tabla
        if "sistema" not in columnas:
            con.execute("ALTER TABLE accesos_web ADD COLUMN sistema TEXT DEFAULT 'WEB'") #Agrega una columna a la tabla que ya existe sin borrar datos

        
def a_texto(tiempo):
    return tiempo.strftime("%Y-%m-%d %H:%M:%S") if tiempo else None
def guardar_eventos(lista_eventos):
    with conectar() as con:
        cur = con.executemany(
            "INSERT OR IGNORE INTO eventos (ip, usuario, estado, tiempo, fuente, puerto, original) VALUES(?, ?, ?, ?, ?, ?, ?)",
            lista_eventos
        )
        return cur.rowcount #cuantos se insertaron realmente 

def contar_fallos_por_ip(minimo=5):
    with conectar() as con:
        filas = con.execute(
        """SELECT ip, COUNT(*) AS intentos
           FROM eventos 
           WHERE estado IN ('FAIL', 'DENY')
           GROUP BY ip
           HAVING COUNT(*) >= ?
           ORDER BY intentos DESC""",
        (minimo,),
    ).fetchall()
    return [dict(f) for f in filas]

def guardar_alerta_unica(tipo,ip,detalle=None):
    """Crea la alerta solo si no existe una igual para esa IP"""
    with conectar () as con:
        existe = con.execute(
            "SELECT 1 FROM alertas WHERE tipo = ? AND ip = ?",
            (tipo,ip),
        ).fetchone()
        if existe: 
            return None
        cur = con.execute(
            "INSERT INTO alertas (tipo, ip, detalle) VALUES (?, ?, ?)",
            (tipo, ip, detalle),
        )
        return cur.lastrowid

#Informes 
def guardar_informe(nombre_archivo, contenido):
    """Guarda el PDF (bytes) y devuelve su id"""
    with conectar() as con:
        cur = con.execute(
            "INSERT INTO informes (nombre_archivo, contenido) VALUES (?, ?)",
            (nombre_archivo, contenido)
        )
        return cur.lastrowid

def listar_informes(limite=20):
    """Lista informes sin cargar el contenido o se va a ser mas liviano"""
    with conectar() as con:
        filas = con.execute(
            "SELECT id,creado, nombre_archivo FROM informes ORDER BY creado DESC LIMIT ?",
            (limite,),
        ).fetchall()
        return[dict(f) for f in filas]
    
def obtener_informe(id_informe):
    """Devuelve (nombre_archivo, bytes) o None si no existe"""
    with conectar () as con: 
        fila = con.execute(
            "SELECT nombre_archivo, contenido FROM informes WHERE id = ?",
            (id_informe,),
        ).fetchone() 
    if fila is  None:
        return None
    return(fila["nombre_archivo"], fila["contenido"])

    
def guardar_alerta(tipo, ip=None, detalle=None):
    with conectar () as con:
        cur= con.execute(
            "INSERT INTO alertas (tipo, ip, detalle) VALUES(?, ?, ?)",
            (tipo, ip, detalle),
        )
        return cur.lastrowid

def consultar_eventos(ip=None, usuario=None, estado=None, limite=100):
    sql = "SELECT * FROM eventos WHERE 1=1"
    params = []
    if ip:
        sql += " AND ip = ? "
        params.append(ip)
    if usuario:
        sql+= " AND usuario = ? "
        params.append(usuario)
    if estado:
        sql+=  " AND estado = ? "
        params.append(estado)
    sql +=  " ORDER BY tiempo DESC LIMIT ? "
    params.append(limite)
    with conectar() as con:
        return [dict(f) for f in con.execute(sql, params).fetchall()]
    
#Busca alertas
def consultar_alertas(tipo=None, ip=None, solo_pendientes=False, limite=100):
    sql = "SELECT * FROM alertas WHERE 1=1"
    params = []
    if tipo:
        sql +=  " AND tipo = ? "
        params.append(tipo)
    if ip:
        sql +=  " AND ip = ? "
        params.append(ip)
    if solo_pendientes:
        sql +=  " AND enviada = 0 "
    sql += " ORDER BY creada DESC LIMIT ?"
    params.append(limite)
    with conectar() as con:
        return [dict(f) for f in con.execute(sql,params).fetchall()]
    
# las marca como enviadas 
def marcar_alerta_enviada(id_alerta):
    """Va a marcar una alerta como enviada para no repetirla"""
    with conectar() as con:
        con.execute("UPDATE alertas SET enviada = 1 WHERE id = ?", (id_alerta,))

def crear_cuenta_web(usuario, correo_principal, clave_hash):
    """Guarda una cuenta  de prueba del servidor web"""
    with conectar () as con: 
        con.execute(
            "INSERT OR IGNORE INTO cuentas_web (usuario, correo_principal, clave_hash) VALUES (?, ?, ?)",
            (usuario, correo_principal, clave_hash),
        )

def buscar_cuenta_web(usuario):
    """Devuelve la cuenta si existe, o None si no existe"""
    with conectar () as con: 
        return con.execute(
            "SELECT * FROM cuentas_web WHERE usuario = ?", (usuario,)
        ).fetchone()

def guardar_acceso_web( usuario, correo_principal, ip, dispositivo, user_agent, estado, motivo, sistema="WEB"):
    """ Guarda cada intento de inicio de sesion en el servidor web"""
    tiempo = datetime.now().strftime("%Y-%m-%d %H:%M:%S") #Fecha y hora del intento
    with conectar () as con: 
        con.execute(
        "INSERT INTO accesos_web(tiempo, usuario, correo_principal, ip, dispositivo, user_agent, estado, motivo, sistema) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (tiempo, usuario, correo_principal, ip, dispositivo, user_agent, estado, motivo, sistema),
           
        )
def leer_accesos_web():
    """Convierte los accesos del servidor web al formato que usan las detecciones"""
    with conectar () as con: 
        filas = con.execute(
            "SELECT tiempo, usuario, correo_principal, ip, dispositivo, estado, motivo, sistema FROM accesos_web"
        ).fetchall()
    registros = []
    for fila in filas: 
        #Convierte el texto de la fecha en un datetime, como en el Modulo 1 
  
        tiempo = datetime.strptime(fila["tiempo"], "%Y-%m-%d %H:%M:%S") if fila ["tiempo"] else None
#Solo corre cuando se ejecuta el archivo directamente
        registros.append({
            "ip": fila["ip"],
            "usuario": fila["usuario"],
            "estado": fila["estado"],
            "tiempo": tiempo,
            "puerto": None, # El login web no tiene puerto
            "correo_principal": fila["correo_principal"],
            "dispositivo": fila["dispositivo"],
            "motivo": fila["motivo"],
            "sistema": fila["sistema"] or "WEB" ,
        })
    return registros 


def limpiar_registros_antiguos(dias=DIAS_RETENCION):
    """Borra eventos y accesos web mas viejos que 'dias' para que la base no crezca sin limite"""
    limite = f"-{dias} days"
    with conectar() as con:
        eventos = con.execute(
            "DELETE FROM eventos WHERE tiempo <> '' AND tiempo < datetime('now', 'localtime', ?)",
            (limite,),
        ).rowcount
        accesos = con.execute(
            "DELETE FROM accesos_web WHERE tiempo <> '' AND tiempo < datetime('now', 'localtime', ?)",
            (limite,),
        ).rowcount

    borrados = eventos + accesos
    if borrados:
        with conectar() as con:
            con.execute("VACUUM") # Recupera el espacio que dejaron los registros borrados
    return borrados
def fallos_recientes(usuario, minutos, sistema="WEB"):
    """Cuenta las contraseñas incorrectas de un usuario en los ultimos minutos"""
    limite = f"-{minutos} minutes"
    with conectar() as con:
        # Count cuenta las filas que cumplen la condicion 
        return con.execute(
            "SELECT COUNT (*) FROM accesos_web WHERE usuario = ? AND sistema = ? AND motivo = 'CLAVE_INCORRECTA' "
            "AND tiempo >= datetime('now', 'localtime', ?)",
            (usuario, sistema, limite),
        ).fetchone()[0] #devuelve la fila con solo dato y lo saca
TIPOS_TICKET = ("CONTRASENA_OLVIDADA", "USUARIO_OLVIDADO", "CUENTA_BLOQUEADA", "ERROR_APP", "OTRO")
ESTADOS_TICKET = ("abierto", "en_proceso", "resuelto", "cerrado")
MAX_TICKETS_x_HORA = 3

def contar_tickets_recientes(ip, correo, horas=1):
    """Cuenta los tickets de la misma IP o del mismo correo en la ultima hora"""
    with conectar() as con:
        return con.execute(
            "SELECT COUNT(*) FROM tickets "
            "WHERE (ip = ? OR correo_contacto = ?) AND creado >= datetime('now', 'localtime', ?)",
            (ip, correo.strip().lower(), f"{horas} hours"),
        ).fetchone() [0]

def crear_ticket(tipo, correo_contacto, descripcion, ip, usuario=None):
    """Guarda un ticket nuevo y limita la descripcion a 500 caracteres"""
    if tipo not in TIPOS_TICKET:
        raise ValueError("Tipo de ticket no válido")
    descripcion = descripcion.strip()[:500]
    with conectar() as con:
        cur = con.execute(
            "INSERT INTO tickets (tipo, correo_contacto, usuario, ip, descripcion) VALUES (?, ?, ?, ?, ?)",
            (tipo, correo_contacto.strip().lower(), usuario, ip, descripcion),
        )
        return cur.lastrowid
def listar_tickets(estado=None, limite=100):
    """Listar tickets, los más recientes primero y filtra por estado si se indica"""
    sql = "SELECT * FROM tickets WHERE 1=1"
    params = []
    if estado:
        sql += "AND estado = ?"
        params.append(estado)
    sql += " ORDER BY creado DESC LIMIT ?"
    params.append(limite)
    with conectar () as con:
        return [dict(f) for f in con.execute(sql, params).fetchall()]

def actualizar_ticket(id_ticket, estado, respuesta=None):
    """Cambia el estado del ticket y si se indica se guarda la respuesta al administrador"""
    if estado not in ESTADOS_TICKET:
        raise ValueError("Estado de ticket no válido")
    with conectar() as con:
        con.execute(
            "UPDATE tickets SET estado = ?, respuesta =COALESCE(?, respuesta),"
            "actualizado = datetime('now', 'localtime') WHERE id = ?",
            (estado, respuesta, id_ticket),
        )


    
if __name__ == "__main__":
    crear_tablas()
    print("Base lista en:", RUTA_DB)

        