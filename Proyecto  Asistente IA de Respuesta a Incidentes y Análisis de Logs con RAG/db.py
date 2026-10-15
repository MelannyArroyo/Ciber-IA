import os
import sqlite3

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
            UNIQUE (ip, usuario, estado, tiempo, fuente,puerto)     
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
        """)
def a_texto(tiempo):
    return tiempo.strftime("%Y-%m-%d %H:%M:%S") if tiempo else None
def guardar_eventos(lista_eventos):
    with conectar() as con:
        cur = con.executemany(
            "INSERT OR IGNORE INTO eventos (ip, usuario, estado, tiempo, fuente, puerto) VALUES(?, ?, ?, ?, ?, ?)",
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
    """Va a crear la alerta solo si no existe una igual pendiente para  es IP"""
    with conectar () as con:
        existe = con.execute(
            "SELECT 1 FROM alertas WHERE tipo = ? AND ip = ? AND enviada = 0",
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
            "SELECT id,creando, nombre_archivo FROM informes ORDER BY creando DESC LIMIT ?",
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
    return(fila["nombre_archivo"], fila["comtenido"])

    
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
        sql+= " AND ip = ? "
        params.append
    if estado:
        sql+=  " AND ip = ? "
        params.append(estado)
    sql +=  " ORDER BY tiempo DESC LIMIT ? "
    params.append(limite)
    with conectar() as con:
        return [dict(f) for f in con.execute(sql, params).fetchall()]

def consultar_alertas(tipo=None, ip=None, solo_pendientes=False, limite=100):
    sql = "SELECT * FROM alertas WHERE 1=1"
    params = []
    if tipo:
        sql +=  " AND tipo = ? "
        params.append(tipo)
    if ip:
        sql +=  " AND tipo = ? "
        params.append(ip)
    if solo_pendientes:
        sql +=  " AND enviada = 0 "
    sql += "ORDER BY creada DESC LIMIT ?"
    params.append(limite)
    with conectar() as con:
        return [dict(f) for f in con.execute(sql,params).fetchall()]

  
  
#Solo corre cuando se ejecuta el archivo directamente
if __name__ == "__main__":
    crear_tablas()
    print("Base lista en:", RUTA_DB)

        