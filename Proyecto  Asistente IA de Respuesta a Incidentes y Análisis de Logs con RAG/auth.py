import sqlite3
import bcrypt #convierte la contraseña en codigo cifrado
from db import conectar,  guardar_acceso_web, fallos_recientes

ROLES = ("administrador", "analista")
#Hash falso es para que un usuario inexistentente tarde lo mismo
HASH_FALSO = bcrypt.hashpw(b"clave_que_no_se_usa", bcrypt.gensalt())
INTENTOS_MAXIMOS = 5 # Contraseñas antes de bloquear
MINUTOS_BLOQUEO = 5 # Duracion del bloqueo


def registrar_usuario(nombre_usuario, contrasena, rol="analista"):
    """Guarda un usuario con la contraseña cifrada"""
    nombre_usuario = (nombre_usuario or "").strip()
    if not nombre_usuario or not contrasena:
        return False, "Usuario y contraseña son obligatorios "
    if len(contrasena) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."
    if len(contrasena.encode("utf-8")) > 72:
        return False, "La contraseña es demasiado larga (maximo 72 caracteres)"
    if rol not in ROLES:
        return False, "Rol no valido"

    contrasena_hash = bcrypt.hashpw(contrasena.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    try:
        with conectar() as con:
            con.execute(
                "INSERT INTO usuarios (nombre_usuario, contrasena_hash, rol) VALUES (?, ?, ?)",
                (nombre_usuario, contrasena_hash, rol),
            )
        return True, "Usuario registrado."
    except sqlite3.IntegrityError:
        return False, "Ese usuario ya existe."
    
def verificar_usuario(nombre_usuario, contrasena, ip="LOCAL", agente=""):
    """Devuelve el rol si la contraseña es correcta, o None si no. Registra cada intento"""
    nombre_usuario = (nombre_usuario or "").strip()
    if not nombre_usuario or not contrasena:
        return None
    with conectar() as con:
        fila = con.execute(
        "SELECT contrasena_hash, rol FROM usuarios WHERE nombre_usuario = ?",
        (nombre_usuario,),
        ).fetchone()
    clave = contrasena.encode("utf-8")[:72] # bcrypt solo usa los primeros 72 bytes
    if fila is None:
        bcrypt.checkpw(clave, HASH_FALSO) # Gasta el mismo tiempo que la cuenta real
        estado, motivo, rol = "FAIL", "USUARIO_NO_EXISTE", None
    elif fallos_recientes(nombre_usuario, MINUTOS_BLOQUEO, sistema="APP") >= INTENTOS_MAXIMOS:
        bcrypt.checkpw(clave, HASH_FALSO) # se bloquea y no revisa la contraseña real
        estado, motivo, rol = "FAIL", "CUENTA_BLOQUEADA", None
    elif bcrypt.checkpw(clave, fila["contrasena_hash"].encode("utf-8")):
        estado, motivo, rol = "OK", "", fila["rol"]
    else: 
        estado, motivo, rol = "FAIL", "CLAVE_INCORRECTA", None

    # Registra el intento nunca la contraseña para que se pueda ver las detecciones
    dispositivo = "TELEFONO" if ("Android" in agente or "iPhone" in agente) else "COMPUTADORA"
    guardar_acceso_web(nombre_usuario, None, ip, dispositivo, agente, estado, motivo, sistema="APP")
    return rol


    
PERMISOS = {
    "administrador": {"ver_panel", "usar_chat", "descargar_informe", "gestionar_usuarios", "atender_tickets"},
    "analista": {"ver_panel", "usar_chat", "descargar_informe"},
}
    
def tiene_permiso(rol, accion):
    """Devuelve True si el rol puede hacer esa accion"""
    return accion in PERMISOS.get(rol, set())

def listar_usuarios():
    """Lista usuarios sin mostrar la contraseña cifrada"""
    with conectar() as con:
        filas = con.execute(
            "SELECT nombre_usuario, rol, creado FROM usuarios ORDER BY nombre_usuario"
        ).fetchall()
    return[dict(f) for f in filas]
