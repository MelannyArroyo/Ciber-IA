import sqlite3
import bcrypt #convierte la contraseña en codigo cifrado
from db import conectar

ROLES = ("administrador", "analista")

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
    
def verificar_usuario(nombre_usuario, contrasena):
    """Devuelve el rol si la contraseña es correcta, o None si no"""
    nombre_usuario = (nombre_usuario or "").strip()
    if not nombre_usuario or not contrasena:
        return None
    with conectar() as con:
        fila = con.execute(
            "SELECT contrasena_hash, rol FROM usuarios WHERE nombre_usuario = ?",
            (nombre_usuario,),
        ).fetchone()
    if fila is None:
        return None
    if bcrypt.checkpw(contrasena.encode("utf-8"), fila["contrasena_hash"].encode("utf-8")):
        return fila["rol"]
    return None 

PERMISOS = {
    "administrador": {"ver_panel", "usar_chat", "descargar_informe", "gestionar_usuarios"},
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
