from flask import Flask, request, render_template_string
import bcrypt
from db import crear_tablas, crear_cuenta_web, guardar_acceso_web, buscar_cuenta_web, fallos_recientes

app = Flask(__name__)
# es para que un usuario inexistente tarde lo mismo que uno real evita los ataque de tiempo
HASH_FALSO = bcrypt.hashpw(b" clave_que_no_se_usa", bcrypt.gensalt())
INTENTOS_MAXIMOS = 5 # Contraseñas incorrectas antes de bloquear la cuenta
MINUTOS_BLOQUEO = 5 # Minutos que se revisan hacia atras es la duracion del bloqueo
crear_tablas()  # Crea tablas nuevas si no existen 

#Formulario HTML que sirve para registro y para login
FORMULARIO = """
<h1>{{ titulo }}</h1>
<p>{{ mensaje }}</p>
<form method="post">
    <input name="usuario" placeholder="Usuario" required><br><br>
    {% if registro %}
    <input name="correo" type="email" placeholder="Correo principal" required><br><br>
    {% endif %}
    <input name="clave" type="password" placeholder="Contrasena" required><br><br>
    <button type="submit">{{ boton }}</button>
</form>
"""
def tipo_dispositivo(agente):
    """Dice si el acceso viene de un telefono o de una computadora"""
    if "android" in agente.lower() or "iPhone" in agente.lower ():
        return "TELEFONO"
    return "COMPUTADORA"

@app.route("/registro", methods=["GET", "POST"])
def registro():
    mensaje = ""
    if request.method == "POST": #es la persona que envio el formulario
        usuario = request.form["usuario"].strip()
        correo = request.form ["correo"].strip().lower()
        clave = request.form["clave"]
        if buscar_cuenta_web(usuario):
            mensaje = "Ese usuario ya existe"
        else:
            # Guarda solo el hash, nunca la contraseña 
            clave_hash = bcrypt.hashpw(clave.encode("utf-8"), bcrypt.gensalt())
            crear_cuenta_web(usuario, correo, clave_hash)
            mensaje = "cuenta creada"
    return render_template_string(FORMULARIO, titulo="Registro", mensaje=mensaje,
                                  boton="Crear cuenta", registro=True)

@app.route("/login", methods=["GET", "POST"])
def login():
    mensaje = ""
    if request.method == "POST":
        usuario = request.form["usuario"].strip()
        clave = request.form["clave"]
        ip = request.remote_addr
        agente = request.headers.get("User-Agent", "")
        dispositivo = tipo_dispositivo(agente)

        cuenta = buscar_cuenta_web(usuario)
        if cuenta is None:
            bcrypt.checkpw(clave.encode("utf-8"), HASH_FALSO)# Es el mismo tiempo que la cuenta real
            estado, motivo, correo = "FAIL", "USUARIO_NO_EXISTE", None
        elif fallos_recientes(usuario, MINUTOS_BLOQUEO) >= INTENTOS_MAXIMOS:
            # Cuenta bloqueada ni si quiera se revisa la contraseña
            bcrypt.checkpw(clave.encode("utf-8"), HASH_FALSO) #Mismo tiempo de respuesta
            estado, motivo, correo = "FAIL", "CUENTA_BLOQUEADA", cuenta["correo_principal"]
        elif bcrypt.checkpw(clave.encode("utf-8"), cuenta["clave_hash"]):
            estado, motivo, correo = "OK", "", cuenta["correo_principal"]
        else:
            estado, motivo, correo = "FAIL", "CLAVE_INCORRECTA", cuenta["correo_principal"]
      
        #Guarda el intento SIN la contraseña
        guardar_acceso_web(usuario, correo, ip, dispositivo, agente, estado, motivo)
        print(f"Login {estado} | {usuario} | {correo} | {ip} | {dispositivo} | {motivo}")

        if estado == "OK":
            mensaje = f"Bienvenid(a), {usuario}. Entraste desde: {dispositivo}"
        else:
            #Mismo menaje siempre, para no dar pistas
            mensaje = "Usuario o contraseña incorrectos"
    return render_template_string(FORMULARIO, titulo="Iniciar sesion", mensaje=mensaje,
                                  boton= "Entrar", registro=False)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)