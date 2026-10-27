from flask import Flask, request

# Crea la aplicacion web 
app = Flask(__name__)

@app.route("/") # Ruta principal es lo que se va abrir la pagina
def inicio ():
    ip= request.remote_addr
    agente = request.headers.get("User-Agent", "") #IP quien entra y navegador y sistema del dispositivo

    # si el user-agent menciona android i iphone es un telefono
    if "Android" in agente or "iPhone" in agente:
        dispositivo = "TELEFONO"
    else:
        dispositivo = "COMPUTADORA"

    # Muestra la visita en la terminal
    print(f"Visita desde {ip} | {dispositivo} | {agente}")

    # Lo que ve el usuario en el navegador 
    return f"<h1>Hola</h1><p>IP: {ip}</p><p>Dispositivo: {dispositivo}</p>"

if __name__ == "__main__":
    # este host permite que otros dispositivos de la misma red de wi fi entren
    app.run(host="0.0.0.0", port=5000)

