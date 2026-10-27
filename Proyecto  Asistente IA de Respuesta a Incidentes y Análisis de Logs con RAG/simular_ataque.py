import urllib.parse
import urllib.request

URL = "http://127.0.0.1:5000/login"
USUARIO = "Prueba 1" # cuenta de prueba que existe

# Envia 10 intentos seguidos con contraseñas incorrectas(fuerza bruta)
for i in range(10):
    datos = urllib.parse.urlencode({"usuario": USUARIO, "clave": f"clave_mala_{i}"}).encode()
    urllib.request.urlopen(URL, data=datos) # Envia el formulario como si fuera una persona
    print(f" Intento{i + 1} enviado ")

#Enumeracion de usuarios prueba muchos nombres que noo existen
USUARIOS_FALSOS = ["admin", "root", "soporte", "test", "invitado", "ventas"]

for usuario in USUARIOS_FALSOS:
    datos = urllib.parse.urlencode({"usuario": usuario, "clave": "123456"}).encode()
    urllib.request.urlopen(URL, data=datos)
    print(f" Probando usuario: {usuario} ")