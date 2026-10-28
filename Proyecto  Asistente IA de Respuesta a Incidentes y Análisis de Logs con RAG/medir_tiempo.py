import time
import urllib.parse
import urllib.request

URL = "http://127.0.0.1:5000/login"

def medir(usuario, veces=10):
    """Devuelve el tiempo promedio de respesta del login, en milisegundos"""
    total = 0
    for _ in range(veces):
        datos = urllib.parse.urlencode({"usuario": usuario, "clave": "clave_mala"}).encode()
        inicio = time.perf_counter()
        urllib.request.urlopen(URL, data=datos)
        total += time.perf_counter() - inicio # Suma lo que tardo
    return total / veces * 1000

print(f" Usuario que SI existe: {medir('Prueba 1'):.1f} ms")
print(f" usuario que NO existe: {medir('usuario_inventado'):.1f} ms")