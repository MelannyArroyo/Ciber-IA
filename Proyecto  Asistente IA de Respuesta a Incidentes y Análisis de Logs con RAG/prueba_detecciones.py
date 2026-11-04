# Pruebas de las funciones de deteccion del modulo 1
# se usan eventos invetados para comprobar que cada deteccion
# encuentra los ataques y que no de falsas alarmas
from datetime import datetime, timedelta
from Ingest_modulo1 import (
    detectar_sospechosos,
    detectar_ataques,
    detectar_escaneos,
    correlacionar,
    es_trafico_de_ruido,
    interpretar_linea,
    leer_fecha,
    correlacionar_fuentes,
    es_cuenta_de_sistema,
    detectar_enumeracion,
    detectar_varios_dispositivos,
    niveles_de_riesgo,
    
)
BASE = datetime(2026, 10, 16, 10, 0, 0)#Hora de inicio fija para que las pruebas den siempre el mismo resultado

def evento(ip, estado, segundos, usuario="admin", puerto=None):
    """Crea un evento de prueba a BASE + segundos"""
    return {
        "ip": ip,
        "usuario": usuario,
        "estado": estado,
        "tiempo": BASE + timedelta(seconds=segundos),
        "puerto": puerto,
    }
# fuerza bruta 10 fallos en 20 segundos se marca como ataque
def test_fuerza_bruta_detectada():
    registros = [evento("10.0.0.5", "FAIL", i * 2) for i in range(10)]
    assert detectar_ataques(registros)["10.0.0.5"] == "ATAQUE AUTOMATIZADO"

#Pocos fallos separados por 10min no se marcan como ataque
def test_error_humano_no_es_ataque():
    registros = [evento("10.0.0.6", "FAIL", i * 600) for i in range(3)]
    assert detectar_ataques(registros)["10.0.0.6"] == "Error humano aislado"

# Con 6 fallos la IP pasa el umbral de 5 y se marca como sospechosa
def test_ip_sospechosa_por_volumen():
    registros = [evento("10.0.0.7", "FAIL", i * 60) for i in range(6)]
    assert detectar_sospechosos(registros)

# Con solo 2 fallos la IP no debe de aparecer como sospechosa
def test_pocos_fallos():
    registros = [evento("10.0.0.8", "FAIL", 0), evento("10.0.0.8", "FAIL", 60)]
    assert detectar_sospechosos(registros) == {}

#Escaneo: Una IP bloqueada wn 12 puertos distintos en pocos segundos
def test_escaneo_de_puertos():
    registros = [
        evento("203.0.113.9", "DENY", i, usuario="firewall", puerto=str(20 + i))
        for i in range(12)
    ]
    assert detectar_escaneos(registros) == ["203.0.113.9"]

#Muchos bloqueos al mismo puerto no son un escaneo 
def test_mismo_puerto():
    registros = [
        evento("203.0.113.10", "DENY", i, usuario="firewall", puerto="443")
        for i in range(12)
    ]
    assert detectar_escaneos(registros) == []

#Varios fallos y luego un acceso OK dentro de 10min
def test_correlacion_fallos_y_acceso():
    registros = [evento("10.0.0.9", "FAIL", i * 10) for i in range(5)]
    registros.append(evento("10.0.0.9", "OK", 120))
    assert correlacionar(registros) == ["10.0.0.9"]

#Si el acceso OK llega una hora despues ya no se relaciona con el fallo
def test_acceso_lejano_no_correlaciona():
    registros = [evento("10.0.0.10", "FAIL", 0), evento("10.0.0.10", "OK", 3600)]
    assert correlacionar(registros) == []

#El trafico local se descarta como ruido
#Pero una IP externa hacia la red interna no 
def test_trafico_de_ruido():
    assert es_trafico_de_ruido("127.0.0.1", "8.8.8.8") is True
    assert es_trafico_de_ruido("192.168.1.10", "192.168.1.255") is True
    assert es_trafico_de_ruido("203.0.113.9", "192.168.1.10") is False

#Cambiamos DROP por DENY y se guarda el puerto destino 
def test_interpretar_linea_firewall():
    linea = "2026-10-19 10:00:00 DROP TCP 203.0.113.9 192.168.1.10 51515 22 0 - - - - - - - RECEIVE"
    r = interpretar_linea(linea)
    assert r["ip"] == "203.0.113.9"
    assert r["estado"] == "DENY"
    assert r["puerto"] == "22"

#3 fallos de login y un bloqueo del firewall es un ataque en capas
def test_ataque_multifuente():
    logins = [evento("203.0.113.20", "FAIL", i * 5) for i in range(3)]
    firewall = [evento("203.0.113.20", "DENY", 120, usuario="firewall", puerto="22")]
    assert correlacionar_fuentes(logins, firewall) == ["203.0.113.20"]

#Si el bloqueo del firewall llega 2 horas despues, no se relacionan
def test_multifuente_lejano_no_correlacion():
    logins = [evento("203.0.113.21", "FAIL", 0)]
    firewall = [evento("203.0.113.21", "DENY", 7200, usuario="firewall", puerto="22")]
    assert correlacionar_fuentes(logins, firewall) == []


#Un texto que no es fecha se devuelve a un None en vez de detener el programa 
def test_fecha_invalida():
    assert leer_fecha("no es una fecha") is None

#Las cuentas de servicio de Windows se descartan,los usuarios reales no
def test_cuentas_de_sistema():
    assert es_cuenta_de_sistema("Servicio de red") is True
    assert es_cuenta_de_sistema("SERVICIO LOCAL") is True
    assert es_cuenta_de_sistema("DESKTOP-ABC$") is True
    assert es_cuenta_de_sistema("Melanny") is False

#Prueba distintos usuarios que no existen 
def test_enumeracion_detectada():
    registros = [
        {"ip": "10.0.0.20", "usuario": nombre, "estado": "FAIL", "tiempo": BASE, "motivo": "USUARIO_NO_EXISTE"}
        for nombre in ["admin", "root", "test", "soporte", "invitado"]
    ]
    assert detectar_enumeracion(registros) == {"10.0.0.20": 5}
# el mismo usuario 10 veces no es enumeracion porque es alguien que escribio mal su usuario
def test_mismo_usuario_no_es_enumeracion():
    registros = [
        {"ip": "10.0.0.21", "usuario": "admin", "estado": "FAIL", "tiempo": BASE, "motivo": "USUARIO_NO_EXISTE"}
        for _ in range (10)
    ]
    assert detectar_enumeracion(registros) == {}

# Mismo correo en el celular y compu con 5min de diferencia si se detecta 
def test_varios_dispositivos_detectado():
    registros = [
        {"ip": "127.0.0.1", "usuario": "ana", "estado": "OK", "tiempo": BASE,
         "correo_principal": "ana@correo.com", "dispositivo": "COMPUTADORA"},
         {"ip": "192.168..1.73", "usuario": "ana", "estado": "OK", "tiempo": BASE + timedelta(minutes=5),
          "correo_principal": "ana@correo.com", "dispositivo": "TELEFONO"},
    ]
    assert detectar_varios_dispositivos(registros) == ["ana@correo.com"]

def test_respuesta_dns_no_es_escaneo():
    registros = [
        {**evento("167.250.221.254", "DENY", i, usuario="firewall", puerto=str(50000 + i)),
            "puerto_origen": "53", "protocolo": "UDP"}
            for i in range(12)
    ]
    assert detectar_escaneos(registros) == []

def test_escaneo_desde_puerto_53_si_se_detecta():
    # si un atacante usa ese puerto desde una IP que no es de DNS
    registros = [
        {**evento("203.0.113.50", "DENY", i, usuario="firewall", puerto=str(20 + i)),
         "puerto_origen": "53", "protocolo": "UDP"}
         for i in range(12)
    ]
    assert detectar_escaneos(registros) == ["203.0.113.50"]

#Comprueba que una IP con un ataque alto y otro distinto sube a critico 
def test_riesgo_sube_con_varios_ataques():
    detecciones = [
        {"Origen": "10.0.0.1", "Severidad": "ALTO", "Tipo": "POSIBLE_COMPROMISO_WEB"},
        {"Origen": "10.0.0.1", "Severidad": "INFORMATIVO", "Tipo": "ENUMERACION_USUARIOS"},
    ]
    assert niveles_de_riesgo(detecciones)[0]["Nivel de riesgo"] == "CRITICO"
    
# Comprueba que salgan todos los origenes de los mas critico a lo mas leve
def test_riesgo_incluye_todos_los_origenes():
    detecciones = [
        {"Origen": "10.0.0.1", "Severidad": "ALTO", "Tipo": "POSIBLE_COMPROMISO_WEB"},
        {"Origen": "10.0.0.2", "Severidad": "MEDIO", "Tipo": "ESCANEO_PUERTOS"},
        {"Origen": "10.0.0.3", "Severidad": "INFORMATIVO", "Tipo": "ENUMERACION_USUARIOS"}
    ]
    niveles = [f["Nivel de riesgo"] for f in niveles_de_riesgo(detecciones)]
    assert niveles == ["ALTO", "MEDIO", "BAJO"]






#Corre todas las funciones y cuenta cuantas pasaron 
if __name__== "__main__":
    pruebas = [f for nombre, f in list(globals().items()) if nombre.startswith("test_")]
    pasaron = 0 
    for prueba in pruebas:
        try:
            prueba()
            print(f" OK{prueba.__name__} " )
            pasaron += 1
        except AssertionError:
            print(f" FALLO  {prueba.__name__} ")
    print(f"{pasaron} de {len(pruebas)} pruebas pasaron")






    