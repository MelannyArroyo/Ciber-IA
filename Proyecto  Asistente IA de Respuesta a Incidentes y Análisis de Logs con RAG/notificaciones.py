import os
import smtplib #Libreria que conecta con el servidor del correo y envia el mensaje
SEVERIDAD = {
    "POSIBLE_COMPROMISO": "ALTO",
    "POSIBLE_COMPROMISO_WEB": "ALTO",
    "ATAQUE_MULTIFUENTE": "ALTO",
    "ATAQUE_AUTOMATIZADO": "MEDIO",
    "ATAQUE_AUTOMATIZADO_WEB": "MEDIO",
    "ESCANEO_PUERTOS": "MEDIO",
    "VARIOS_DISPOSITIVOS": "MEDIO",
    "ENUMERACION_USUARIOS": "INFORMATIVO",
}
from email.message import EmailMessage #Sirve para armar el correo
from dotenv import load_dotenv
from db import consultar_alertas, marcar_alerta_enviada, agregar_mensaje_ticket


load_dotenv()
# Leen el .env el correo que envia, la contraseña de la aplicacion 
#y el correo que recibe
REMITENTE = os.getenv("CORREO_REMITENTE")
CLAVE = os.getenv("CORREO_CLAVE")
DESTINO = os.getenv("CORREO_DESTINO")

def enviar_correo(asunto, cuerpo):
    """Envia un correo y se devuelve si se envio"""
    if not REMITENTE or not CLAVE or not DESTINO:
        print("Correo no configurado en el .env, no se envia")
        return False

    mensaje = EmailMessage()
    mensaje["Subject"] = asunto
    mensaje["From"] = REMITENTE
    mensaje["To"] = DESTINO
    mensaje.set_content(cuerpo)

    try:
        #se conecta con el servidor de gmail por el puerto 587, sin limite el gmail no responde
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as servidor:
            servidor.starttls()
            servidor.login(REMITENTE, CLAVE)
            servidor.send_message(mensaje)
            return True
    except Exception as e:
        print(f"No se pudo enviar el correo: {e}")
        return False

def enviar_alertas_pendientes():
    """Envia por correo las alertas con enviada = 0 y las marca como enviadas"""
    enviadas = 0
    for a in consultar_alertas(solo_pendientes=True):
        severidad = SEVERIDAD.get(a["tipo"], "MEDIO") # Si el tipo no esta en la lista, usa MEDIO   
        asunto = f"[{severidad}] {a['tipo']} desde {a['ip']}"
        cuerpo = (
            f"Severidad: {severidad}\n"
            f"Tipo: {a['tipo']}\n"
            f"Origen: {a['ip']}\n"
            f"Detalle: {a['detalle']}\n"
            f"Fecha: {a['creada']}\n\n" 
            "Revisar en el Asistente IA de logs"

        )
        if enviar_correo(asunto, cuerpo):
            marcar_alerta_enviada(a["id"])
            enviadas += 1
    return enviadas
TIPOS_LEGIBLES = {
    "CONTRASENA_OLVIDADA": "Olvidó su contraseña",
    "USUARIO_OLVIDADO": "Olvidó su usuario",
    "CUENTA_BLOQUEADA": "Cuenta bloqueada",
    "ERROR_APP": "Error en la app",
    "OTRO": "Otro problema",
}
def avisar_nuevo_ticket(id_ticket, tipo, correo, descripcion):
    """Avisa al administrador que llegó un ticket este no incluye contraseñas ni enlaces"""
    nombre_tipo = TIPOS_LEGIBLES.get(tipo, tipo)
    asunto = f"[TICKET #{id_ticket}] {nombre_tipo}"
    cuerpo = (
        f"Nuevo ticket de soporte #{id_ticket}\n"
        f"Tipo: {nombre_tipo}\n"
        f"Correo de contacto: {correo}\n"
        f"Descripción: {descripcion}\n\n"
        "Revisar el ticket en el sistema antes de desbloquear o cambiar culquier cuenta"
    )
    return enviar_correo(asunto, cuerpo)
def enviar_respuesta_ticket(id_ticket, correo, respuesta):
    """Envia al usuario la respuesta del administrador, este no incluye datos internos del sistema"""
    asunto = f"Respuesta a tu solicitud #{id_ticket}"
    cuerpo = (
        f"Hola, \n\n"
        f"Te respondemos sobre tu solicitud #{id_ticket}"
        f"{respuesta}\n\n"
        "Si el problema continúa, responde este correo o vuelve a enviar una solicitud desde el login."
    )
    return enviar_correo(asunto, cuerpo)
def responder_ticket(ticket, admin, respuesta):
    """Si el ticket tiene correo, responde por correo, si viene de la app responde en el chat del ticket"""
    if ticket["correo_contacto"]:
        return enviar_respuesta_ticket(ticket["id"], ticket["correo_contacto"], respuesta)
    return agregar_mensaje_ticket(ticket["id"], admin, respuesta, es_admin=True)

if __name__ == "__main__":
    ok = enviar_correo("Prueba SOC", "Correo de prueba del asistente de logs")
    print("Enviado" if ok else "No enviado")
