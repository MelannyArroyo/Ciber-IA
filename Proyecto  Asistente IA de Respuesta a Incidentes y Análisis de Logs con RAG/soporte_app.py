"""Interfaz del reporte de errores en la app y del chat con el administrador la logica esta en la db.py y notificaciones.py
aca solo se dibuja en la barra lateral"""
import streamlit as st
from db import (crear_ticket_app, contar_tickets_usuario, MAX_REPORTES_APP_X_HORA, listar_tickets_usuario,listar_mensajes_ticket, agregar_mensaje_ticket, 
                MAX_MENSAJES_CHAT)
from notificaciones import avisar_nuevo_ticket

ESTADOS_LEGIBLES = {
    "abierto": "Abierto",
    "en_proceso": "En proceso",
    "resuelto": "Resuelto",
    "cerrado": "Cerrado",
}
def mostrar_hilo(ticket):
    """Dibuja la descripcion y los mensajes del ticket como un chat"""
    with st.chat_message("user"):
        st.caption(f"{ticket['usuario']} · {ticket['creado']}")
        st.write(ticket["descripcion"])
    for m in listar_mensajes_ticket(ticket["id"]):
        with st.chat_message("assistant" if m["es_admin"] else "user"):
            quien = "Administrador" if m["es_admin"] else m["autor"]
            st.write(m["mensaje"])

def reporte_sidebar(usuario):
    """Boton de la barra lateral para reportar errores y chatear con el administrador"""
    with st.sidebar.expander("Reportar un problema", icon=":material/bug_report:"):
        with st.form("reporte_app", clear_on_submit=True):
            st.caption("Tipo: Error en la app")
            descripcion = st.text_area("Describe que pasó", max_chars=500)
            enviar = st.form_submit_button("Enviar reporte", key="enviar_reporte_app")
    if enviar:
        if not descripcion.strip():
            st.warning("Escribe una descripción.")
        elif contar_tickets_usuario(usuario) >= MAX_REPORTES_APP_X_HORA:
            st.warning("Enviaste varios reportes seguidos. Intenta más tarde.")
        else:
            ip = getattr(st.context, "ip_addess", None) or "LOCAL"
            id_nuevo = crear_ticket_app(usuario, descripcion, ip)
            avisar_nuevo_ticket(id_nuevo, "ERROR_APP", f"usuario de la app: {usuario}",
                                descripcion.strip())
            st.success(f"Reporte #{id_nuevo} enviado. El administrador de responderá aquí.")

        tickets = listar_tickets_usuario(usuario)
        if not tickets:
            return
        st.divider()
        opciones = {
            f"#{t['id']} · {ESTADOS_LEGIBLES.get(t['estado'], t['estado'])}": t
            for t in tickets
        }
        elegido = st.selectbox("Mis reportes", list(opciones), key="mis_reportes")
        t = opciones[elegido]
        mostrar_hilo(t)
        if t["estado"] == "cerrado":
            st.caption("Este reporte está cerrado.")
            return
        with st.form(f"chat_ticket_{t['id']}", clear_on_submit=True):
            mensaje = st.text_input("Escribir mensaje", max_chars=MAX_MENSAJES_CHAT)
            mandar = st.form_submit_button(icon=":material/send:", key=f"mandar_{t['id']}")
            if mandar and agregar_mensaje_ticket(t["id"], usuario, mensaje):
                st.rerun()


    