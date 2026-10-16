import streamlit as st
# importar funcion de analisis
from modulo2_rag import analizar_incidentes_con_gemini
from Ingest_modulo1 import (
    ingestar_logs,
    ingestar_firewall,
    calcular_estadisticas,
    guardar_en_db,
    ruta_archivo,
    ruta_firewall,
    
)
from backend_logs import generar_informe_pdf, filtrar_eventos, registrar_informe
from auth import verificar_usuario, tiene_permiso, registrar_usuario, listar_usuarios
from db import crear_tablas, listar_informes, obtener_informe
# pagina web
st.set_page_config(
    page_title="Colmena Technologies",
    page_icon="🛡️",
    layout="centered"
)

#Ventana de incio de sesion 
crear_tablas ()
if "rol" not in st.session_state:
    st.session_state.rol = None
#Inicio de sesion
if st.session_state.rol is None:
    st.title("Iniciar sesion")
    with st.form("login"):
        usuario = st.text_input("Usuario")
        contrasena = st.text_input("Contraseña", type="password")
        entrar = st.form_submit_button("Entrar")

    if entrar:
        rol = verificar_usuario(usuario, contrasena)
        if rol:
            st.session_state.rol = rol
            st.session_state.usuario = usuario
        else:
            st.error("Usuario o contraseña Incorrectos")
    st.stop()

    #Administrar usuarios
if tiene_permiso(st.session_state.rol, "gestionar_usuarios"):
    with st.sidebar.expander("Administrar usarios"):
        with st.form("nuevo_usuario", clear_on_submit=True):
            nuevo = st.text_input("Nuevo usuario")
            clave = st.text_input("Contraseña", type="password")
            rol_nuevo = st.selectbox("Rol", ["analista", "administrador"])
            crear = st.form_submit_button("Crear usuario")
        if crear:
            ok, mensaje = registrar_usuario(nuevo, clave, rol_nuevo)
            if ok:
                st.success(mensaje)
            else:
                st.error(mensaje)
        st.dataframe(listar_usuarios(), use_container_width=True)
                                   

# Encabezados
st.title("Asistente IA de respuesta a incidentes")
st.caption("Plataforma de Análisis de logs y detección de amenazas asistida por RAG y Gemini API")

# Barra lateral
with st.sidebar:
    st.write(f"Sesion: {st.session_state.usuario}  ({st.session_state.rol})")
    if st.button("Cerrar sesion"):
        st.session_state.clear()
        st.rerun()
    st.header("Estado del sistema")
    st.success("Motor RAG (ChromaDB): Activo")
    st.info("Modelo LLM: Gemini")
    st.markdown("---")
    st.markdown("Colmena Technologies\nPráctica Profesional Ciberseguridad e IA")

logs_cvs = ingestar_logs(ruta_archivo)
logs_fw  = ingestar_firewall(ruta_firewall)
datos = logs_cvs + logs_fw
resumen = calcular_estadisticas(datos)

#Va a evitar que Streamlit guarde los eventos repetidamente
#en cada interaccion
#usando st.session_state como memoria temporal
# para optimizar el rendimiento
if "eventos_guardados" not in st.session_state:
    guardar_en_db(logs_cvs, logs_fw)
    st.session_state.eventos_guardados = True
    
st.subheader("Resumen de Eventos")

st.metric("Total de eventos analizados", resumen["total"])
st.subheader("IP sospechosas")
if resumen["sospechosos"]:
    st.dataframe(
        [{"IP": ip, "Fallos": n } for ip,n in resumen["sospechosos"].items()],
        use_container_width=True
    )
else:
    st.success("No hay IPs sospechosas. ")

st.subheader("Ataques Automatizados")
if resumen["ataques"]:
    for ip in resumen["ataques"]:

        st.error(f"Ataque automatizado detectado desde {ip}")
else:
    st.success("No se detectaron ataques automatizados. ")

#Correlaciones 
st.subheader("Correlacion de eventos")
if resumen ["correlaciones"]:
    for ip in resumen["correlaciones"]:

        st.error(f"Fallos seguidos de un acceso exitoso desde {ip}. Revisar si la cuenta fue comprometida")
else:
    st.success("No se encontraron correlaciones entre fallos y accesos exitosos")


#Escaneos de puertos
st.subheader("Posibles escaneos de puertos")
if resumen["escaneos"]:
    for ip in resumen["escaneos"]:
        st.warning(f"Posible escaneo de puertos desde{ip}")
else:
    st.success("No se detectaron escaneos de puertos.")


st.subheader("Informe") 
texto = (
    f"Total de eventos: {resumen['total']}\n"
    f"IPs sospechosas: {resumen['sospechosos']}\n"
    f"Ataques automatizados: {resumen['ataques']}\n"
    f"Posibles escaneos de puertos: {resumen['escaneos']}\n"

    )

st.subheader("Eventos")# Ver los eventos individuales del log
ip_filtro = st.text_input("Filtrar por IP")
estados = st.multiselect("Estado", ["OK","FAIL","DENY"], default=["OK","FAIL", "DENY"])
filas =  filtrar_eventos(datos, ip_filtro, estados)


st.dataframe(filas)
st.caption(f"Mostrando {len(filas)} eventos")
#Descargar informe en docmento pdf
st.download_button(
    "Descargar informe (PDF)",
    data=generar_informe_pdf(resumen),
    file_name="informe_logs.pdf",
    mime="application/pdf",
    on_click=registrar_informe,
    args=(resumen,),
)
st.subheader("Historial de informes")
informes = listar_informes()
if informes:
    #realciona cada id con el texto
    opciones = {i["id"]: f"{i['nombre_archivo']} ({i['creado']})" for i in informes}
    elegido = st.selectbox(
        "Elige un informe guardado",
        #solo va a dar los id
        list(opciones),
        #recibe un id y devuelve un texto y se usa para mostrar cada opcion
        format_func=lambda id_informe: opciones[id_informe],
    )
    nombre, contenido = obtener_informe(elegido)
    st.download_button(
        "Descargar informe guardado",
        data=contenido,
        file_name=nombre,
        mime="application/pdf",
        key="descargar historial", #Es para que se distinga los botones de descarga
    )
else:
    st.info("Todavía no hay informes guardados")

st.divider()    


        
# Inicializar historial de conversación si no existe
if "messages" not in st.session_state:
    st.session_state.messages = [
        {
            "role": "assistant",
            "content": "Hola, soy tu asistente de seguridad SOC. ¿Qué eventos sospechosos o logs deseas analizar hoy?"
        }
    ]

# Renderizar los mensajes del historial
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

#  Entrada de texto
if prompt := st.chat_input("Escribe tu consulta (Ej: ¿hay intentos de acceso no autorizados desde IPs externas?)", key="chat_input_soc"):
    # Agregar y mostrar mensaje del usuario
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Generar y mostrar respuesta de la IA
    with st.chat_message("assistant"):
        with st.spinner("Consultando logs en ChromaDB y analizando con IA..."):
            try:
                respuesta_ia = analizar_incidentes_con_gemini(prompt)
                st.markdown(respuesta_ia)
                st.session_state.messages.append({"role": "assistant", "content": respuesta_ia})
            except Exception as e:
                st.error(f"Error al procesar la consulta: {e}")

                