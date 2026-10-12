import streamlit as st
# importar funcion de analisis
from modulo2_rag import analizar_incidentes_con_gemini
from Ingest_modulo1 import (
    ingestar_logs,
    ingestar_firewall,
    calcular_estadisticas,
    ruta_archivo,
    ruta_firewall,
    
)
from backend_logs import generar_informe_pdf

# pagina web
st.set_page_config(
    page_title="Colmena Technologies",
    page_icon="🛡️",
    layout="centered"
)

# Encabezados
st.title("Asistente IA de respuesta a incidentes")
st.caption("Plataforma de Análisis de logs y detección de amenazas asistida por RAG y Gemini API")

# Barra lateral
with st.sidebar:
    st.header("Estado del sistema")
    st.success("Motor RAG (ChromaDB): Activo")
    st.info("Modelo LLM: Gemini")
    st.markdown("---")
    st.markdown("Colmena Technologies\nPráctica Profesional Ciberseguridad e IA")

datos = ingestar_logs(ruta_archivo) + ingestar_firewall(ruta_firewall)
resumen = calcular_estadisticas(datos)

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
filas = [
    {"IP":r["usuario"], "Estado": r["estado"], "Fecha": r["tiempo"]}
    for r in datos
    if r["estado"] in estados and (not ip_filtro or ip_filtro in r["ip"])
]

st.dataframe(filas)
st.caption(f"Mostrando {len(filas)} eventos")
#Descargar informe en docmento pdf
st.download_button(
    "Descargar informe (PDF)",
    data=generar_informe_pdf(resumen),
    file_name="informe_logs.pdf",
    mime="application/pdf",
)

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

                