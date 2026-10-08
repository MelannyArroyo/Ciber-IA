import streamlit as st
# importar funcion de analisis
from modulo2_rag import analizar_incidentes_con_gemini

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

                