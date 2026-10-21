import streamlit as st
import pandas as pd
import json
from datetime import datetime
from modulo2_rag import analizar_incidentes_con_gemini, collection
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
from notificaciones import enviar_alertas_pendientes
# pagina web
st.set_page_config(
    page_title="Colmena SOC - Incident Response Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


st.markdown("""
<style>
    /* Fondo principal y tipografía */
    .stApp {
        background-color: #0b2545;
        color: #E2E8F0;
    }

    
    /* Encabezado Principal */
    .soc-header {
        background: linear-gradient(135deg, #1E293B 0%, #0F172A 100%);
        padding: 20px;
        border-radius: 12px;
        border-left: 6px solid #3B82F6;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5);
        margin-bottom: 25px;
    }
    .soc-title {
        font-size: 2.2rem;
        font-weight: 800;
        color: #f9c74f;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .soc-subtitle {
        color: #94A3B8;
        font-size: 0.95rem;
        margin-top: 5px;
    }

    /* Tarjetas de Métricas Custom */
    .metric-card {
        background-color: #1E293B;
        border-radius: 10px;
        padding: 16px;
        border: 1px solid #334155;
        box-shadow: 0 2px 4px rgba(0,0,0,0.2);
    }
    .metric-title {
        font-size: 0.85rem;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-weight: 600;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        margin: 5px 0;
    }
    
    /* Colores de Alerta/Estado */
    .status-critical { color: #d90429; }
    .status-warning { color: #F59E0B; }
    .status-success { color: #10B981; }
    .status-info { color: #3B82F6; }

    /* Estilos de Insignias (Badges) */
    .badge-critical {
        background-color: rgba(239, 68, 68, 0.15);
        color: #F87171;
        padding: 3px 10px;
        border-radius: 12px;
        border: 1px solid #EF4444;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .badge-success {
        background-color: rgba(16, 185, 129, 0.15);
        color: #34D399;
        padding: 3px 10px;
        border-radius: 12px;
        border: 1px solid #10B981;
        font-size: 0.8rem;
        font-weight: 600;
    }

    /* Pestañas personalizadas */
    .stTabs [data-baseweb="tab-list"] {
        gap: 10px;
        background-color: #0F172A;
        padding: 8px;
        border-radius: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 45px;
        border-radius: 6px;
        color: #94A3B8;
        font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1E293B !important;
        color: #38BDF8 !important;
        border-bottom: 2px solid #38BDF8;
    }
</style>
""", unsafe_allow_html=True)

#Ventana de Inicio de Sesion
crear_tablas()
if "rol" not in st.session_state:
    st.session_state.rol = None
#Inicio de sesion
if st.session_state.rol is None:
    st.title("Iniciar Sesion")
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
                                   

# Barra lateral
with st.sidebar:
    st.write(f"Sesion: {st.session_state.usuario}  ({st.session_state.rol})")
    if st.button("Cerrar sesion"):
        st.session_state.clear()
        st.rerun()
 

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
    enviar_alertas_pendientes()
    st.session_state.eventos_guardados = True



st.markdown("""
<div class="soc-header">
    <div class="soc-title">🛡️ Colmena CyberSOC <span class="badge-critical">Modo Activo</span></div>
    <div class="soc-subtitle">Plataforma Inteligente de Análisis de Logs y Triaje de Incidentes asistida por RAG & Gemini AI</div>
</div>
""", unsafe_allow_html=True)


with st.sidebar:
    st.markdown("###  Control del Sistema")
    st.markdown("---")
    
    st.markdown("#### 🟢 Estado del Pipeline")
    st.markdown("• **VectorDB:** <span class='status-success'>ChromaDB Conectado</span>", unsafe_allow_html=True)
    st.markdown("• **Modelo LLM:** <span class='status-info'>Gemini 2.5 / 2.0 Flash</span>", unsafe_allow_html=True)
    st.markdown("• **Embeddings:** <span class='status-info'>API / Fallback ONNX</span>", unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("#### 🛠️ Opciones de Sesión")
    if st.button("🗑️ Limpiar Historial de Chat", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

    st.markdown("---")
    st.caption("🏢 **Colmena Technologies**\nPráctica Profesional: Ciberseguridad & IA")

# --- PANEL SUPERIOR DE MÉTRICAS (KPIS INTUITIVOS) ---
try:
    total_logs_count = collection.count()
except Exception:
    total_logs_count = 4
amenazas = (len(resumen["ataques"]) + len(resumen["escaneos"])
            + len(resumen["correlaciones"]) + len(resumen["multifuente"]))
nivel = "ALTO" if amenazas else "BAJO"
clase_nivel = "status-critical" if amenazas else "status-success"
#La IP con mas fallos es la primera de sospechosos
ip_top = next(iter(resumen["sospechosos"]), "Ninguna")
fallos_top = resumen["sospechosos"].get(ip_top, 0)


col_kpi1, col_kpi2, col_kpi3, col_kpi4 = st.columns(4)

with col_kpi1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Eventos Ingestados</div>
        <div class="metric-value status-info">{total_logs_count}</div>
        <div style="font-size:0.75rem; color:#64748B;">Almacenados en ChromaDB</div>
    </div>
    """, unsafe_allow_html=True)

with col_kpi2:
     st.markdown(f"""
        <div class="metric-card">
            <div class="metric-title">Nivel de Amenaza Global</div>
            <div class="metric-value {clase_nivel}">{nivel}</div>
            <div style="font-size:0.75rem; color:#94A3B8;">{amenazas} amenaza(s) detectadas(s)</div>
        </div>
    """, unsafe_allow_html=True)

with col_kpi3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">IP Origen Sospechosa</div>
        <div class="metric-value  status-warning">{ip_top}</div>
        <div style="font-size:0.75rem; color:#F59E0B;">{fallos_top} intentos fallidos</div>
    </div>
    """, unsafe_allow_html=True)

with col_kpi4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-title">Eventos Analizados</div>
        <div class="metric-value status-success">{resumen['total']}</div>
        <div style="font-size:0.75rem; color:#10B981;">Logs de Windows y firewall</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# --- PESTAÑAS PRINCIPALES ---
tab_detecciones,tab_chat, tab_explorer, tab_report, tab_informes = st.tabs([
    "🚨 Detecciones",
    "💬 Asistente SOC & Triaje IA", 
    "📜 Explorador de Logs", 
    "📋 Generador de Reporte SOC",
    "📄 Informes",
])
#pestaña de detecciones: muestra los resultados del analisis de logs reales
with tab_detecciones:
    st.subheader("IPs sospechosas")
    if resumen ["sospechosos"]:
        st.dataframe(
            [{"IP": ip, "Fallos": n} for ip, n in resumen["sospechosos"].items()],
            use_container_width=True
        )
    else: 
        st.success("No hay IPs sospechosas")

    st.subheader("Ataques automatizados")
    if resumen["ataques"]:
        for ip in resumen["ataques"]:
            st.error(f"Ataque automatizado detectado desde {ip}")
    else:
        st.success("No se detectaron ataque automatizados")
    st.subheader("Correlacion de eventos")
    if resumen["correlaciones"]:
        for ip in resumen["correlaciones"]:
            st.error(f"Fallos seguidos de un acceso exitoso desde {ip}.Revisar si la cuenta fue comprometida")
    else:
        st.success("No se dectaron escaneos de puertos")

    st.subheader("Ataques en varias capas")
    if resumen["multifuente"]:
        for ip in resumen["multifuente"]:
            st.error(f" La IP {ip} tiene fallos de login y bloqueo del firewall en poco tiempo")
    else:
        st.success("No se detectaron ataques en varias capas")

    #Ranking de eventos mas frecuentes
    st.subheader("Eventos más frecuentes")
    col_ips, col_usuarios, col_puertos = st.columns(3)
    with col_ips:
        st.markdown("**IPs**")
        st.dataframe([{"IP": ip, "Eventos": n} for ip, n in resumen["ranking"]["ips"]],
                     use_container_width=True, hide_index=True)
    with col_usuarios:
        st.markdown("**Usuarios**")
        st.dataframe([{"Usuario": u, "Eventos": n} for u, n in resumen["ranking"]["usuarios"]],
                     use_container_width=True, hide_index=True)
    with col_puertos:
        st.markdown("**Puertos del Firewall**")
        st.dataframe([{"Puerto": p, "Eventos": n} for p, n in resumen["ranking"]["puertos"]],
                     use_container_width=True, hide_index=True)
        


#Pestaña de informes:descarga del PDF y el historial guardado
with tab_informes:
    st.subheader("Informe PDF del análisis")
    st.download_button(
        "Descargar informe (PDF)",
        data=generar_informe_pdf(resumen),
        file_name="Informe_logs.pdf",
        mime="application/pdf",
        on_click=registrar_informe,
        args=(resumen,),
    )
                       
    st.subheader("Historial de informes")
    informes = listar_informes()
    if informes:
        opciones = { i["id"]: f"{i['nombre_archivo']} ({i['creado']})" for i in informes}
        elegido = st.selectbox(
            "Elige un informe guardado",
            list(opciones),
            format_func=lambda id_informe: opciones[id_informe]
        )
        nombre, contenido = obtener_informe(elegido)
        st.download_button(
            "Descargar informe guardado",
            data=contenido,
            file_name=nombre,
            mime="application/pdf",
            key= "descargar_historial",

        )
    else:
        st.info("Todavia no hay informes guardados")

# --- PESTAÑA 1: CHATBOT SOC ---
with tab_chat:
    st.markdown("##### ⚡ Consultas Rápidas de Seguridad")
    
    col_b1, col_b2, col_b3 = st.columns(3)
    prompt_rapido = None

    if col_b1.button(" Analizar intentos fallidos de inicio de sesión", use_container_width=True):
        prompt_rapido =  "¿Qué IPs y usuarios tienen intentos fallidos de inicio de sesión y que tan grave es?"
    if col_b3.button(" Revisar bloqueos del firewall", use_container_width=True):
        prompt_rapido = "¿Qué conexiones bloqueó el firewall y hacia qué puertos?"

    st.markdown("---")

    # Inicializar historial del chat
    if "messages" not in st.session_state:
        st.session_state.messages = [
            {
                "role": "assistant",
                "content": " **Hola, soy el Asistente  + de Colmena Technologies.**\n\nEstoy listo para analizar la telemetría de red. Selecciona un botón de acceso rápido o escribe tu consulta en el campo inferior."
            }
        ]

    # Renderizar historial
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Captura de mensaje (Fuera de bucles para evitar duplicados)
    user_input = st.chat_input("Escribe tu pregunta de análisis (Ej: ¿Qué incidentes críticos ocurrieron hoy?)", key="soc_main_input")
    prompt_a_procesar = prompt_rapido if prompt_rapido else user_input

    if prompt_a_procesar:
        st.session_state.messages.append({"role": "user", "content": prompt_a_procesar})
        with st.chat_message("user"):
            st.markdown(prompt_a_procesar)

        with st.chat_message("assistant"):
            with st.spinner(" Analizando vectores en ChromaDB y sintetizando reporte con Gemini..."):
                try:
                    respuesta = analizar_incidentes_con_gemini(prompt_a_procesar)
                    st.markdown(respuesta)
                    
                    
                    
                    
                    
                    
                    
                    st.session_state.messages.append({"role": "assistant", "content": respuesta})
                except Exception as e:
                    err = f" **Error de procesamiento:** {e}"
                    st.error(err)
                    st.session_state.messages.append({"role": "assistant", "content": err})



#EXPLORADOR DE LOGS
with tab_explorer:
    #Eventos reales: logs de windows y de firewall ya analizados
    col_titulo, col_refresh = st.columns([12, 1])
    with col_titulo:
        st.markdown("##### Eventos analizados")
    with col_refresh:
        if st.button("🔄", help="Actualizar eventos"):
            #Permite guardar los eventos nuevos y enviar sus alertas
            del st.session_state["eventos_guardados"]
            st.rerun()
    ip_filtro = st.text_input("Filtrar por IP")
    estados = st.multiselect("Estado", ["OK", "FAIL", "DENY"], default=["OK", "FAIL", "DENY"])
    filas = filtrar_eventos(datos, ip_filtro, estados)
    st.dataframe(filas, use_container_width=True)
    st.caption(f"Mostrando {len(filas)} eventos")
   
   
 # Reporte SOC generado por Gemini con los resultados reales del del analisis
with tab_report:
    st.markdown("#####  Exportar Reporte Ejecutivo del Incident Response")
    st.button("Generar Reporte SOC con IA", type="primary")
    #Resultados de las detecciones que se le pasan a la IA 
    hallazgos = (
        f"Total de eventos analizados: {resumen['total']}\n"
        f"Eventos por estado: {resumen['por_estado']}\n"
        f"IPs sospechosas (IP: Fallos): {resumen['sospechosos'] or 'ninguna'}\n"
        f"Ataque automatizados: {resumen['ataques'] or 'ninguno'}\n"
        f"Posibles escaneos de puertos: {resumen['escaneos'] or 'ninguno'}\n"
        f"Fallos seguidos de acceso exitoso: {resumen['correlaciones'] or 'ninguno'}\n"
        f"Ataques en varias capas: {resumen['multifuente'] or 'ninguno'}\n"

    )
    pregunta = (
        "Redacta un reporte ejecutivo de incidentes de ciberseguridad usando "
        "SOLO estos resultados del análisis automático, sin inventar\n "
        f"{hallazgos}\n "
        "Incluye: resumen ejecutivo, hallazgos por IP, nivel de severidad "
        "y acciones de mitigación recomendadas "
        "No escribas un título principal, empieza directo con resumen ejecutivo "
    )
    with st.spinner("Generando reporte con Gemini..."):
        try:
            cuerpo = analizar_incidentes_con_gemini(pregunta)
            fecha_actual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            #Se guarda en la sesion para que no se pierda al descargar
            st.session_state.reporte_ia = (
                "# REPORTE DE INCIDENTES DE CIBERSEGURIDAD\n"
                "**Organización:** Colmena Technologies - SOC \n\n"
                f"**Fecha de emisión:** {fecha_actual} \n\n"
                f"{cuerpo}"
                )
             
        except Exception as e:
            st.error(f"No se pudo generar el reporte: {e}")
     #Muestra el ultimo reporte generado y permite descargarlo       
    if "reporte_ia" in st.session_state:
        st.markdown(st.session_state.reporte_ia)
        st.download_button(
            "Descargar Reporte (md.)",
            data=st.session_state.reporte_ia,
            file_name=f"Reporte_SOC_Colmena_{datetime.now().strftime('%Y%m%d')}.md",
        )

  
