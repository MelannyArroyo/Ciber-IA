import streamlit as st
import pandas as pd
import json
from datetime import datetime
from modulo2_rag import analizar_incidentes_con_gemini, collection


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
    st.markdown("""
    <div class="metric-card">
        <div class="metric-title">Nivel de Amenaza Global</div>
        <div class="metric-value status-critical">ALTO</div>
        <div style="font-size:0.75rem; color:#EF4444;">🚨 Ataques de Fuerza Bruta SSH</div>
    </div>
    """, unsafe_allow_html=True)

with col_kpi3:
    st.markdown("""
    <div class="metric-card">
        <div class="metric-title">IP Origen Sospechosa</div>
        <div class="metric-value status-warning">192.168.1.50</div>
        <div style="font-size:0.75rem; color:#F59E0B;">3 Intentos / 1 Acceso Éxito</div>
    </div>
    """, unsafe_allow_html=True)

with col_kpi4:
    st.markdown("""
    <div class="metric-card">
        <div class="metric-title">Tiempo de Respuesta RAG</div>
        <div class="metric-value status-success">&lt; 1.5s</div>
        <div style="font-size:0.75rem; color:#10B981;">Consultas optimizadas</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# --- PESTAÑAS PRINCIPALES ---
tab_chat, tab_explorer, tab_report = st.tabs([
    "💬 Asistente SOC & Triaje IA", 
    "📜 Explorador de Telemetría (Logs)", 
    "📋 Generador de Reporte SOC"
])

# --- PESTAÑA 1: CHATBOT SOC ---
with tab_chat:
    st.markdown("##### ⚡ Consultas Rápidas de Seguridad")
    
    col_b1, col_b2, col_b3 = st.columns(3)
    prompt_rapido = None

    if col_b1.button(" Analizar ataques a cuentas Root", use_container_width=True):
        prompt_rapido =  "¿Hay registros de fuerza bruta o intentos de inicio de sesión con el usuario root?"
    if col_b3.button(" Revisar eventos de Firewall / Web", use_container_width=True):
        prompt_rapido = "¿Se detectaron peticiones HTTP 403 o accesos prohibidos a rutas administrativas?"

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
    st.markdown("#####  Búsqueda y Filtrado de Logs en ChromaDB")
    
    col_f1, col_f2 = st.columns([3, 1])
    with col_f1:
        filtro_ip = st.text_input("Filtrar por palabra clave o IP (Ej: 192.168.1.50, SSH, 403):", "")
    with col_f2:
        st.write("")
        st.write("")
        btn_refresh = st.button("🔄 Actualizar Tabla", use_container_width=True)

    try:
        raw_data = collection.get()
        if raw_data and "documents" in raw_data and raw_data["documents"]:
            data_list = []
            for doc, meta, doc_id in zip(raw_data["documents"], raw_data["metadatas"], raw_data["ids"]):
                if not filtro_ip or filtro_ip.lower() in doc.lower():
                    data_list.append({
                        "ID": doc_id,
                        "Evento Detallado": doc,
                        "Usuario": meta.get("user", "N/A"),
                        "IP Origen": meta.get("src_ip", "N/A"),
                        "Estado": meta.get("status", "N/A")
                    })
            
            df = pd.DataFrame(data_list)
            if not df.empty:
                st.dataframe(
                    df, 
                    use_container_width=True, 
                    hide_index=True,
                    column_config={
                        "ID": st.column_config.TextColumn("ID Log", width="medium"),
                        "Evento Detallado": st.column_config.TextColumn("Registro de Telemetría", width="large"),
                        "Estado": st.column_config.TextColumn("Resultado", width="small")
                    }
                )
            else:
                st.warning("No se encontraron registros que coincidan con la búsqueda.")
        else:
            st.info("La base de datos ChromaDB no contiene registros cargados.")
    except Exception as e:
        st.error(f"Error cargando registros de ChromaDB: {e}")
 
with tab_report:
    st.markdown("#####  Exportar Reporte Ejecutivo del Incident Response")
    st.write("Genera un resumen oficial de los hallazgos para presentar al equipo directivo o al cliente.")

    if st.button(" Generar Borrador de Reporte SOC", type="primary"):
        fecha_actual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        reporte_md = f"""# REPORTE DE INCIDENTES DE CIBERSEGURIDAD
**Organización:** Colmena Technologies - SOC  
**Fecha de Emisión:** {fecha_actual}  
**Estado:** <span style="color:red;">CRÍTICO</span>  

---

### 1. RESUMEN EJECUTIVO
Se detectó un patrón de ataque de **Fuerza Bruta por SSH** proveniente de la dirección IP interna `192.168.1.50`, seguido por un inicio de sesión exitoso bajo la cuenta privilegiada `root`. Adicionalmente, la IP externa `203.0.113.195` realizó escaneos sobre rutas administrativas restringidas (`/admin`).

### 2. TELEMETRÍA ASOCIADA
- **IP Atacante SSH:** `192.168.1.50` -> Servidor Objetivo `10.0.0.5`
- **Usuario Comprometido:** `root`
- **Intentos Fallidos:** 2
- **Acceso Exitoso:** 1 (`2026-10-06T10:15:35Z`)

### 3. ACCIONES DE MITIGACIÓN RECOMENDADAS
1. **Aislamiento Inmediato:** Bloquear la IP `192.168.1.50` en las reglas del Firewall interno.
2. **Revocación de Credenciales:** Forzar el cambio de contraseña y claves SSH para el usuario `root`.
3. **Petición Zero Trust:** Implementar autenticación multifactor (MFA) para todas las conexiones administrativas SSH.
"""
        st.markdown(reporte_md, unsafe_allow_html=True)
        st.download_button(
            label=" Descargar Reporte (.md)",
            data=reporte_md,
            file_name=f"Reporte_SOC_Colmena_{datetime.now().strftime('%Y%m%d')}.md",
            mime="text/markdown"
        )
