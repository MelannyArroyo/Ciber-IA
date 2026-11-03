import streamlit as st
import pandas as pd
import json
import time
import html
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
from db import crear_tablas, listar_informes, obtener_informe, leer_accesos_web
from notificaciones import enviar_alertas_pendientes, SEVERIDAD
inicio_pagina = time.perf_counter() #cronometro de toda la pagina

# pagina web
st.set_page_config(
    page_title="Colmena SOC - Incident Response Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


st.markdown("""
<style>
/*--- Barra lateral--- */
section[data-testid="stSidebar"] {
background-color: #0B1220;
border-right: 1px solid #263345;}
    /* Fondo principal y tipografía */
    .stApp {
        background-color: #0F172A;
        color: #E2E8F0;
    }
    .side-card {
    background-color: #131D2E;
    border: 1px solid #263345;
    padding: 12px 14px;
    margin-bottom: 10px;
    }
    .side-titulo {
    font-size: 0.75rem;
    font-weight: 600;
    color: #94A3B8;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin: 8px 0 6px;
    }
    .side-usuario {
    font-size: 1rem;
    font-weight: 700;
    color: #E2E8F0;
    margin: 2px 0 8px;
    }
    .badge-rol {
    background: rgba(45, 212, 191, 0.12);
    color: #2DD5BF;
    border: 1px solid rgba(45, 212, 191, 0.35);
    border-radius: 12px;
    padding: 2px 10px;
    font-size: 0.75rem;
    font-weight: 600;
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
    .stTaps [aria-selected="true"] {
    background-color: #1E29RB ! important;
    color: #38BDF8 ! important;
    border-bottom: 2px solid #38BDF8;
    }
    /* --- Detecciones ---*/
    .sev-card {
    border: 1px solid #2A3A52;
    border-radius: 10px;
    pedding: 16px 18px;
    text-align: center;
    }
    .sev-label {
    font-size: 0.8rem;
    font-weight: 600;
    color: #CBD5E1;
    text-transform: upper case;
    letter-spacing: 0.08em;
    }
    .sev-dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    display: inline-block;
    }
    .sev-num {
    font-size: 2.2rem;
    font-weight: 700;
    margin-top: 4px;
    }
    .estado{
    display: flex;
    align-items: center;
    gap: 8px;
    color: #94A3B8;
    font-size: 0.95rem;
    padding: 6px 2px;
    }
    /* Paneles de detecciones, mismo fondo borde y espaciado*/
    div[class*=st-key-panel] {
    background-color: #131D2E;
    border: 1px solid #263345;
    border-raidus: 12px;
    padding: 18px 20px;
    margin-bottom: 8px;
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
            st.rerun()
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
    st.markdown(f"""
    <div class="side-card">
        <div class= "side-titulo">Sesión activa</div>
        <div class= "side-usuario">{html.escape(st.session_state.usuario)}</div>
        <span class="badge-rol">{html.escape(st.session_state.rol)}</span>
    </div> """, unsafe_allow_html=True)
    if st.button("Cerrar sesión", use_container_width=True):
        st.session_state.clear()
        st.rerun()
    

@st.cache_data(ttl=60, show_spinner="Cargando logs.....")
def cargar_datos():
    """Lee todas las fuentes y calcula las detecciones, lo guarda 60 seg en memoria"""
    logs_cvs = ingestar_logs(ruta_archivo)
    logs_fw  = ingestar_firewall(ruta_firewall)
    web = leer_accesos_web()
    return logs_cvs, logs_fw, web, calcular_estadisticas(logs_cvs + logs_fw), calcular_estadisticas(web)

@st.cache_data(ttl=60, show_spinner=False)
def pdf_cacheado(resumen):
    """Genera el PDF solo cuando cambian los resultados del analisis"""
    return generar_informe_pdf(resumen)
@st.cache_data(ttl=60, show_spinner=False)
def tabla_eventos():
    """Junta Windows. firewall y servidor web en una sola tabla con las mismas columnas"""
    logs_cvs, logs_fw, web, _, _ = cargar_datos()
    filas = []
    for fuente, lista in (("Windows", logs_cvs), ("Firewall", logs_fw), ("Web", web)):
        for r in lista:
            filas.append({
                "Fecha": r["tiempo"].strftime("%Y-%m-%d %H:%M:%S") if r["tiempo"] else "",
                "Fuente": fuente,
                "Usuario": r["usuario"],
                "Correo principal": r.get("correo_principal") or "",
                "IP": str(r["ip"]),
                "Dispositivo": r.get("dispositivo") or "COMPUTADORA",
                "Puerto": r.get("puerto") or "",
                "Estado": r["estado"],
                "Motivo": r.get("motivo") or "",
            })
    tabla = pd.DataFrame(filas)
    return tabla.sort_values("Fecha", ascending= False) # Lo mas reciente primero

def lista_detecciones(resumen, est_web):
    """Junta todas las detecciones en una sola"""
    filas = []

    def agregar(tipo, fuente, origen, detalle):
        # Cada deteccion toma su severidad del mismo diccionario que usan los correos
        filas.append({
            "Severidad": SEVERIDAD.get(tipo, "MEDIO"),
            "Tipo": tipo,
            "Fuente": fuente,
            "Origen": origen,
            "Detalle": detalle, 
        })
    for ip in resumen["ataques"]:
        agregar("ATAQUE_AUTOMATIZADO", "Windows", ip, "Rafaga de fallos en poco tiempo")
    for ip in sorted(set(resumen["escaneos"])):
        agregar("ESCANEO_PUERTOS",  "Firewall", ip, "Muchos puertos bloqueados en poco tiempo")
    for ip in resumen["correlaciones"]:
        agregar("POSIBLE_COMPROMISO", "Windows", ip, "Fallos seguidos de un acceso exitoso")
    for ip in resumen["multifuente"]:
        agregar("ATAQUE_MULTIFUENTE", "Windows + Firewall", ip, "Fallos de login y bloqueos del firewall")
    for ip in est_web["ataques"]:
        agregar("ATAQUE_AUTOMATIZADO_WEB", "Web", ip, "Fuerza bruta contra el login web")
    for ip in est_web["correlaciones"]:
        agregar("POSIBLE_COMPROMISO_WEB", "Web", ip, "Fallos seguidos de un acceso OK en el login web")
    for ip, cantidad in est_web["enumeracion"].items():
        agregar("ENUMERACION_USUARIOS", "Web", ip, f"{cantidad} usuarios inexistentes probados")
    for correo in est_web["varios_dispositivos"]:
        agregar("VARIOS_DISPOSITIVOS", "Web", correo, "Accesos OK desde dispositivos distintos")
    for usuario in est_web["bloqueos"]:
        agregar ("CUENTA_BLOQUEADA", "Web", usuario, "Cuenta bloqueada por varios intentos fallidos")

    # Ordena ALTO a INFORMATIVO como el mas bajo
    orden = {"ALTO": 0, "MEDIO": 1, "INFORMATIVO": 2}
    filas.sort(key=lambda f: orden.get(f["Severidad"], 1))
    return filas 

inicio_carga = time.perf_counter() # Cronometro para medi cuanto tarda en cargar
logs_cvs, logs_fw, web, resumen, est_web = cargar_datos ()
datos = logs_cvs + logs_fw
st.sidebar.caption(f"⏱️ Datos cargados en {(time.perf_counter() - inicio_carga) * 1000:.0f} ms")

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
    # Revisa de verdad si ChromaDB responde, en vez de escribirlo fijo
    try:
        collection.count()
        chroma_ok = True
    except Exception:
        chroma_ok = False
    color_chroma = "#2DD4BF" if chroma_ok else "#F87171"
    texto_chroma = "ChromaDB conectado" if chroma_ok else "#F87171"

    st.markdown('<div class="side-titulo">Estado del sistema</div', unsafe_allow_html=True)
    st.markdown(f"""
    <div class="side-card">
        <div class="estado"><span class="sev-dot" style="background:{color_chroma};"></span>{texto_chroma}</div>
        <div class="estado"><span class="sev-dot" style="background:#2DD4BF;"></span>Gemini 3.8 Flash</div>
        <div class="estado"><span class="sev-dot" style="background:#2DD4BF;"></span>Embeddings: API / ONNX</div>
        </div>""", unsafe_allow_html=True)

    st.markdown('<div class="side-titulo">Opciones</div>', unsafe_allow_html=True)
    if st.button("Limpiar historial del chat", use_container_width=True):
        st.session_state.messages = []
        st.rerun()

    st.caption("Colmena Technologies. Práctica profesional: Ciberseguridad & IA")


    

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
tab_frecuentes,tab_detecciones,tab_chat, tab_explorer, tab_report, tab_informes = st.tabs([
    "📊 Eventos frecuentes",
    "🚨 Detecciones",
    "💬 Asistente SOC & Triaje IA", 
    "📜 Explorador de Logs", 
    "📋 Generador de Reporte SOC",
    "📄 Informes",
])
#Pestaña de eventos mas frecuentes: ranking de IPs, usuarios y puertos
with tab_frecuentes:
    with st.container(key="panel_eventos"):
        st.subheader("Eventos mas frecuentes")
        col_ips, col_usuarios, col_puertos = st.columns(3)
        with col_ips:
            st.markdown("**IPs**")
            st.dataframe([{"IP": ip, "Eventos": n} for ip, n in resumen["ranking"] ["ips"]],
                            use_container_width=True, hide_index=True)  
        with col_usuarios:
            st.markdown("**Usuarios**")
            st.dataframe([{"Usuario": u, "Eventos": n} for u, n in resumen["ranking"] ["usuarios"]],
                        use_container_width=True, hide_index=True) 
        with col_puertos:
            st.markdown("**Puertos del Firewall**")
            st.dataframe([{"Puerto": p, "Eventos": n} for p, n in resumen["ranking"] ["puertos"]],
                            use_container_width=True, hide_index=True)

#pestaña de detecciones: muestra los resultados del analisis de logs reales
with tab_detecciones:
    detecciones = lista_detecciones(resumen, est_web)
    # color de cada severidad:solo indicadores pequeños
    colores_sev = {"ALTO": "#F87171", "MEDIO": "#FBBF24", "INFORMATIVO": "#2DD4BF"}
    # Fondo pastel
    fondos_sev = {
        "ALTO": "rgba(248, 113, 0.12)",
        "MEDIO": "rgba(251, 191, 36, 0.12)",
        "INFORMATIVO": "rgba(45, 112, 191, 0.12)",
    }

    # Alertas detectadas
    with st.container(key="panel_alertas"):
        st.subheader("Alertas detectadas")
        for columna, sev in zip(st.columns(3), ["ALTO", "MEDIO", "INFORMATIVO"]):
            cantidad = sum(1 for d in detecciones if d["Severidad"] == sev)
            columna.markdown(f"""
            <div class="sev-card" style="background:{fondos_sev}; border-color:{colores_sev[sev]}55;">
                <div class="sev-label">{sev.capitalize()}</div>
                <div class="sev-num" style="color:{colores_sev[sev]};">{cantidad}</div>
            </div>""", unsafe_allow_html=True)

        st.write("") # Espacio entre las tarjetas y la tabla
        if detecciones:
            def color_severidad(valor):
                #solo colorea el texto de la severidad
                color = colores_sev.get(valor)
                return f"color: {color}; font-weight:600" if color else ""

            tabla_det = pd.DataFrame(detecciones).style.map(color_severidad, subset=["Severidad"])
            st.dataframe(tabla_det, use_container_width=True, hide_index=True)
        else:
            st.markdown('<div class="estado"><span class="sev-dot" style="background:#2DD4BF";></span>No se detectaron amenazas</div>', unsafe_allow_html=True)
    # IPs sospechosas
    with st.container(key="panel_ips"):
        st.subheader("IPs sospechosas")
        if resumen["sospechosos"]:
            st.dataframe(
                [{"IP": ip, "Fallos": n} for ip, n in resumen["sospechosos"].items()],
                use_container_width=True, hide_index=True,
            )
        else:
            st.markdown('<div class="estado"><span class="sev-dot" style="background:#2DD4BF;"></span>No hay IPs sospechosas</div>', unsafe_allow_html=True)

#Pestaña de informes:descarga del PDF y el historial guardado
with tab_informes:
    st.subheader("Informe PDF del análisis")
    st.download_button(
        "Descargar informe (PDF)",
        data=pdf_cacheado(resumen),
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

# EXPLORADOR DE LOGS una sola tabla con todas las fuentes 
with tab_explorer:
    col_titulo, col_refresh = st.columns([10, 2])
    col_titulo.markdown("##### Todos los eventos")
    if col_refresh.button("🔄", key="actualizar"):
        st.cache_data.clear()                               # Borra la cache para leer datos nuevos
        st.session_state.pop("eventos_guardados", None)     # Vuelve a enviar eventos y enviar alertas
        st.rerun()

    tabla = tabla_eventos()
    c1, c2, c3, c4 = st.columns(4)
    fuente = c1.selectbox("Fuente", ["Todas", "Windows", "Firewall", "Web"], key="f_fuente")
    dispositivo = c2.selectbox("Dispositivo", ["Todos", "COMPUTADORA", "TELEFONO"], key="f_disp")
    correos = sorted(c for c in tabla["Correo principal"].unique() if c)
    correo = c3.selectbox("Correo principal", ["Todos"] + correos, key="f_correo")
    estados = c4._multiselect("Estado", ["OK", "FAIL", "DENY"], default=["OK", "FAIL", "DENY"], key="f_estado")
    ip_filtro = st.text_input("Filtar por IP", key="f_ip")

    # Cada filtro deja solo las filas que coinciden 
    if fuente != "Todas":
        tabla = tabla[tabla["Fuente"] == fuente]
    if dispositivo != "Todos":
        tabla = tabla[tabla["Dispositivo"] == dispositivo]
    if correo != "Todos":
        tabla = tabla[tabla["Correo principal"] == correo]
    tabla = tabla[tabla["Estado"].isin(estados)]
    if ip_filtro:
        tabla = tabla[tabla["IP"].str.contains(ip_filtro, regex=False)]

    st.dataframe(tabla, use_container_width=True, hide_index=True)
    st.caption(f"Mostrando {len(tabla)} eventos")

    
   
   
 # Reporte SOC generado por Gemini con los resultados reales del del analisis
with tab_report:
    st.markdown("#####  Exportar Reporte Ejecutivo del Incident Response")
    if st.button("Generar Reporte SOC con IA", type="primary"):
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

st.sidebar.caption(f"⏱️ Página completa en {(time.perf_counter() - inicio_pagina)* 1000:.0f}ms")