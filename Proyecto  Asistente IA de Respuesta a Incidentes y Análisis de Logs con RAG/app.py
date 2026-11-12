import streamlit as st
import pandas as pd
import json
import time
import html
import base64
from datetime import datetime
from modulo2_rag import analizar_incidentes_con_gemini, collection
from Ingest_modulo1 import (
    ingestar_logs,
    ingestar_firewall,
    calcular_estadisticas,
    guardar_en_db,
    ruta_archivo,
    ruta_firewall,
    niveles_de_riesgo
    
)
from backend_logs import generar_informe_pdf, filtrar_eventos, registrar_informe, generar_pdf_reporte_ia
from auth import verificar_usuario, tiene_permiso, registrar_usuario, listar_usuarios
from db import crear_tablas, listar_informes, obtener_informe, leer_accesos_web
from notificaciones import enviar_alertas_pendientes, SEVERIDAD
from pathlib import Path
inicio_pagina = time.perf_counter() #cronometro de toda la pagina

@st.cache_data
def imagen_base64(ruta):
    """Convierte  una imagen en texto para poder mostrarla dentro de HTML"""
    return base64.b64encode(Path(ruta).read_bytes()).decode()
   

# pagina web
st.set_page_config(
    page_title="Colmena SOC - Incident Response Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


st.markdown("""
<style>
/* Pestaña del asistente de IA*/

.ia-header { 
    display:flex; align-items: center; gap: 14px;
     background-color: #131D2E; border: 1px solid #263345;
     border-radius: 12px: padding: 14px 18px; margin-bottom: 12px;
 }
 .ia-titulo {
 font-size: 1.2rem;
 font-weight: 700;
 color: #F1F5F9;
 }
 .ia-texto {
 color: #94A3B8;
 font-size: 1rem;
 }
.stButton button,
.stDownloadButton button,
.stFormSubmitButton button {
background: rgba(34, 211, 238, 0..0) !important;
border: 1px solid rgba(34, 211, 238, 0.035) !important;
color: #22D3EE !important;
border-radius: 999px !important;
font-size: 0.85rem;
}
.stButton button:hover,
.stDownloadButton button:hover {
background: rgba(34, 211, 238, 0.18) !important;
border-color: #22D3EE !important;
color: #FFFFFF !important;
}
.usuario-fila {
display:  flex;
justify-content: space.between;
align-items: center;
gap: 12px;
background: #131D2E;
border: 1px solid #263345;
border-radius: 10px;
padding: 12px 14px;
margin-bottom: 10px
font-size: 0.85rem;
color: #F1F5F9;
}
.usuario-fila span:first-child {
display: block;
font-weight: 600
margin-botton: 8px;
}
.rol-chip {
font-size: 0.7rem;
padding: 3px 10px;
border-radius: 999px;
white-space: nowrap;
}
.rol-administrador {
background: rgba(34, 211, 238, 0.12);
color: #22D3EE;
border: 1px solid rgba(34, 211, 238, 0.35);
}
.rol-analista {
background: rgba(59, 130, 246, 0.12);
color: #60A5FA;
border: 1px solid rgba(50, 130, 246, 0.35);
}
.sesion-header {
position: absolute;
top: 18px
right: 22px;
text-align: right;
background: rgba(19, 29, 46, 0.75);
border: 1px solid #263345;
border-radius: 12px
padding: 10px 14px;
}
.sesion-nombre {
font-weight: 600;
font-size: 0.9rem;
color: #F1F5F9;
margin-bottom: 6px;
}

/* Encabezado texto a la izquierda y logo a la derecha*/
.soc-header { display: flex; justify-content: space-between; align-items: center; gap: 20px;  }
/* Encabezado*/
.header-logo { height: 90px; border-radius: 14px; box-shadow: 0 6px 18px rgba(0, 0, 0, 0.35); }
.badge-activo {
    background: rgba(45, 212, 191, 0.12); color #2DD4BF;
    border: 1px solid rgba(45,212,191, 0.4);
    padding: 3px 10px; border-radius: 12px; font-size: 0.8rem; font-weight:600;
}
/* Equipo en la barra lateral*/
.side-rol { color: #94A3B8; font-size: 0.8rem; margin-bottom: 8px; }

/* Pantalla de inicio de sesion*/
.login-marca {text-align: center; margin: 10px 0 18px; }
.login-logo {width: 230px; max-width: 80%; border-radius:22px; box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35); }
.login-sub { color: #94A3B8; letter-spacing: 0.18em; font-size: 0.78rem; margin-top: 6px; }
.login-ia {
     display:inline-flex; align-items: center; gap: 8px; margin-top: 12px;
     padding: 4px 14px; border-radius: 999px;
     border: 1px solid rgba(34, 211, 238, 0.35); background: rgba(34, 211, 238, 0.08);
     color: #22D3EE; font-size: 0.8rem; font-weight: 600;
}
[data-testid="stForm"] {
background-color: #131D2E; border: 1px solid #263345;
border-radius: 14px; padding: 24px 26px;
}
.login-titulo{ font-size: 1.6rem; font-weight: 700; color: #F1F6F9; }
.login-texto { color: #94A3B8; margin-bottom: 12px; }
[data-testid="stFormSubmitButton"] button {
    background-color: #320652; !important; color: white; !important; border: none !important;font-weight: 600;
}
[data-testid="stFormSubmitButton"] button:hover { background-color: #2563EB !important; color: white !important; }
.login-pie { text-align: center; color: #94A3B8; font-size: 0.8rem; margin-top: 10px; }
.login-footer { text-align: center; color: #64748B; font-size: 0.75rem; margin-top: 18px; }

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
    border-radius: 12px;
    padding: 18px 20px;
    margin-bottom: 8px;
    }
</style>
""", unsafe_allow_html=True)

#Ventana de Inicio de Sesion
crear_tablas()
if "rol" not in st.session_state:
    st.session_state.rol = None

# Reglas de incio de sesion
MINUTOS_INACTIVIDAD = 30
HORAS_MAXIMAS = 8
MINUTOS_AVISO = 2

def motivo_de_cierre(ahora):
    """Devuelve porque se debe cerrar la sesion, o None si sigue activa"""
    if ahora - st.session_state.get("inicio_sesion", ahora) > HORAS_MAXIMAS * 3600: # segundos de una hora
        return "Tu sesión llegó a su duración máxima de 8 horas. Vuelve a iniciar sesión."
    if ahora - st.session_state.get("ultima_actividad", ahora) > MINUTOS_INACTIVIDAD * 60:
        return "Tu sesión se cerró por inactividad. Vuelve a iniciar sesión."
    return None

if st.session_state.rol:
    motivo = motivo_de_cierre(time.time())
    if motivo:
        st.session_state.clear()
        st.session_state.rol = None
        st.session_state.aviso = motivo
    else:
        st.session_state.ultima_actividad = time.time() # Cualquier clic cuenta como actividad

#Inicio de sesion
if st.session_state.rol is None:
    _, centro, _ = st.columns([1, 1.2, 1]) # Columna central para la tarjeta
    with centro:
        st.markdown(f"""
        <div class="login-marca">
            <img src="data:image/jpeg;base64,{imagen_base64('logo_app.jpeg')}" class="login-logo">
            <div class="login-sub">INCIDENT RESPONSE PLATFORM</div>
            <div class="login-ia">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22D3EE" stroke-width="1.8" stroke-linecap="round">
                <line x1="12" y1="2" x2="12" y2="5"/><circle cx="12" cy="2" r="1" fill="#22D3EE"/>
                <rect x="4" y="5" width="16" height="13" rx="4"/>
                <circle cx="9" cy="11" r="1.5" fill="#22D3EE"/><circle cx="15" cy="11" r="1.5" fill="#22D3EE"/>
                <line x1="9" y1="15" x2="15" y2="15"/>
            </svg>
            Asistido por IA
            </div>
        </div>""", unsafe_allow_html=True)

        if st.session_state.get("aviso"):
            st.warning(st.session_state.pop("aviso")) # Aviso de sesion cerrada, una sola vez
        with st.form("login"):
            st.markdown('<div class="login-titulo">Iniciar sesión</div>'
                        '<div class="login-texto">Accede a tu centro de análisis de seguridad.</div>',
                        unsafe_allow_html=True)
            usuario = st.text_input("Usuario", placeholder="Ingresa tu usuario")
            contrasena = st.text_input("Contraseña", type="password", placeholder="Ingresa tu contraseña")
            entrar = st.form_submit_button("Iniciar sesión", icon=":material/login:", key="iniciar_sesion")
            st.markdown('<div class="login-pie">🔒 Acceso registrado y monitoreado<br>'
                        '¿Problemas para entrar? Contacta al administrador</div>',
                        unsafe_allow_html=True)

        if entrar:
            ip = getattr(st.context, "ip_address", None) or "LOCAL"
            agente = st.context.headers.get("User-Agent", "")
            rol = verificar_usuario(usuario, contrasena, ip, agente)
            if rol:
                st.session_state.rol = rol
                st.session_state.usuario = usuario
                st.session_state.inicio_sesion = time.time()
                st.session_state.ultima_actividad = time.time()
                st.rerun()
            else:
                st.error("Usuario o contraseña incorrectos")

            st.markdown('<div class="login-footer">COLMENA CYBERSOC. Sistema de análisis y respuesta a incidentes</div>',
                        unsafe_allow_html=True)
    st.stop()


    

    #Administrar usuarios
if tiene_permiso(st.session_state.rol, "gestionar_usuarios"):
    with st.sidebar.expander("Administrar usuarios", icon=":material/person_add:"):
        with st.form("nuevo_usuario", clear_on_submit=True):
            nuevo = st.text_input("Nuevo usuario")
            clave = st.text_input("Contraseña", type="password")
            rol_nuevo = st.selectbox("Rol", ["analista", "administrador"])
            crear = st.form_submit_button("Crear usuario", icon=":material/add:", key="crear_usuario")
        if crear:
            ok, mensaje = registrar_usuario(nuevo, clave, rol_nuevo)
            if ok:
                st.success(mensaje)
            else:
                st.error(mensaje)
        st.caption("Usuarios registrados")
        for u in listar_usuarios():
            nombre = html.escape(str(u["nombre_usuario"]))
            rol = html.escape(str(u["rol"]))
            st.markdown(
                f'<div class="usuario-fila"><span>{nombre}<span>'
                f'<span class="rol-chip rol-{rol}">{rol.capitalize()}</span></div',
                unsafe_allow_html=True
            )
                                   

# Barra lateral
with st.sidebar:
    if st.button("Cerrar sesión",icon=":material/logout:", key="cerrar_sesion"): 
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
# Motivos claros para mostrar en la app
MOTIVOS = {
    "CLAVE_INCORRECTA": "Contraseña incorrecta",
    "USUARIO_NO_EXISTE": "Usuario no existe en el sistema",
    "CUENTA_BLOQUEADA": "La cuenta fue bloqueada",
}
@st.cache_data(ttl=60, show_spinner=False)
def tabla_eventos():
    """Junta Windows. firewall y servidor web en una sola tabla con las mismas columnas"""
    logs_cvs, logs_fw, web, _, _ = cargar_datos()
    filas = []
    for fuente, lista in (("Windows", logs_cvs), ("Firewall", logs_fw), ("Web", web)):
        for r in lista:
            #Los accesos web se separan segun de donde vinieron
            if fuente == "Web":
                origen_log = "App SOC" if r.get("sistema") == "APP" else "Servidor web"
            else: origen_log = fuente
            filas.append({
                "Fecha": r["tiempo"].strftime("%Y-%m-%d %H:%M:%S") if r["tiempo"] else "",
                "Fuente": origen_log,
                "Usuario": r["usuario"],
                "Email": r.get("correo_principal") or "",
                "IP": str(r["ip"]),
                "Dispositivo": r.get("dispositivo") or "COMPUTADORA",
                "Puerto": r.get("puerto") or "",
                "Estado": r["estado"],
                "Motivo": MOTIVOS.get((r.get("motivo") or "").strip(), r.get("motivo") or ""),
            })
    tabla = pd.DataFrame(filas)
    return tabla.sort_values("Fecha", ascending= False) # Lo mas reciente primero
#Nombres claros para mostrar en la app 
NOMBRES_DETECCION = {
   "ATAQUE_AUTOMATIZADO" : "Ataque automatizado",
    "ATAQUE_AUTOMATIZADO_WEB":"Fuerza bruta web",
    "POSIBLE_COMPROMISO": "Posible compromiso",
    "POSIBLE_COMPROMISO_WEB" :"Posible compromiso en la web",
    "ATAQUE_MULTIFUENTE":"Ataque en varias capas",
   "ESCANEO_PUERTOS" :"Escaneo de puertos",
    "ENUMERACION_USUARIOS" :"Enumeración de usuarios",
    "VARIOS_DISPOSITIVOS" : "Acceso desde varios dispositivos",
    "CUENTA_BLOQUEADA": "La cuenta fue bloqueada",
}

def lista_detecciones(resumen, est_web, web):
    """Junta todas las detecciones en una sola"""
    filas = []

    def agregar(tipo, fuente, origen, detalle):
        # Cada deteccion toma su severidad del mismo diccionario que usan los correos
        filas.append({
            "Severidad": SEVERIDAD.get(tipo, "MEDIO"),
            "Tipo": NOMBRES_DETECCION.get(tipo, tipo),
            "Fuente": fuente,
            "Origen": origen,
            "Detalle": detalle, 
        })
    def fuente_web(origen):
        """Dice si un origen aparece en el servidor web, en la app o si fue en las dos"""
        sistemas = {r.get("sistema") for r in web
                    if origen in (r["ip"], r["usuario"], r.get("correo_principal"))}
        if sistemas == {"APP"}:
            return "App SOC"
        if sistemas == {"WEB"}:
            return "Servidor web"
        return "Servidor web y App SOC"

    
    for ip in resumen["ataques"]:
        agregar("ATAQUE_AUTOMATIZADO", "Windows", ip, "Rafaga de fallos en poco tiempo")
    for ip in sorted(set(resumen["escaneos"])):
        agregar("ESCANEO_PUERTOS",  "Firewall", ip, "Muchos puertos bloqueados en poco tiempo")
    for ip in resumen["correlaciones"]:
        agregar("POSIBLE_COMPROMISO", "Windows", ip, "Fallos seguidos de un acceso exitoso")
    for ip in resumen["multifuente"]:
        agregar("ATAQUE_MULTIFUENTE", "Windows + Firewall", ip, "Fallos de login y bloqueos del firewall")
    for ip in est_web["ataques"]:
            agregar("ATAQUE_AUTOMATIZADO_WEB", fuente_web(ip), ip, "Fuerza bruta contra el login web")
    for ip in est_web["correlaciones"]:
        agregar("POSIBLE_COMPROMISO_WEB", fuente_web(ip), ip, "Fallos seguidos de un acceso OK en el login web")
    for ip, cantidad in est_web["enumeracion"].items():
        agregar("ENUMERACION_USUARIOS", fuente_web(ip), ip, f"{cantidad} usuarios inexistentes probados")
    for correo in est_web["varios_dispositivos"]:
        agregar("VARIOS_DISPOSITIVOS", fuente_web(correo), correo, "Accesos OK desde dispositivos distintos")
    for usuario in est_web["bloqueos"]:
        agregar ("CUENTA_BLOQUEADA", fuente_web(usuario), usuario, "Cuenta bloqueada por varios intentos fallidos")

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



st.markdown(f"""
<div class="soc-header">
<div style="width: 170px;"></div>
<div style="flex: 1; text-align: center;">
<div class="soc-title" style="justify-content: center; color: #F1F6F9;">Colmena CyberSOC <span class="badge-activo">Modo activo</span></div>
<div class="soc-subtitle">Plataforma Inteligente de Análisis de logs y Triaje de Incidentes asistida por RAG & Gemini AI</div>
<img src="data:image/jpeg;base64,{imagen_base64('logo_app.jpeg')}" class="header-logo" style="height: 120px; width: auto;">
</div>
<div style="width: 170px; align-self: flex-start;"><div class="side-card"><div class="side-titulo">Sesión activa</div><div class="side-usuario">{html.escape(st.session_state.usuario)}</div><span class="badge-rol">{html.escape(st.session_state.rol)}</span></div><div>
</div>
""", unsafe_allow_html=True)

@st.fragment(run_every=30)
def vigilar_sesion():
    """Cada 30 segundos revisa si la sesion esta por cerrarse y avisa"""
    ahora = time.time()
    if motivo_de_cierre(ahora):
        st.rerun() # Recarga  toda la app para cerrar sesion
    restante_total = HORAS_MAXIMAS * 3600 - (ahora - st.session_state.inicio_sesion)
    restante_inactividad = MINUTOS_INACTIVIDAD * 60 - (ahora - st.session_state.ultima_actividad)
    if restante_total <= MINUTOS_AVISO * 60:
        st.warning("Tu sesion se cerrará en menos de 2 minutos llegó a la duración máxima. Guarda tu trabajo")
    elif restante_inactividad <= MINUTOS_AVISO * 60:
        st.warning("Tu sesion se cerrará en menos de 2 minutos por inactividad")
        if st.button("Seguir en la sesión", icon=":material/timer:", key="seguir_en_la_sesion"):
            st.session_state.ultima_actividad = time.time()
            st.rerun() # recarga la app y quita el aviso
vigilar_sesion()



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
    if st.button("Limpiar historial del chat", icon=":material/delete_history:", key="limpiar_historial_del_chat"):
        st.session_state.messages = []
        st.rerun()

    st.markdown("""
    <div class="side-titulo">Desarrollado por</div>
    <div class="side-card">
        <div class="side-usuario">Melanny Arroyo</div>
        <div class"side-usuario>Ethan Rojas</div"
        </div>
        <div class="login-footer">Colmena Technologies . Práctica profesional</div>
        """, unsafe_allow_html=True)


    

# --- PANEL SUPERIOR DE MÉTRICAS (KPIS INTUITIVOS) ---
try:
    total_logs_count = collection.count()
except Exception:
    total_logs_count = 4
# Van a usar la misma lista que la pestaña de detecciones
detecciones = lista_detecciones(resumen, est_web, web)
riesgos = niveles_de_riesgo(detecciones)
amenazas = len(detecciones)
severidades = {d["Severidad"] for d in detecciones}
if "ALTO" in severidades:
    nivel, clase_nivel = "ALTO", "status-critical"
elif "MEDIO" in severidades:
    nivel, clase_nivel = "MEDIO", "status-warning"
else:
    nivel, clase_nivel = "BAJO", "status-success"
# El primero es el mayor nivel de riesgo
ip_top = riesgos[0]["Origen"] if riesgos else "Ninguno"
nivel_top = riesgos[0]["Nivel de riesgo"] if riesgos else "Sin riesgo"




# --- PESTAÑAS PRINCIPALES ---
tab_resumen,tab_frecuentes,tab_detecciones,tab_chat, tab_explorer, tab_report, tab_informes = st.tabs([
    ":material/dashboard: Resumen",
    ":material/trending_up: Eventos frecuentes",
    ":material/gpp_maybe: Detecciones",
    ":material/smart_toy: Asistente SOC",
    ":material/table_view: Explorador de logs",
    ":material/summarize: Generador de reporte",
    ":material/picture_as_pdf: Informes",

])
# Pestaña de resumen es el estado general del sistema
with tab_resumen:
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
        <div class="metric-title"> Origen de mayor riesgo</div>
        <div class="metric-value  status-warning">{ip_top}</div>
        <div style="font-size:0.75rem; color:#F59E0B;">{nivel_top}</div>
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

with tab_resumen:
 # Nivel de riesgo por origen
    with st.container(key="panel_riesgo"):
        st.subheader("Nivel de riesgo por origen")
        riesgos = niveles_de_riesgo(detecciones)
        if riesgos:
            colores_riesgo = {"CRITICO": "#F87171", "ALTO": "#FB923C", "MEDIO":"#FBBF24", "BAJO": "#2DD4BF"}

            def color_riesgo(valor):
                color = colores_riesgo.get(valor)
                return f"color: {color}; font-weight: 600" if color else ""

            tabla_riesgo = pd.DataFrame(riesgos).style.map(color_riesgo, subset=["Nivel de riesgo"])
            st.dataframe(tabla_riesgo, use_container_width=True, hide_index=True)
        else:
            st.markdown('<div class="estado"><span class="sev-dot" style="background:#2DD4BF;></span>Sin origenes de riesgo</div', unsafe_allow_html=True)
#Pestaña de eventos mas frecuentes: ranking de IPs, usuarios y puertos, en una sola tabla
with tab_frecuentes:
    with st.container(key="panel_eventos"):
        st.subheader("Eventos más frecuentes")
        # Va a juntar el ranking de IPs, usuarios y puertos en una sola  lista
        ranking = []
        for tipo, llave in (("IP", "ips"), ("Usuario", "usuarios"), ("Puerto", "puertos")):
            for valor, cantidad in resumen["ranking"][llave]:
                ranking.append({"Tipo": tipo, "IP, Usuario o puerto": str(valor), "Eventos": cantidad})
        tabla_rank = pd.DataFrame(ranking)

        c_tipo, c_buscar = st.columns([1, 3])
        tipo_rank = c_tipo.selectbox("Tipo", ["Todos", "IP", "Usuario", "Puerto"], key="rank_tipo")
        buscar_rank = c_buscar.text_input("Buscar", placeholder="Escribe la IP, usuario o un puerto", key="rank_buscar")

        if tipo_rank != "Todos":
            tabla_rank = tabla_rank[tabla_rank["Tipo"] == tipo_rank]
        if buscar_rank:
            tabla_rank = tabla_rank[tabla_rank["IP, Usuario o puerto"].str.contains(buscar_rank, case=False, regex=False)]
        st.dataframe(tabla_rank, use_container_width=True, hide_index=True)
   

#pestaña de detecciones: muestra los resultados del analisis de logs reales
with tab_detecciones:
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
        icon=":material/picture_as_pdf:"
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
            icon=":material/history:",

        )
    else:
        st.info("Todavía no hay informes guardados")

# --- PESTAÑA 1: CHATBOT SOC ---
with tab_chat:
    # Encabezado con el mismo robot del login
    st.markdown("""
    <div class="ia-header">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#22D3EE" stroke-width="1.8" stroke-linecap="round">
            <line x1="12" y1="2" x2="12" y2="5"/><circle cx="12" cy="2" r="1" fill="#22D3EE"/>
            <rect x="4" y="5" width="16" height="13" rx="4"/>
            <circle cx="9" cy="11" r="1.5" fill="#22D3EE/><circle cx= "15" cy="11" r="1.5" fill="#22D3EE"/>
            <line x1="9" y1="15" x2="15" y2="15"/>
        </svg>
        <div>
            <div class="ia-titulo">Asistente SOC</div>
            <div class="ia-texto">Pregunta sobre la actividad  y los eventos del sistema.</div>
        <div>
    </div>""", unsafe_allow_html=True)

    # Botones de consultas rapidas
    st.caption("Consultas rápidas")
    c1, c2, c3 = st.columns(3)
    prompt_rapido = None
    if c1.button("Intentos fallidos" , icon=":material/crisis_alert:",  key="rapido_fallos", use_container_width=True):
        prompt_rapido = "¿Qué IPs y usuarios tienen intentos fallidos de inicio de sesión y qué tan grave es?"
    if c2.button("Orígenes de mayor riesgo", icon=":material/dangerous:", key="rapido_riesgo", use_container_width=True):
        prompt_rapido = "¿Cuáles son los orígenes con más actividad sospechosa y que recomiendas hacer?"
    if c3.button("Bloqueos del Firewall", icon=":material/block:", key="rapido_firewall", use_container_width=True):
        prompt_rapido = "¿Qué conexiones bloqueó el firewall y hacia que puertos?"

    # Historial del chat
    if "messages" not in st.session_state:
        st.session_state.messages = [{
            "role": "assistant",
            "content": "**Hola, soy el asistente SOC de Colmena Technologies.**\n\n Estoy aquí para ayudar: puedo analizar los eventos registrados. Elige una consulta rápida o escribe tu pregunta para comenzar.",
        }]
    for message in st.session_state.messages:
        avatar = ":material/smart_toy:" if message["role"] == "assistant" else ":material/person:"
        with st.chat_message(message["role"], avatar=avatar):
            st.markdown(message["content"])

    # Pregunta escrita o boton rápido
    user_input = st.chat_input("Escribe tu pregunta (ej: ¿qué incidentes críticos ocurrieron hoy?)", key="soc_main_input")
    prompt_a_procesar = prompt_rapido if prompt_rapido else user_input

    if prompt_a_procesar:
        st.session_state.messages.append({"role": "user", "content": prompt_a_procesar})
        with st.chat_message("user", avatar=":material/person:"):
            st.markdown(prompt_a_procesar)

        with st.chat_message("assistant", avatar=":material/smart_toy:"):
            with st.spinner("Analizando eventos con ChromaDB y Gemini..."):
                try:
                    respuesta = analizar_incidentes_con_gemini(prompt_a_procesar)
                    st.markdown(respuesta)
                    st.session_state.messages.append({"role": "assistant", "content": respuesta})
                except Exception as e:
                    err = f"**Error de procesamiento:** {e}"
                    st.error(err)
                    st.session_state.messages.append({"role": "assistant", "content": err})
 
# EXPLORADOR DE LOGS una sola tabla con todas las fuentes 
with tab_explorer:
    col_titulo, col_refresh = st.columns([10, 2])
    col_titulo.markdown("Todos los eventos")
    if col_refresh.button( "", icon=":material/refresh:", key="actualizar", use_container_width=True):
        st.cache_data.clear()                               # Borra la cache para leer datos nuevos
        st.session_state.pop("eventos_guardados", None)     # Vuelve a enviar eventos y enviar alertas
        st.rerun()

    tabla = tabla_eventos()
    buscar = st.text_input("Buscar", placeholder="Buscar en los registros....", key="explorador_buscar")
    if buscar:
        # Deja que las filas cualquier columna tiene texto buscado
        coincide = tabla.astype(str).apply(lambda col: col.str.contains(buscar, case=False, regex=False))
        tabla = tabla[coincide.any(axis=1)]

    total = len(tabla)
    tabla = tabla.head(2000) # Muestra los 2000 mas recientes para que la app no se haga lenta

    #Colores son en el texto, igual que en detecciones
    colores_estado = {"OK": "#2DD4BF", "FAIL": "#F87171", "DENY": "#FBBF24"}
    colores_fuente = {"Windows": "#3B82F6", "Firewall": "#8B5CF6", "Servidor web": "#22D3EE", "App SOC": "#2DD4BF" }

    def color_estado(valor):
        color = colores_estado.get(valor)
        return f"color: {color}; font-weight: 600" if color else ""
    def color_fuente(valor):
        color = colores_fuente.get(valor)
        return f"color: {color}; font-weight: 600" if color else ""

    tabla_color = tabla.style.map(color_estado, subset=["Estado"]).map(color_fuente, subset=["Fuente"])
    st.dataframe(tabla_color, 
                 use_container_width=True, 
                 hide_index=True,
                 column_config={   
                     "Fecha": st.column_config.TextColumn(width="medium"),
                     "Fuente": st.column_config.TextColumn(width="small"),
                     "Usuario": st.column_config.TextColumn(width="medium"),
                     "Email": st.column_config.TextColumn(width="medium"),
                     "IP": st.column_config.TextColumn(width="small"),
                     "Dispositivo": st.column_config.TextColumn(width="medium"),
                     "Puerto": st.column_config.TextColumn(width="small"),
                     "Estado": st.column_config.TextColumn(width="small"),
                     "Motivo": st.column_config.TextColumn(width="large"),
                     
                 },

                 )
    st.caption(f"Mostrando {len(tabla)} de {total} eventos")

 # Reporte SOC generado por Gemini con los resultados reales del del analisis
with tab_report:
    st.markdown("#####  Exportar Reporte Ejecutivo del Incident Response")
    if st.button("Generar Reporte SOC con IA", icon=":material/touch_app:" , key="generar_reporte_SOC_con_IA"):
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
            icon=":material/download:"
        )
        st.download_button(
            "Descargar en PDF",
            data=generar_pdf_reporte_ia(st.session_state.reporte_ia),
            file_name=f"repprte_ia_{datetime.now():%Y%m%d_%H%M}.pdf",
            mime="application/pdf",
            icon=":material/picture_as_pdf:",
            key="descargar_reporte_pdf",
        )

st.sidebar.caption(f"⏱️ Página completa en {(time.perf_counter() - inicio_pagina)* 1000:.0f}ms")    