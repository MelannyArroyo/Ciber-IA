from fpdf import FPDF
from datetime import datetime
from db import crear_tablas, guardar_informe
import os

FONDO_OSCURO = (15, 23, 42)
AZUL = (37, 99, 235)
TURQUESA = (34, 211, 238)
GRIS= (241, 245, 249)
TEXTO = (30,41,59)

COLORES_SEVERIDAD ={
    "ALTO": (220, 38, 38),
    "MEDIO": (217, 119, 6),
    "INFORMATIVO": (37, 99, 235),
    "BAJO": (22, 163, 74),
    "CRITICO": (127, 29, 29),
}
RECOMENDACIONES = {
    "Ataque automatizado": "Bloquear en el firewall perimetral las IPs {origenes} y revisar si alguna cuenta fue comprometida.",
    "Ataque en varias capas": "Bloquear {origenes} en el servidor web y revisar los intentos contra el login web.",
    "Posible compromiso": "Revisar {origenes}: hubo fallos seguidos de un acceso exitoso. Confirmar con el usuario de la cuenta y cambiar la contraseña.",
    "Posible compromiso en la web": "Revisar {origenes}: hubo fallos seguidos de un acceso OK en el login web. Confirmar con el usuario, cambiar la contraseña y cerrar sus sesiones activas.",
    "Escaneo de puertos": "Revisar los puertos que intentó  alcanzar {origenes} y confirmar que los servicios expuestos estén cerrados o protegidos.",
    "Enumeración de usuarios": "Limitar los intentos desde {origenes} y revisar si los nombres probados corresponden a cuentas reales.",
    "Acceso desde varios dispositivos": "Confirmar con el usuario de {origenes} si reconoce los dispositivos desde los que accedió, y cerrar las sesiones que no sean suyas.",
    "La cuenta fue bloqueada": "Confirmar con {origenes} si intentó entrar. Desbloquear solo si es legítimo y cambiar la contraseña si hay dudas.",

}
TIPOS_ATAQUE_REAL = {
    "Ataque automatizado",
    "Ataque en varias capas",
    "Fuerza bruta web",
    "Posible compromiso",
    "Posible compromiso en la web"
}


class Informe(FPDF):
    subtitulo = "Informe de análisis de logs"

    def header(self):
        #Franja oscura y linea turquesa
        self.set_fill_color(*FONDO_OSCURO)
        self.rect(0, 0, 210, 30, "F")
        self.set_fill_color(*TURQUESA)
        self.rect(0, 30, 210, 1.2, "F")

        # Logo de la app
        ruta_logo = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo_app.jpeg")
        if os.path.exists(ruta_logo):
            self.image(ruta_logo, x=12, y=5, h=20)

        # Nombre y subtítulo
        self.set_xy(36, 8)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "", 9)
        self.cell(0, 8, "Colmena Technologies", new_x="LMARGIN", new_y="NEXT")
        self.set_x(36)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*TURQUESA)
        self.cell(0, 6, self.subtitulo)

        # Etiqueta "Asistido por IA"
        self.set_xy(160, 11.5)
        self.set_draw_color(*TURQUESA)
        self.set_font("Helvetica", "B", 8)
        self.cell(38, 7, "Asistido por IA", border=1, align="C")

        self.set_text_color(*TEXTO)
        self.set_y(38)

    def footer(self):
        self.set_draw_color(*TURQUESA)
        self.line(12, 282, 198, 282)
        self.set_y(-14)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(130, 130, 130)
        self.cell(0, 6, "Colmena Technologies . Asistente SOC . Documento confidencial")
        self.set_x(self.l_margin)
        self.cell(0, 6, f"Página {self.page_no()}", align="R")
        self.set_text_color(*TEXTO)

       

def titulo_seccion(pdf, texto):
    pdf.ln(4)
    y = pdf.get_y()
    pdf.set_fill_color(*TURQUESA)
    pdf.rect(pdf.l_margin,  y + 1.5, 1.5, 5, "F" )
    pdf.set_x(pdf.l_margin + 4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*FONDO_OSCURO)
    pdf.cell(0, 8, texto, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(*TEXTO)
    pdf.set_font("Helvetica", "", 10)
 

def tarjetas(pdf,valores):
    y0 = pdf.get_y()
    ancho = (186-3*4) / 4
    for i, (titulo,valor) in enumerate(valores):
        x = 12 + i * (ancho + 4)
        pdf.set_fill_color(*GRIS)
        pdf.rect(x, y0, ancho, 20, "F")
        pdf.set_xy(x +4, y0 + 3)
        pdf.set_font("Helvetica", "B", 15)
        pdf.set_text_color(*AZUL)
        pdf.cell(ancho - 8,8, str(valor))
        pdf.set_xy(x +4, y0 + 12)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*TEXTO)
        pdf.cell(ancho -8, 5, titulo)
    pdf.set_xy(12,y0 + 24)

def partir_texto(pdf, texto, ancho):
    """Divide el texto en lineas que caben en el ancho de la celda"""
    palabras = str(texto).split()
    lineas, actual = [], ""
    for palabra in palabras:
        prueba = f"{actual} {palabra}".strip()
        if pdf.get_string_width(prueba) <= ancho - 2:
            actual = prueba
        else:
            if actual:
                lineas.append(actual)
            actual = palabra
    lineas.append(actual)
    return lineas

def tabla(pdf,encabezados, filas, anchos):
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(*FONDO_OSCURO)
    pdf.set_text_color(255, 255, 255)
    for h, w in zip(encabezados, anchos):
        pdf.cell(w, 7, h, fill=True)
    pdf.ln()
    pdf.set_font("Helvetica", "", 9)
    for i, fila in enumerate(filas):
        celdas = [partir_texto(pdf, v, w) for v, w in zip(fila, anchos)]
        alto = max(len(c) for c in celdas) * 5 + 2
        if pdf.get_y() + alto > 265:
            pdf.add_page()
        x0, y0 = pdf.l_margin, pdf.get_y()
        fondo = GRIS if i % 2 else (255, 255, 255)
        x = x0
        for valor, lineas, w in zip(fila, celdas, anchos):
            pdf.set_fill_color(*fondo)
            pdf.rect(x, y0, w, alto, "F")
            pdf.set_text_color(*COLORES_SEVERIDAD.get(str(valor), TEXTO))
            for j, linea in enumerate(lineas):
                pdf.set_xy(x + 1, y0 + 1 + j * 5)
                pdf.cell(w - 2, 5, linea)
            x += w
        pdf.set_xy(x0, y0 + alto)
   
def recortar(texto, largo):
    """Corta el texto si es más largo que el espacio de la celda"""
    texto = str(texto)
    return texto if len(texto) <= largo else texto[:largo - 3] + "..."

def generar_informe_pdf(resumen, detecciones, riesgos):
    """Va a genererar un informe en pdf a partir del resumen del análisis"""
    por_estado = resumen ["por_estado"]
    ataques = [
        d for d in detecciones
        if d["Severidad"] in ("ALTO", "MEDIO") and d["Tipo"] in  TIPOS_ATAQUE_REAL
    ]
    escaneos = set(resumen ["escaneos"])

    pdf = Informe()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(*AZUL)
    pdf.cell(0,10, "Informe de análisis de logs", ln=True)
    pdf.set_text_color(*TEXTO)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0,6, f"Generado: {datetime.now():%d/%m/%Y %H:%M}", ln=True)

    titulo_seccion(pdf, "Resumen ejecutivo")
    pdf.multi_cell(0, 5, (
        f"Se analizaron {resumen['total']} eventos. "
        f"{por_estado.get('OK', 0)} fueron permitidos, "
        f"{por_estado.get('DENY', 0)} bloqueados y "
        f"{por_estado.get('FAIL', 0)} fallido(s). "
        f"Se detectaron {len(ataques)} ataque(s) confirmado(s) de severidad alta o media y "
        f"{len(escaneos)} posible(s) escaneo(s) de puertos."
    ), align="L")
    pdf.ln(3)
    tarjetas(pdf, [
        ("Total de eventos", resumen["total"]),
        ("Permitidos", por_estado.get("OK", 0)),
        ("Bloqueados", por_estado.get("DENY", 0)),
        ("Ataques", len(ataques)),
    ])
    titulo_seccion(pdf, "Detecciones")

    filas = [
        [d["Severidad"], d["Tipo"], d["Fuente"], d["Origen"], d["Detalle"]]
        for d in detecciones
    ]
    tabla(pdf, ["Severidad", "Tipo", "Fuente", "Origen", "Detalle"],
          filas, [24, 40, 34, 42, 46])
    
    if pdf.get_y() + 12 + 7 + 7 * len(riesgos) > 265:
        pdf.add_page()
    titulo_seccion(pdf, "Nivel de riesgo por origen")
    if riesgos:
        filas = [[r["Origen"], r["Nivel de riesgo"]] for r in riesgos if r["Origen"] != "LOCAL"]
        tabla(pdf, ["Origen", "Nivel de riesgo"], filas, [120, 66])
    else:
        pdf.multi_cell(0, 6, "No hay niveles de riesgo calculados")

    titulo_seccion(pdf, "Recomendaciones")
    recomendaciones = []
    agrupadas = {}
    for d in detecciones: 
        clave = (d["Tipo"], d["Fuente"])
        origenes = agrupadas.setdefault(clave, [])
        if d["Origen"] not in origenes:
            origenes.append(d["Origen"])

    for (tipo, fuente), origenes in agrupadas.items():
        origenes = [ o for o in origenes if o != "LOCAL"]
        if tipo in RECOMENDACIONES and origenes: 
            texto = RECOMENDACIONES[tipo].format(origenes=" , ".join(origenes))
            recomendaciones.append(f"[{fuente}] {texto}")

    if not recomendaciones:
        recomendaciones.append("No se detectaron amenazas que requieran acción inmediata. Mantener el minitoreo continuo.")
    
       

    for n, texto in enumerate(recomendaciones, start=1):
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(170, 6, f"{n}. {texto}", new_x="LMARGIN", new_y="NEXT")

       
    return bytes(pdf.output())

#Toma la lista de eventos y devuelve solo las filas que coinciden con IP y los estados que se elijan
def filtrar_eventos(datos, ip_filtro="", estados=("OK", "FAIL", "DENY")):
    filas = []
    for r in datos:
        if r["estado"] not in estados: 
            continue
        if ip_filtro and ip_filtro not in r["ip"]:
            continue
        filas.append({
            "IP": r["ip"],
            "Usuario": r["usuario"],
            "Estado": r["estado"],
            "Fecha": r["tiempo"].strftime("%Y-%m-%d %H:%M:%S")  if r["tiempo"] else "Sin fecha en el log",
        })
    return filas

def registrar_informe(resumen, detecciones, riesgos):
    """Guarda en la base una copia dell informe que se descarga"""
    crear_tablas()
    nombre = f"informe_{datetime.now():%Y%m%d_%H%M%S}.pdf"
    guardar_informe(nombre, generar_informe_pdf(resumen, detecciones, riesgos))

# Cambia los simbolos raros que pone gemini por otros mas normales
def limpiar_texto(texto):
    """Quita simbolos que la letra helvetica no puede mostrar"""
    cambios = cambios = {"•": "-", "–": "-", "—": "-", "“": '"', "”": '"', "‘": "'", "’": "'", "…": "..."}
    for viejo, nuevo in cambios.items():
        texto = texto.replace(viejo, nuevo)
    return texto.encode("latin-1", "ignore").decode("latin-1")

def generar_pdf_reporte_ia(texto):
    """Convierte el reporte de la IA en n PDF con el mismo diseño que el informe"""
    pdf = Informe()
    pdf.subtitulo = "Reporte del Asistente SOC"
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(*AZUL)
    pdf.cell(0, 10, "Reporte del Asistente SOC", ln=True)
    pdf.set_text_color(*TEXTO)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, f"Generado: {datetime.now():%d/%m/%Y %H:%M}", ln=True)    
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 10)

    for linea in limpiar_texto(texto).splitlines():
        linea = linea.strip()
        if not linea or set(linea) <= set("-*_"):
            pdf.ln(2)
            continue
        if linea.startswith("#"):
            titulo_seccion(pdf, linea.lstrip("#").strip().replace("**", ""))
            continue
        if linea.startswith("**") and linea.endswith("**") and linea.count("**") == 2:
            titulo_seccion(pdf, linea.replace("**", ""))
            continue
        if linea.startswith(("-" , "* ")):
            linea = " - " + linea[2:]
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5.5, linea, markdown=True, align="L", new_x="LMARGIN", new_y="NEXT")
    return bytes(pdf.output())