from fpdf import FPDF
from datetime import datetime
from db import crear_tablas, guardar_informe
import os

FONDO_OSCURO = (15, 23, 42)
AZUL = (37, 99, 235)
TURQUESA = (34, 211, 238)
GRIS= (241, 245, 249)
TEXTO = (30,41,59)


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

def tabla(pdf,encabezados, filas, anchos):
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(*FONDO_OSCURO)
    pdf.set_fill_color(255,255,255)
    for h, w in zip(encabezados, anchos):
        pdf.cell(w,7,h,fill=True)
    pdf.ln()
    pdf.set_text_color(*TEXTO)
    pdf.set_font("Helvetica", "", 9)
    for i, fila in enumerate(filas):
        pdf.set_fill_color(*(GRIS if i % 2 else (255,255,255)))
        for valor, w in zip(fila,anchos):
            pdf.cell(w, 6.5, str(valor), fill=True)
        pdf.ln()

def generar_informe_pdf(resumen):
    """Va a genererar un informe en pdf a partir del resumen del análisis"""
    por_estado = (resumen["por_estado"])
    ataques = set(resumen["ataques"])
    escaneos = set(resumen["escaneos"])

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
        f"Se detectaron {len(ataques)} ataque(s) automatizados(s) y "
        f"{len(escaneos)} posible(s) escaneo(s) de puertos."
    ), align="L")
    pdf.ln(3)
    tarjetas(pdf, [
        ("Total de eventos", resumen["total"]),
        ("Permitidos", por_estado.get("OK", 0)),
        ("Bloqueados", por_estado.get("DENY", 0)),
        ("Ataques", len(ataques)),
    ])
    titulo_seccion(pdf, "Hallazgos por IP")
    ips= list(resumen["sospechosos"]) + [
        ip for ip in resumen["escaneos"] if ip not in resumen["sospechosos"]
    ]
    filas = []
    for ip in ips:
        fallos = resumen["sospechosos"].get(ip, 0)
        usuario = resumen["usuarios"].get(ip, ("N/A", 0,))[0]
        if ip in ataques:
            tipo, severidad = f"Fuerza bruta contra {usuario}", "Alta"
        elif ip in escaneos:
            tipo, severidad = "Escaneo de puertos", "Media"
        else:
            tipo, severidad = "Intentos fallidos", "Baja"
        filas.append([ip, fallos, tipo, severidad])

    if filas:
        tabla(pdf, ["IP origen", "Fallos", "Tipo", "Severidad"], filas, [50, 30, 60, 46])
    else:
        pdf.multi_cell(0, 6, "No se encontraron IPs sospechosas. ")

    titulo_seccion(pdf, "Recomendaciones")
    recomendaciones = [f"Bloquear la IP {ip} en el firewall perimetral. " for ip in ataques] 
    if ataques:
        recomendaciones.append("Revisar las cuentas atacadas y cambiar sus contraseñas si hay dudas. ")
    recomendaciones += [f"Revisar la actividad de {ip} y los puertos que intentó alcanzar. " for ip in escaneos]
    recomendaciones.append("Mantener el monitoreo continuo y revisar este informe periódicamente. ")

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

def registrar_informe(resumen):
    """Guarda en la base una copia dell informe que se descarga"""
    crear_tablas()
    nombre = f"informe_{datetime.now():%Y%m%d_%H%M%S}.pdf"
    guardar_informe(nombre, generar_informe_pdf(resumen))

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