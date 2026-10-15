from fpdf import FPDF
from datetime import datetime
from db import crear_tablas, guardar_informe



AZUL = (31,56,100)
GRIS = (242,244,247)
TEXTO = (45,45,45)

class Informe(FPDF):

    def header(self):
        self.set_fill_color(*AZUL)
        self.rect(0,0,210,26, "F")
        import os
        ruta_logo = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.jpg")
        if os.path.exists(ruta_logo):
            self.image(ruta_logo, x=12, y=5, h=16)

        self.set_xy(34,7)
        self.set_text_color(255,255,255)
        self.set_font("Helvetica", "B", 15)
        self.cell(0,8, "Colmena Technologies ", ln=True)
        self.set_x(34)
        self.set_font("Helvetica", "", 9)
        self.cell(0,6, "Informe de análisis de logs")
        self.set_text_color(*TEXTO)
        self.set_y(32)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(130,130,130)
        self.cell(0,6, f"Página {self.page_no()}", align="R")
        self.set_text_color(*TEXTO)

def titulo_seccion(pdf, texto):
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*AZUL)
    pdf.cell(0,8, texto, ln=True)
    pdf.set_text_color(*TEXTO)
    pdf.set_font("Helvetica", "", 10)

def tarjetas(pdf,valores):
    y0 = pdf.get_y()
    ancho = (186-3*4) / 4
    for i, (titulo,valor) in enumerate(valores):
        x = 12 + i * (ancho +4)
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
    pdf.cell(0,10, "Informe de analisis de logs", ln=True)
    pdf.set_text_color(*TEXTO)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0,6, f"Generado: {datetime.now():%d/%m/%Y %H:%M}", ln=True)

    titulo_seccion(pdf, "Resumen ejecutivo")
    pdf.multi_cell(0, 5, (
        f"Se analizaron {resumen['total']} eventos. "
        f"{por_estado.get('OK', 0)} fueron permitidos, "
        f"{por_estado.get('DENY', 0)} bloqueados y "
        f"{por_estado.get('FAIL', 0)} fallidos. "
        f"Se detectaron {len(ataques)} ataque(s) automatizados(s) y "
        f"{len(escaneos)} posible(s) escaneo(s) de puertos."

    ))
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