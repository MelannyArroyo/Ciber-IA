from fpdf import FPDF
from datetime import datetime

def generar_informe_pdf(resumen):
    """Va a genrerar un informe en pdf a partir del resumen del analisis"""
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0,10, "Informe de analisis de logs", ln=True)

    pdf.set_font("Helvetica", "" , 10)
    pdf.cell(0,6, f"Generado:  {datetime.now(): %d/%m/%Y %H:%M}", ln=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0,8, "Resumen", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0,6, f"Total de eventos analizados: {resumen['total']}", ln=True)
    pdf.cell(0,6, f"IPs sospechosas: {len(resumen['sospechosos'])}", ln=True)
    pdf.cell(0,6, f"Ataques automatizados: {len(resumen['ataques'])}", ln=True)
    pdf.cell(0,6, f"Posibles escaneos de puertos: {len(resumen['escaneos'])}", ln=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0,8, "IPs sospechosas", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for ip,fallos in resumen["sospechosos"].items():
        pdf.cell(0,6, f"- {ip}: {fallos} fallos", ln=True)
    return bytes(pdf.output())