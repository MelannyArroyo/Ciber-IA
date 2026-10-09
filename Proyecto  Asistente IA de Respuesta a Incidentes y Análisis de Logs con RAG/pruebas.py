import os 
from dotenv import load_dotenv
from google import genai

load_dotenv()
carpeta = os.path.dirname(os.path.abspath(__file__))
ruta = os.path.join(carpeta,"modulo2_rag.py")

print("=== 1. Revisando modulo 2_rag.py===")
marcas= ["client.models.list", "candidatos", "generate_content", "raise RuntimeError"]
with open(ruta,encoding="utf-8") as f:
    for numero, linea in enumerate(f, start=1):
        if any(m in linea for m in marcas):
            print(f"Linea {numero}: {linea.rstrip()}")
print("\n===Probando modelos===")
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
modelos= [
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-3-flash-preview",
    "gemini-3.1-pro-preview"
]
for m in modelos:
    try:
        r= client.models.generate_content(
            model=m,
            contents="Responde solo con la palabra ok"
        )
        print(f"OK {m}: {r.text.strip()[:40]} ")
    except Exception as e:
         print(f"FALLA {m}: {str(e)[:120]}")