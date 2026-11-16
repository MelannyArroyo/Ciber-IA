import os
import chromadb
from chromadb.utils import embedding_functions
from google import genai
from google.genai import types
from dotenv import load_dotenv
from Ingest_modulo1 import ingestar_logs, ingestar_firewall, a_esquema_rag, ruta_archivo, ruta_firewall
import re
import time
import numpy as np #Aplana el vector para que sea una lista simple de numeros


# 1. Cargar variables de entorno desde .env
load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    raise ValueError(" Error: No se encontró la variable GEMINI_API_KEY en el archivo .env")

# 2. Inicializar cliente Gemini y cliente ChromaDB
print(" Conectando con clientes de Gemini y ChromaDB...", flush=True)
client = genai.Client(api_key=api_key, http_options=types.HttpOptions(timeout=30000))
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="logs_seguridad")

# Generador local de respaldo para embeddings (ONNX)
fallback_embedding_fn = embedding_functions.DefaultEmbeddingFunction()
MODELO_ACTIVO = None # Guarda el modelo que funcionó para no buscarlo en cada pregunta
EMBEDDING_ACTIVO = None # Guarda la ruta de embeddings que funcionó

def _texto_en_partes(primero, resto):
    """Entrega la respuesta de Gemini por partes, conforme va llegando"""
    yield primero.text or ""
    for parte in resto:
        yield parte.text or ""



def obtener_embedding(texto: str) -> list[float]:
   """Usa la misma ruta de embeddings siempre, para que guardar y buscar usen las mismas dimensiones"""
   global EMBEDDING_ACTIVO
   if EMBEDDING_ACTIVO is None:
        EMBEDDING_ACTIVO = "onnx" #Ruta local, sin llamadas  de red
   if EMBEDDING_ACTIVO == "onnx":
       vector_local = np.asarray(fallback_embedding_fn([texto]) [0]).reshape(-1) # Aplana el arreglo a una sola dimension antes de convertirlo en lista
       return [float(x) for x in vector_local]
       
   


def agregar_logs_a_vectorstore(lista_de_logs: list[dict]) -> int:
    """Procesa logs, calcula embeddings y guarda en ChromaDB."""
    ids = []
    embeddings = []
    documents = []
    metadatas = []

    for idx, log in enumerate(lista_de_logs):
        log_id = f"log_{idx}_{log.get('timestamp', 'sin_fecha')}"
        texto_log = (
            f"Timestamp: {log.get('timestamp', 'N/A')} | "
            f"Evento: {log.get('event', 'N/A')} | "
            f"IP Origen: {log.get('src_ip', 'N/A')} | "
            f"IP Destino: {log.get('dst_ip', 'N/A')} | "
            f"Usuario: {log.get('user', 'N/A')} | "
            f"Estado: {log.get('status', 'N/A')}"
        )

        vector = obtener_embedding(texto_log)

        ids.append(log_id)
        embeddings.append(vector)
        documents.append(texto_log)
        metadatas.append({k: str(v) for k, v in log.items()})

    collection.upsert(
        ids=ids,
        embeddings=embeddings,
        documents=documents,
        metadatas=metadatas
    )
    return len(lista_de_logs)

def buscar_logs_relevantes(pregunta_usuario: str, top_k: int = 5) -> list[str]: 
    """Primero busca los logs de las IPs mencionadas y luego completa similitud vectorial."""
   
    docs_ip = []
    for ip in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", pregunta_usuario):
        encontrados = collection.get(where={"src_ip": ip}, limit=5)
        docs_ip.extend(encontrados.get("documents", []))
    
#Siempre incluye los fallos y bloqueos, que son los eventos de seguridad
    docs_alerta = []
    for estado in ("FAIL","DENY"):
        encontrados = collection.get(where={"status": estado}, limit=8)
        docs_alerta.extend(encontrados.get("documents", []))
        
    vector_pregunta = obtener_embedding(pregunta_usuario)
    resultados = collection.query(
        query_embeddings=[vector_pregunta], 
        n_results=top_k 
    )
    docs_similares = resultados.get("documents",[[]])[0]
    return list(dict.fromkeys(docs_ip +  docs_alerta + docs_similares))

    


def analizar_incidentes_con_gemini(pregunta_usuario: str, contexto_app: str = "", modo: str = "chat", stream: bool = False) -> str:
    """Busca contexto en ChromaDB y realiza la consulta filtrando exclusivamente modelos de texto."""
    global MODELO_ACTIVO
    Inicio = time.perf_counter()
    print("  🔎 Buscando contexto en ChromaDB...", flush=True)
    logs_relacionados = buscar_logs_relevantes(pregunta_usuario)
    print(f" Búsqueda en ChromaDB: {time.perf_counter() - Inicio:.1f} s", flush=True)

    if logs_relacionados:
        contexto = "\n".join(f"- {log}" for log in logs_relacionados)
    else:
        contexto = "No se encontraron logs relevantes en la base de datos."

    if modo == "reporte":
        instrucciones = """1. Diagnóstico y resumen de los hallazgos.
        2. Nivel de severdidad (Bajo, Medio, Alto, Crítico) con su justificación .
        3.Técnicas de MITRE ATT&CK relacionadas: usa tu conocimiento de marco de relacionar el comportamiento observado con sus técnicas (por ejemplo, T1110 - Brute Force).
        4. Indicadores de compromiso (IPs, usuarios o puertos involucrados).
        5. Recomendaciones concretas de mitigación y contención."""
    else:
        instrucciones = """Responde SOLO lo que pregunta el analista, de forma breve y directa (máximo 150 palabras).
        Usa viñetas si ayudan. Menciona técnicas MITRE ATT&CK o reconocimiento solo si la pregunta las pide o si son importantes."""
        


    prompt = f"""
Eres un analista experto en ciberseguridad y Centro de Operaciones de Seguridad (SOC).
Responde siempre en español, de forma clara y técnica.
Analiza la consulta utilizando EXCLUSIVAMENTE la información provista abajo.
Si algo no aparece en los datos, dilo en lugar de inventarlo.

--- DETECCIONES ACTUALES DEL SISTEMA ---ç
{contexto_app or "No se enviaron detecciones."}

--- CONTEXTO DE LOS LOGS RECUPERADOS ---
{contexto}

---CONSULTA DEL ANALISTA ---
{pregunta_usuario}

--- INSTRUCCIONES DE RESPUESTA ---
{instrucciones}
"""

    # Modelos estándar de texto priorizados (sin prefijos)
    candidatos = [
        "gemini-flash-lite-latest", 
        "gemini-3.8-flash",
         

    ]
    if MODELO_ACTIVO:
        candidatos = [MODELO_ACTIVO] + [m for m in candidatos if m != MODELO_ACTIVO]

    # Filtrar únicamente modelos válidos para texto desde la API
    if MODELO_ACTIVO is None: # Solo pide la lista de modelos la primera vez
        try:
            for m in client.models.list():
                raw_name = m.name if hasattr(m, "name") else str(m)
                nombre = raw_name.replace("models/", "")
                
                # Excluir modelos de voz, audio, embeddings o imágenes
                es_invalido = any(x in nombre.lower() for x in ["tts", "embed", "audio", "imagen", "realtime", "pro"])
                if "gemini" in nombre.lower() and not es_invalido:
                    if nombre not in candidatos:
                        candidatos.append(nombre)
        except Exception:
            pass
    if MODELO_ACTIVO:
        candidatos.insert(0, MODELO_ACTIVO) #Prueba primero el que ya funcionó

    ultimo_error = None
    for modelo in candidatos:
        try:
            print(f"  👉 Probando generación con: {modelo}...", flush=True)
            if stream:
                partes = iter(client.models.generate_content_stream(model=modelo, contents=prompt))
                primero = next(partes) # Si el modelo no sirve, el error de sale aquí y prueba el siguiente 
                print(f" ⏱️ Primera parte de Gemini: {time.perf_counter() - Inicio:.2f} s", flush=True)
                MODELO_ACTIVO = modelo
                return _texto_en_partes(primero, partes)
            
            response = client.models.generate_content(
                model=modelo,
                contents=prompt
            )
            if response and hasattr(response, "text") and response.text:
                print(f"  ✅ Respuesta recibida exitosamente desde {modelo}\n", flush=True)
                MODELO_ACTIVO = modelo
                return response.text
        except Exception as e:
            print(f"  ⚠️ {modelo} falló ({e}), intentando el siguiente...", flush=True)
            ultimo_error = e
            continue

    raise RuntimeError(f" Ningún modelo disponible pudo responder. Último error: {ultimo_error}")


# --- BLOQUE DE EJECUCIÓN DIRECTA ---
if __name__ == "__main__":
    MAX_FIREWALL = 200
    logs_csv = ingestar_logs(ruta_archivo)
    logs_fw = ingestar_firewall(ruta_firewall)

  #Todos los inicios de sesion y solo los bloqueos de firewall
    bloqueos = [r for r in logs_fw if r["estado"] == "DENY"] [:MAX_FIREWALL]
    relevantes = logs_csv + bloqueos
#Borra los datos de muestra que habia antes
    viejos = collection.get()["ids"]
    if viejos:
        collection.delete(ids=viejos)
        print(f"Se borraron {len(viejos)} eventos de muestra")
    logs_rag = [a_esquema_rag (r) for r in relevantes]
    total = agregar_logs_a_vectorstore(logs_rag)
    print(f"Se guardaron {[total]} eventos en ChromaDB")

    resultado = analizar_incidentes_con_gemini("¿Que ocurrio con la IP 192.168.1.50")
    print(resultado)