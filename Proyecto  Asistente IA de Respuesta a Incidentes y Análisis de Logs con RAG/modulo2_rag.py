import os
import chromadb
from chromadb.utils import embedding_functions
from google import genai
from dotenv import load_dotenv
from Ingest_modulo1 import ingestar_logs, ingestar_firewall, a_esquema_rag, ruta_archivo, ruta_firewall
import re

# 1. Cargar variables de entorno desde .env
load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    raise ValueError(" Error: No se encontró la variable GEMINI_API_KEY en el archivo .env")

# 2. Inicializar cliente Gemini y cliente ChromaDB
print(" Conectando con clientes de Gemini y ChromaDB...", flush=True)
client = genai.Client(api_key=api_key)
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="logs_seguridad")

# Generador local de respaldo para embeddings (ONNX)
fallback_embedding_fn = embedding_functions.DefaultEmbeddingFunction()


def obtener_embedding(texto: str) -> list[float]:
    """Genera vector embedding con Gemini API o procesador local si falla."""
    modelos_api = ["text-embedding-004", "embedding-001"]

    for modelo in modelos_api:
        try:
            response = client.models.embed_content(model=modelo, contents=texto)
            if hasattr(response, "embeddings") and response.embeddings:
                return [float(x) for x in response.embeddings[0].values]
            elif hasattr(response, "embedding") and response.embedding:
                return [float(x) for x in response.embedding.values]
        except Exception:
            continue

    # Fallback local garantizado
    vector_local = fallback_embedding_fn([texto])[0]
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
   
        encontrados = collection.get(where={"src_ip": ip}, limit=20)
        docs_ip.extend(encontrados.get("documents", []))
        
    vector_pregunta = obtener_embedding(pregunta_usuario)
    resultados = collection.query(
        query_embeddings=[vector_pregunta], 
        n_results=top_k 
    )
    docs_similares = resultados.get("documents",[[]])[0]
    return list(dict.fromkeys(docs_ip + docs_similares))

    


def analizar_incidentes_con_gemini(pregunta_usuario: str) -> str:
    """Busca contexto en ChromaDB y realiza la consulta filtrando exclusivamente modelos de texto."""
    print("  🔎 Buscando contexto en ChromaDB...", flush=True)
    logs_relacionados = buscar_logs_relevantes(pregunta_usuario)

    if logs_relacionados:
        contexto = "\n".join(f"- {log}" for log in logs_relacionados)
    else:
        contexto = "No se encontraron logs relevantes en la base de datos."

    prompt = f"""
Eres un analista experto en ciberseguridad y Centro de Operaciones de Seguridad (SOC).
Analiza la siguiente consulta utilizando EXCLUSIVAMENTE el contexto de logs provisto.

--- CONTEXTO DE LOGS RECUPERADOS ---
{contexto}

--- CONSULTA DEL ANALISTA ---
{pregunta_usuario}

--- INSTRUCCIONES DE RESPUESTA ---
1. Diagnóstico y resumen de los hallazgos.
2. Nivel de severidad (Bajo, Medio, Alto, Crítico) con su respectiva justificación.
3. Recomendaciones concretas de mitigación y contención.
"""

    # Modelos estándar de texto priorizados (sin prefijos)
    candidatos = [
       "gemini-5.5-flash",
        "gemini-2.0-flash",
        "gemini-1.5-flash",
        "gemini-2.5-pro"
        "gemini-3.8-flash",
        "gemini-3.1-pro-preview"
    ]

    # Filtrar únicamente modelos válidos para texto desde la API
    try:
        for m in client.models.list():
            raw_name = m.name if hasattr(m, "name") else str(m)
            nombre = raw_name.replace("models/", "")
            
            # Excluir modelos de voz, audio, embeddings o imágenes
            es_invalido = any(x in nombre.lower() for x in ["tts", "embed", "audio", "imagen", "realtime"])
            if "gemini" in nombre.lower() and not es_invalido:
                if nombre not in candidatos:
                    candidatos.append(nombre)
    except Exception:
        pass

    ultimo_error = None
    for modelo in candidatos:
        try:
            print(f"  👉 Probando generación con: {modelo}...", flush=True)
            response = client.models.generate_content(
                model=modelo,
                contents=prompt
            )
            if response and hasattr(response, "text") and response.text:
                print(f"  ✅ Respuesta recibida exitosamente desde {modelo}\n", flush=True)
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