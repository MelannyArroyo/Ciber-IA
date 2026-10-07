import os
import chromadb
from chromadb.utils import embedding_functions
from google import genai
from dotenv import load_dotenv

# cargar variables de gemini
load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    raise ValueError(" Error: No se encontró la variable GEMINI_API_KEY en el archivo .env")

# 2. Iniciar cliete gemini y cliente google
client = genai.Client(api_key=api_key)
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="logs_seguridad")

# Generador local de respaldo para embeddings (ONNX)
fallback_embedding_fn = embedding_functions.DefaultEmbeddingFunction()


def obtener_embedding(texto: str) -> list[float]:
    """Genera vector embedding con Gemini API """
    modelos_api = [
        "text-embedding-004",
        "embedding-001"
    ]

    for modelo in modelos_api:
        try:
            response = client.models.embed_content(
                model=modelo,
                contents=texto
            )
            if hasattr(response, "embeddings") and response.embeddings:
                return [float(x) for x in response.embeddings[0].values]
            elif hasattr(response, "embedding") and response.embedding:
                return [float(x) for x in response.embedding.values]
        except Exception:
            continue

    #
    vector_local = fallback_embedding_fn([texto])[0]
    return [float(x) for x in vector_local]


def agregar_logs_a_vectorstore(lista_de_logs: list[dict]) -> int:
    """Procesa logs."""
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

    collection.add(
        ids=ids,
        embeddings=embeddings,
        documents=documents,
        metadatas=metadatas
    )
    return len(lista_de_logs)


def buscar_logs_relevantes(pregunta_usuario: str, top_k: int = 5) -> list[str]:
    """Recupera los logs con mayor similitud vectorial desde chromaDB."""
    vector_pregunta = obtener_embedding(pregunta_usuario)

    resultados = collection.query(
        query_embeddings=[vector_pregunta],
        n_results=top_k
    )

    documents = resultados.get("documents", [[]])
    return documents[0] if documents else []


def analizar_incidentes_con_gemini(pregunta_usuario: str) -> str:
    """Busca contexto en ChromaDB y detecta automáticamente los modelos habilitados con mi api key."""
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

    #  lista de modelos
    candidatos = []
    try:
        for m in client.models.list():
            nombre = m.name if hasattr(m, "name") else str(m)
            if "gemini" in nombre.lower():
                candidatos.append(nombre)
    except Exception:
        pass

    # 2. Respaldos estándar
    candidatos.extend([
        "gemini-2.5-flash",
        "gemini-2.0-flash",
        "gemini-1.5-flash",
        "gemini-1.5-pro",
        "models/gemini-2.5-flash",
        "models/gemini-2.0-flash",
        "models/gemini-1.5-flash"
    ])

    candidatos_unicos = list(dict.fromkeys(candidatos))

    ultimo_error = None
    for modelo in candidatos_unicos:
        try:
            response = client.models.generate_content(
                model=modelo,
                contents=prompt
            )
            if response and hasattr(response, "text") and response.text:
                return response.text
        except Exception as e:
            ultimo_error = e
            continue

    raise RuntimeError(f" No se pudo conectar con ningún modelo de Gemini. Error final: {ultimo_error}")



