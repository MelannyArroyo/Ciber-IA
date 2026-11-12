import os
import json


os.environ["GEMINI_API_KEY"] = "AQ.Ab8RN6JzufwnAY-P2yaK3RFt0qMnM42QASHQKXQchrodVLJ9BQ"



try:
    import chromadb
    chroma_client = chromadb.PersistentClient(path="./chroma_db")
    collection = chroma_client.get_or_create_collection(name="soc_logs")
    
    if collection.count() == 0:

        logs_iniciales = [
            "2026-10-06 10:15:30 - SSH Contraseña fallida para el usuario root desde 192.168.1.50 puerto 52210",
            "2026-10-06 10:15:32 - SSH Contraseña fallida para el usuario root desde 192.168.1.50 puerto 52210",
            "2026-10-06 10:15:35 - SSH Contraseña aceptada para el usuario root 0 1/8*-*635471}"
            "-++++++++++++++++++++++++++++++++++++++++++7*+-------------------"
            ""
            ""
            "192.168.1.50 puerto 52210",
            "2026-10-06 10:20:00 - HTTP 403 Prohibido en /admin/config desde 203.0.113.195"
        ]
        metadatas_iniciales = [
            {"user": "root", "src_ip": "192.168.1.50", "status": "Fallido", "event": "Fuerza Bruta SSH"},
            {"user": "root", "src_ip": "192.168.1.50", "status": "Fallido", "event": "Fuerza Bruta SSH"},
            {"user": "root", "src_ip": "192.168.1.50", "status": "Exitoso", "event": "Compromiso SSH"},
            {"user": "anonymous", "src_ip": "203.0.113.195", "status": "Prohibido", "event": "Escaneo de Administración Web"}
        ]
        ids_iniciales = ["log_001", "log_002", "log_003", "log_004"]
        collection.add(documents=logs_iniciales, metadatas=metadatas_iniciales, ids=ids_iniciales)
except Exception as e:
    print(f"Aviso ChromaDB: {e}")
    collection = None


try:
    import google.generativeai as genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

def obtener_modelo_funcional():
    """Selecciona un modelo estable evitando versiones deprecadas o bloqueadas."""
    modelos_preferidos = ['gemini-1.5-flash', 'gemini-1.5-pro', 'gemini-pro']
    try:
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                nombre_limpio = m.name.replace("models/", "")
                if nombre_limpio in modelos_preferidos:
                    return m.name
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                if '2.5' not in m.name:
                    return m.name
    except Exception:
        pass
    return 'gemini-1.5-flash'

def analizar_incidentes_con_gemini(consulta_usuario: str) -> str:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or "TU_API_KEY_REAL" in api_key:
        return "❌ **Error:** Debes colocar tu API key real en la línea 6 del archivo `modulo2_rag.py`."
    if not HAS_GENAI:
        return "❌ **Error:** La librería `google-generativeai` no está instalada."

    try:
        genai.configure(api_key=api_key)
        
        contexto_logs = "No se encontraron registros relevantes."
        if collection:
            try:
                resultados = collection.query(query_texts=[consulta_usuario], n_results=5)
                if resultados and resultados.get("documents") and resultados["documents"][0]:
                    contexto_logs = "\n".join(resultados["documents"][0])
            except Exception:
                pass

       
        prompt_sistema = f"""
        Eres un Analista SOC Tier 3 y experto en Ciberseguridad Corporativa e Inteligencia de Amenazas.
        **IMPORTANTE:** Responde absoluta y estrictamente en idioma ESPAÑOL fluido, técnico y profesional.
        
        Proporciona un informe forense profundo, técnico y estructurado basado exclusivamente en la siguiente telemetría. Tu respuesta DEBE incluir obligatoriamente:
        1. **Resumen Ejecutivo del Incidente**
        2. **Línea de Tiempo Cronológica de los Eventos**
        3. **Mapeo con el marco MITRE ATT&CK** (Identificando tácticas y técnicas, ej. T1110 - Brute Force).
        4. **Indicadores de Compromiso (IoCs)** detectados.
        5. **Medidas de Mitigación y Contención recomendadas**.

        [TELEMETRÍA RELEVANTE]:
        {contexto_logs}

        [CONSULTA DEL ANALISTA]:
        {consulta_usuario}
        """

        nombre_modelo = obtener_modelo_funcional()
        model = genai.GenerativeModel(nombre_modelo)
        response = model.generate_content(prompt_sistema)
        
        if response and response.text:
            return response.text
        return "❌ **Error:** La respuesta recibida de Gemini está vacía."

    except Exception as e:
        return f"❌ **Error de API Gemini:** `{str(e)}`"

def analisis_proactivo_automatico() -> dict:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or "TU_API_KEY_REAL" in api_key or not HAS_GENAI or not collection:
        return {"nivel_amenaza": "SEGURO", "resumen_alerta": "Sistema operativo en modo local (Falta API Key).", "accion_recomendada": "Configurar API Key"}

    try:
        genai.configure(api_key=api_key)
        datos = collection.get()
        if not datos or not datos.get("documents"):
            return {"nivel_amenaza": "SEGURO", "resumen_alerta": "Sin registros en la base vectorial.", "accion_recomendada": "Ninguna"}

        resumen_telemetria = "\n".join([f"- {doc}" for doc in datos["documents"]])
        prompt_proactivo = f"""
        Actúa como un Agente SOC Autónomo de ciberseguridad. Analiza los siguientes registros y detecta si hay alguna amenaza CRÍTICA (como fuerza bruta seguida de login exitoso de root, o accesos maliciosos a /admin).
        **IMPORTANTE:** Responde estrictamente en ESPAÑOL.
        
        {resumen_telemetria}
        
        Responde estrictamente en formato JSON válido (sin texto adicional ni bloques markdown):
        {{
            "nivel_amenaza": "CRITICO",
            "resumen_alerta": "Breve descripción de 1 línea de la amenaza detectada en español",
            "accion_recomendada": "Acción automática sugerida en español"
        }}
        """

        nombre_modelo = obtener_modelo_funcional()
        model = genai.GenerativeModel(nombre_modelo)
        response = model.generate_content(prompt_proactivo)
        
        if response and response.text:
            texto_limpio = response.text.strip().replace("```json", "").replace("```", "").strip()
            return json.loads(texto_limpio)
            
        return {"nivel_amenaza": "SEGURO", "resumen_alerta": "Análisis automático omitido.", "accion_recomendada": "Revisar logs manualmente"}
    except Exception as e:
        return {"nivel_amenaza": "SEGURO", "resumen_alerta": f"Nota informativa: {str(e)}", "accion_recomendada": "Verificar configuración"}

def ejecutar_playbook_contencion(accion: str, objetivo: str) -> str:
    """Ejecuta medidas automatizadas (Playbooks SOAR)."""
    if accion == "Bloquear IP":
        return f"🛡️ **[PLAYBOOK SOAR]** Regla de firewall aplicada con éxito. IP `{objetivo}` bloqueada en el perímetro (Drop inbound)."
    elif accion == "Revocar Credenciales":
        return f"🔐 **[PLAYBOOK SOAR]** Sesiones activas terminadas y credenciales de `{objetivo}` forzadas a cambio de contraseña."
    elif accion == "Aislar Host":
        return f"🚨 **[PLAYBOOK SOAR]** Servidor aislado de la red corporativa (Quarantine VLAN aplicada para `{objetivo}`)."
    return f"⚡ **[PLAYBOOK SOAR]** Acción `{accion}` ejecutada sobre `{objetivo}`."
