# Ciber-IA
# Asistente IA de Respuesta a Incidentes y Análisis de Logs con RAG
Proyecto de práctica profesional en Colmena Technologies.
Aplicacion web que se centraliza en logs de seguridad, detecta atques automaticamente,
envia alertas por correo y permite consultar los eventos con un asistente de IA.

## Funcionalidades
- Lectura de logs de inicio de sesión de Windows(CSV) y del firewall(`pfirewall.log`)
- Filtro de trafico de ruido de la red local
- Deteccion de fuerza bruta, escaneo de puertos y correlacion de eventos
- Alertas automaticas por correo una sola notificacion por IP y tipo de ataque
- Guardado de eventos y alertas en una base de datos SQlite(`soc.db`) sin duplicados 
- Informe PDF descargable con historial de informes
- Chat con IA (Gemini + ChromaDB) para consultar los logs 
- Inicio de sesion con roles: administrador y analista

## Tecnologías
- Python 3.14
- Streamlit (interfaz web)
- SQLite (base de datos)
- bcrypt (cifrado de contraseñas)
- ChromaDB y Gemini API (RAG)
- fpdf2 (informes PDF)
- smtplib (envio de correos)

## Estructura del proyecto 
│Archivo │ Función │
│---│---│
│`app.py`│ Interfaz web y flujo principal │
│`Ingest_modulo1.py`│ Lectura de logs y detecciones │
│`modulo2.rag.py `│ Busqueda en ChromaDB y respuestas con Gemini │
│`db.py`│ Tablas y consultas de la base de datos │
│`auth.py`│ Registro e inicio de sesión y roles │
│`backend_logs.py`│ Informe PDF y filtros de eventos │
│`notificaciones`│ Envío de alertas por correo │
│`prueba_detecciones.py │ Pruebas de las detecciones │

## Instalación 
1. Clonar el repositorio
2. Crear el entorno virtual:
   ```
   python -m venv .venv
   ```
3. Instalar las librerías: 
  ```
  .\venv\Scripts\python -m pip install -r requirements.txt
  ```
## Configuración 
Crear un archivob`.env` en la carpeta del proyecto con estos datos: 
```
GEMINI_API_KEY=clave_de_gemini
CORREO_REMITENTE=correo@gmail.com
CORREO_CLAVE=contraseña_de_aplicacion
CORREO_DESTINO=correo_que_recibe_alertas@gmail.com
```
El archivo `.env`no se sube a Github(está es `.gitignore`).

## Uso 
```
.\.venv\Scripts\python.exe -m streamlit run app.py
```
Se abre la app en el navegador. El administrador puede crear usuarios desde la barra lateral.

## Seguridad
- **Contraseñas:** se guardan cifradas con bcrypt, nunca en texto plano.
- **Claves y credenciales:** se leen desde `.env` con `python-dotenv`; no estan escritas en el código 
- **Roles:**
    - *Administrador:* puede ver todo y crear usuarios
    - *Analista:* consulta eventos, alertas e informes 
- **Datos Sensibles:** `.env`, `soc.db` y los logs reales están excluidos del repositorio

## Pruebas 
```
.\.venv\Scripts\python prueba_detecciones.py
```
Comprueba las detecciones con casos conocidos. Resultado esperado: `11 de 11 pruebas pasaron`.

## Autores 
Melanny: backend y ciberseguridad
Ethan: frontend e IA




