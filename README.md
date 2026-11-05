# Ciber-IA
# Asistente IA de Respuesta a Incidentes y Análisis de Logs con RAG
Proyecto de práctica profesional en Colmena Technologies.
Aplicacion web que se centraliza en logs de seguridad, detecta ataques automaticamente,
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
- Exportacion automática de eventos de Windows y copia del log del firewall cada 30 minutos (tarea programada)
- Mini servidor web (Flask) con registro e inicio de sesión, que identifica si el acceso viene de un teléfono o una computadora
- Cuentas secundarias agrupadas por correo principal
- Detección de enumeración de usuarios, acceso desde varios dispositivos y cuentas bloqueadas
- Bloqueo temporal de cuentas después de varios intentos fallidos
- Alertas clasificadas por severidad (alto, medio e informativo)
- Nivel de riesgo por origen (bajo,  medio, crítico)
- Tabla única de eventos de Windows, firewall y servidor web con filtros
- Política de retención de 90 días

## Tecnologías
- Python 3.14
- Streamlit (interfaz web)
- SQLite (base de datos)
- bcrypt (cifrado de contraseñas)
- ChromaDB y Gemini API (RAG)
- fpdf2 (informes PDF)
- smtplib (envio de correos)
- Flask
- pandas (tablas y filtros)
- PowerShell (exportación de eventos de windows y firewall)
- Programador de tareas de Windows (vigilancia automática)

## Estructura del proyecto 
|Archivo | Función |
|---|---|
|`app.py`| Interfaz web y flujo principal |
|`Ingest_modulo1.py`|Lectura de logs y detecciones |
|`modulo2_rag.py `| Busqueda en ChromaDB y respuestas con Gemini |
|`db.py`| Tablas y consultas de la base de datos |
|`auth.py`| Registro e inicio de sesión y roles |
|`backend_logs.py`| Informe PDF y filtros de eventos |
|`notificaciones.py`| Envío de alertas por correo |
|`prueba_detecciones.py` | Pruebas de las detecciones |
|`vigilancia.py` | Vigilancia automática cada 30 minutos |
|`exportar_eventos.ps1` | Exporta eventos de Windows y copia el log del firewall |
|`servidor_web.py` | Servidor web de pruebas con registro e inicio de sesión  |
|`simular_ataque.py` | Simula ataques controlados contra el servidor de pruebas |
|`medir_tiempo.py`|Mide el tiempo de respuesta del login (ataque de tiempo) |
|`.streamlit/config.toml`| Tema visual de la aplicación |


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
Crear un archivo`.env` en la carpeta del proyecto con estos datos: 
```
GEMINI_API_KEY=clave_de_gemini
CORREO_REMITENTE=correo@gmail.com
CORREO_CLAVE=contraseña_de_aplicacion
CORREO_DESTINO=correo_que_recibe_alertas@gmail.com
```
El archivo `.env`no se sube a Github(está en `.gitignore`).

## Uso 
```
.\.venv\Scripts\python.exe -m streamlit run app.py
```
Se abre la app en el navegador. El administrador puede crear usuarios desde la barra lateral.

```
.\.venv\Scripts\python.exe servidor_web.py
```
Servidor web de peruebas (solo en la red local):

```
.\.venv\Scripts\python.exe simular_ataque.py
```
La vigilancia automatica se ejecuta con el programador de tareas de windows, con privilegios de administrador, porque se necesiata leer el registro de seguridad y el log del firewall

## Seguridad
- **Contraseñas:** se guardan cifradas con bcrypt, nunca en texto plano.
- **Claves y credenciales:** se leen desde `.env` con `python-dotenv`; no estan escritas en el código 
- **Roles:**
    - *Administrador:* puede ver todo y crear usuarios
    - *Analista:* consulta eventos, alertas e informes 
- **Datos Sensibles:** `.env`, `soc.db` y los logs reales están excluidos del repositorio
- **Bloqueo temporal** 5 contraseñas incorrectas en 5 minutos bloquean la cuenta, aunque luego se escriba la contraseña correcta
- **Mensajes genéricos** el login responde siempre "Usuario o contraseña incorrectos", para no revelar qué usuarios existen.
- **Ataque de tiempo** el login tarda lo mismo si el usuario existe o no.
- **XSS** los datos del usuario se muestran con `html.escape()`
- **Lista blanca DNS**  las respuestas de los servidores DNS  de la red no se cuentan  como escaneo de puertos
- **Retención** los eventos se borran  después de 90 días;  las alertas de conservan como evidencia


## Pruebas 
```
.\.venv\Scripts\python prueba_detecciones.py
```
Comprueba las detecciones con casos conocidos. Resultado esperado: `21 de 21 pruebas pasaron`.

## Autores 
Melanny: backend y ciberseguridad
Ethan: frontend e IA




