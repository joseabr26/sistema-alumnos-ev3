"""!
@file app.py
@brief "Sistema Alumnos" de SecureDev: API y portal web de alumnos (Evaluación Parcial 3, OCY1102).

VERSIÓN CORREGIDA (solución EV3). Correcciones aplicadas (cada una va en su commit VULN-xx):
  - VULN-01: Inyección SQL en /alumnos/buscar  -> consulta parametrizada (CWE-89)
  - VULN-02: XSS reflejado en /hello           -> se escapa la salida (CWE-79)
  - VULN-03: MD5 y credenciales en el código   -> hash PBKDF2 + variables de entorno (CWE-327/798)
  - VULN-04: debug=True en producción          -> debug por variable de entorno (CWE-489)
  - VULN-05: cabeceras de seguridad faltantes  -> X-Content-Type-Options, X-Frame-Options, CSP

Además de las rutas de negocio, la app publica métricas para Prometheus en /metrics.
Las métricas de seguridad (logins fallidos y peticiones sospechosas) se ven en Grafana.
"""
import os
import re
import sqlite3
import time

from flask import Flask, Response, g, jsonify, render_template_string, request
from markupsafe import escape
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

## VULN-03: la clave de la app y las credenciales del admin salen del entorno, NO del código.
SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(24).hex())
ADMIN_USUARIO = os.environ.get("ADMIN_USUARIO", "admin")
## Hash fuerte (PBKDF2 con sal). De respaldo se genera uno para que el laboratorio funcione;
## en un entorno real este valor SIEMPRE vendría de una variable de entorno / gestor de secretos.
ADMIN_CLAVE_HASH = os.environ.get("ADMIN_CLAVE_HASH", generate_password_hash("admin"))
app.config["SECRET_KEY"] = SECRET_KEY

## Versión desplegada: la inyecta el pipeline (1.0.<build>+<commit>). Sirve para la trazabilidad.
VERSION = os.environ.get("APP_VERSION", "dev")
## Archivo SQLite con los alumnos (cada entorno usa el suyo).
DB_PATH = os.environ.get("DB_PATH", "alumnos.db")

ALUMNOS_INICIALES = [
    (1, "Ana Pérez", "Ingeniería en Informática", 6.1),
    (2, "Benjamín Rojas", "Ingeniería en Ciberseguridad", 5.4),
    (3, "Camila Soto", "Analista Programador", 6.8),
    (4, "Diego Muñoz", "Ingeniería en Informática", 4.9),
]

# ---------------------------------------------------------------- métricas (no modificar los nombres)
HTTP_PETICIONES = Counter("http_requests_total", "Peticiones HTTP atendidas", ["method", "endpoint", "status"])
HTTP_LATENCIA = Histogram("http_request_duration_seconds", "Duración de las peticiones HTTP", ["endpoint"])
LOGIN_FALLIDOS = Counter("login_fallidos_total", "Intentos de inicio de sesión fallidos")
LOGIN_EXITOSOS = Counter("login_exitosos_total", "Inicios de sesión correctos")
SOSPECHOSAS = Counter("peticiones_sospechosas_total", "Peticiones con patrones de ataque", ["tipo"])
APP_INFO = Gauge("app_info", "Versión desplegada de la aplicación", ["version"])
APP_INFO.labels(version=VERSION).set(1)

## Patrones que delatan un intento de ataque (detección, no bloqueo).
PATRONES_ATAQUE = {
    "xss": re.compile(r"<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img", re.I),
    "sqli": re.compile(r"('|%27)\s*(or|and|union)\b|union\s+select|--|;\s*drop\b|sleep\(", re.I),
    "path_traversal": re.compile(r"\.\./|\.\.\\|%2e%2e", re.I),
}

PORTADA = """<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>Sistema Alumnos</title></head>
<body>
<h1>Sistema Alumnos · SecureDev</h1>
<p>Versión {{ version }}</p>
<ul>
  <li><a href="/alumnos">Listado de alumnos (JSON)</a></li>
  <li><a href="/alumnos/1">Alumno 1</a></li>
  <li><a href="/hello?name=Ana">Saludo</a></li>
</ul>
<h2>Buscar alumno</h2>
<form action="/alumnos/buscar" method="get">
  <input name="nombre" value="Ana"> <button type="submit">Buscar</button>
</form>
<h2>Acceso administrador</h2>
<form action="/login" method="post">
  <input name="usuario" value="admin"> <input name="clave" type="password" value="">
  <button type="submit">Entrar</button>
</form>
</body>
</html>"""


def conectar():
    """!
    @brief Abre (una vez por petición) la conexión a la base de datos SQLite.
    @return Conexión sqlite3 con filas accesibles por nombre de columna.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(_error):
    """!
    @brief Cierra la conexión a la base de datos al terminar cada petición.
    @param _error Excepción de la petición (si la hubo); no se usa.
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


def iniciar_db():
    """!
    @brief Crea la tabla de alumnos y carga los datos iniciales si está vacía.
    """
    db = sqlite3.connect(DB_PATH)
    db.execute("CREATE TABLE IF NOT EXISTS alumnos (id INTEGER PRIMARY KEY, nombre TEXT, carrera TEXT, promedio REAL)")
    if db.execute("SELECT COUNT(*) FROM alumnos").fetchone()[0] == 0:
        db.executemany("INSERT INTO alumnos VALUES (?, ?, ?, ?)", ALUMNOS_INICIALES)
    db.commit()
    db.close()


@app.before_request
def antes_de_la_peticion():
    """!
    @brief Marca el inicio de la petición y cuenta los parámetros con patrones de ataque.
    """
    g.inicio = time.perf_counter()
    valores = list(request.args.values()) + list(request.form.values())
    for tipo, patron in PATRONES_ATAQUE.items():
        if any(patron.search(v) for v in valores):
            SOSPECHOSAS.labels(tipo=tipo).inc()
            app.logger.warning("Petición sospechosa (%s) desde %s a %s", tipo, request.remote_addr, request.path)


@app.after_request
def despues_de_la_peticion(respuesta):
    """!
    @brief Registra la métrica de cada petición y agrega cabeceras de seguridad (VULN-05).
    @param respuesta Respuesta que Flask enviará al cliente.
    @return La misma respuesta, con cabeceras de seguridad.
    """
    endpoint = request.url_rule.rule if request.url_rule else "desconocido"
    if endpoint != "/metrics":
        HTTP_PETICIONES.labels(request.method, endpoint, str(respuesta.status_code)).inc()
        HTTP_LATENCIA.labels(endpoint).observe(time.perf_counter() - g.get("inicio", time.perf_counter()))
    # VULN-05: cabeceras que ZAP pide (evitan sniffing de tipo, clickjacking e inyección de contenido).
    respuesta.headers["X-Content-Type-Options"] = "nosniff"
    respuesta.headers["X-Frame-Options"] = "DENY"
    respuesta.headers["Content-Security-Policy"] = "default-src 'self'"
    respuesta.headers["Referrer-Policy"] = "no-referrer"
    return respuesta


@app.route("/")
def portada():
    """!
    @brief Portada HTML con enlaces y formularios del sistema.
    @return Página HTML.
    """
    return render_template_string(PORTADA, version=VERSION)


@app.route("/hello")
def hello():
    """!
    @brief Saluda al usuario cuyo nombre llega en el parámetro de URL «name».
    @return Página HTML con el saludo (la entrada se escapa: VULN-02).
    """
    name = request.args.get("name", "visitante")
    # VULN-02: escape() convierte <script> en texto inofensivo -> no hay XSS reflejado.
    return f"<h1>Hola, {escape(name)}!</h1>"


@app.route("/health")
def health():
    """!
    @brief Estado de la aplicación (lo usan el despliegue y el monitoreo).
    @return JSON {"estado": "ok"}.
    """
    return jsonify({"estado": "ok"})


@app.route("/version")
def version():
    """!
    @brief Versión desplegada, para la trazabilidad.
    @return JSON con el nombre y la versión de la aplicación.
    """
    return jsonify({"aplicacion": "Sistema Alumnos", "version": VERSION})


@app.route("/alumnos")
def listar_alumnos():
    """!
    @brief Lista todos los alumnos.
    @return JSON con la lista de alumnos.
    """
    filas = conectar().execute("SELECT * FROM alumnos ORDER BY id").fetchall()
    return jsonify([dict(f) for f in filas])


@app.route("/alumnos/<int:alumno_id>")
def obtener_alumno(alumno_id):
    """!
    @brief Obtiene un alumno por su identificador.
    @param alumno_id Identificador numérico del alumno.
    @return JSON con el alumno, o error 404 si no existe.
    """
    fila = conectar().execute("SELECT * FROM alumnos WHERE id = ?", (alumno_id,)).fetchone()
    if fila is None:
        return jsonify({"error": "Alumno no encontrado"}), 404
    return jsonify(dict(fila))


@app.route("/alumnos/buscar")
def buscar_alumnos():
    """!
    @brief Busca alumnos cuyo nombre contenga el texto del parámetro «nombre».
    @return JSON con los alumnos encontrados.
    """
    nombre = request.args.get("nombre", "")
    # VULN-01: consulta parametrizada. El valor viaja como DATO (?), nunca como código SQL.
    consulta = "SELECT * FROM alumnos WHERE nombre LIKE ?"
    try:
        filas = conectar().execute(consulta, (f"%{nombre}%",)).fetchall()
    except sqlite3.Error:
        # No se devuelve la consulta ni el detalle del error (evita fuga de información, CWE-209).
        app.logger.exception("Error al buscar alumnos")
        return jsonify({"error": "No se pudo completar la búsqueda"}), 500
    return jsonify([dict(f) for f in filas])


@app.route("/login", methods=["POST"])
def login():
    """!
    @brief Valida las credenciales del administrador enviadas por formulario.
    @return JSON con el resultado; 401 si las credenciales no son válidas.
    """
    usuario = request.form.get("usuario", "")
    clave = request.form.get("clave", "")
    # VULN-03: verificación con hash fuerte (PBKDF2 + sal), no con MD5.
    if usuario == ADMIN_USUARIO and check_password_hash(ADMIN_CLAVE_HASH, clave):
        LOGIN_EXITOSOS.inc()
        return jsonify({"mensaje": "Bienvenido, administrador"})
    LOGIN_FALLIDOS.inc()
    app.logger.warning("Login fallido para el usuario '%s' desde %s", usuario, request.remote_addr)
    return jsonify({"error": "Credenciales inválidas"}), 401


@app.route("/metrics")
def metrics():
    """!
    @brief Métricas en formato Prometheus.
    @return Texto con las métricas.
    """
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


iniciar_db()

if __name__ == "__main__":
    # VULN-04: el modo debug queda APAGADO salvo que se pida explícitamente por entorno.
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    # Escuchar en 0.0.0.0 es intencional: la app corre DENTRO del contenedor y Docker
    # la publica solo en 127.0.0.1 del equipo (ver compose.yaml). Por eso se marca nosec.
    app.run(host="0.0.0.0", port=5000, debug=debug)  # nosec B104
