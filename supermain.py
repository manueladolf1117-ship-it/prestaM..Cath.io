import hashlib
import hmac
import os
import time

import flet as ft
import mysql.connector

# ---------------------------------------------------------------
# CONFIGURACIÓN
# ---------------------------------------------------------------
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", "12345678"),
    "database": os.getenv("DB_NAME", "prestamos_db"),
}

# Admin creado automáticamente la primera vez (CÁMBIALE la clave)
ADMIN_USUARIO = os.getenv("ADMIN_USER", "admin")
ADMIN_CLAVE = os.getenv("ADMIN_PASSWORD", "Admin123!")

# Modo producción (PRODUCCION=1): exige claves seguras y corre como servidor web
PRODUCCION = os.getenv("PRODUCCION") == "1"
if PRODUCCION:
    if ADMIN_CLAVE == "Admin123!" or len(ADMIN_CLAVE) < 10:
        raise SystemExit("PRODUCCION: define ADMIN_PASSWORD (mínimo 10 caracteres).")
    if not DB_CONFIG["password"]:
        raise SystemExit("PRODUCCION: define DB_PASSWORD.")

# Límite de intentos de login (protege contra adivinar contraseñas)
MAX_INTENTOS, VENTANA_SEG = 5, 600
INTENTOS = {}


def login_bloqueado(clave_usuario):
    n, t0 = INTENTOS.get(clave_usuario, (0, 0))
    if time.time() - t0 > VENTANA_SEG:
        INTENTOS.pop(clave_usuario, None)
        return False
    return n >= MAX_INTENTOS


def registrar_fallo(clave_usuario):
    n, t0 = INTENTOS.get(clave_usuario, (0, time.time()))
    if time.time() - t0 > VENTANA_SEG:
        n, t0 = 0, time.time()
    INTENTOS[clave_usuario] = (n + 1, t0)


# Frecuencias de pago: cuántos pagos hay en un año
FRECUENCIAS = {"Semanal": 52, "Quincenal": 24, "Mensual": 12}

# Colores
C_PRIMARIO = ft.Colors.INDIGO_700
C_FONDO = ft.Colors.GREY_100
COLOR_ESTADO = {
    "Pendiente": ft.Colors.ORANGE_700,
    "Aprobada": ft.Colors.GREEN_700,
    "Rechazada": ft.Colors.RED_700,
}


# ---------------------------------------------------------------
# BASE DE DATOS
# ---------------------------------------------------------------
def conectar():
    return mysql.connector.connect(**DB_CONFIG)


def consulta(sql, params=(), uno=False, escribir=False):
    con = conectar()
    try:
        cur = con.cursor(dictionary=True)
        cur.execute(sql, params)
        if escribir:
            con.commit()
            return cur.lastrowid
        return cur.fetchone() if uno else cur.fetchall()
    finally:
        con.close()


def hash_clave(clave):
    sal = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", clave.encode(), sal, 200_000)
    return sal.hex() + "$" + h.hex()


def verificar_clave(clave, guardado):
    sal_hex, h_hex = guardado.split("$")
    h = hashlib.pbkdf2_hmac("sha256", clave.encode(), bytes.fromhex(sal_hex), 200_000)
    return hmac.compare_digest(h.hex(), h_hex)


def init_db():
    consulta(
        """CREATE TABLE IF NOT EXISTS usuarios (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nombre VARCHAR(120) NOT NULL,
            cedula VARCHAR(20) NOT NULL UNIQUE,
            usuario VARCHAR(40) NOT NULL UNIQUE,
            clave_hash VARCHAR(200) NOT NULL,
            rol ENUM('cliente','admin') NOT NULL DEFAULT 'cliente',
            creado DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""", escribir=True)
    consulta(
        """CREATE TABLE IF NOT EXISTS solicitudes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            usuario_id INT NOT NULL,
            monto DECIMAL(12,2) NOT NULL,
            tasa DECIMAL(5,2) NOT NULL,
            frecuencia VARCHAR(15) NOT NULL,
            num_cuotas INT NOT NULL,
            cuota DECIMAL(12,2) NOT NULL,
            total DECIMAL(14,2) NOT NULL,
            estado ENUM('Pendiente','Aprobada','Rechazada') NOT NULL DEFAULT 'Pendiente',
            comentario VARCHAR(255) NULL,
            fecha DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            fecha_respuesta DATETIME NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
        )""", escribir=True)
    consulta(
        """CREATE TABLE IF NOT EXISTS pagos (
            id INT AUTO_INCREMENT PRIMARY KEY,
            solicitud_id INT NOT NULL,
            monto DECIMAL(12,2) NOT NULL,
            nota VARCHAR(255) NULL,
            registrado_por INT NOT NULL,
            fecha DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (solicitud_id) REFERENCES solicitudes(id),
            FOREIGN KEY (registrado_por) REFERENCES usuarios(id)
        )""", escribir=True)
    if not consulta("SELECT id FROM usuarios WHERE rol='admin' LIMIT 1", uno=True):
        consulta(
            "INSERT INTO usuarios (nombre, cedula, usuario, clave_hash, rol) "
            "VALUES (%s, %s, %s, %s, 'admin')",
            ("Administrador", "00000000000", ADMIN_USUARIO, hash_clave(ADMIN_CLAVE)),
            escribir=True)


# Solicitudes con el total pagado hasta ahora
SELECT_SOL = (
    "SELECT s.*, u.nombre, u.cedula, "
    "COALESCE((SELECT SUM(p.monto) FROM pagos p WHERE p.solicitud_id=s.id),0) AS pagado "
    "FROM solicitudes s JOIN usuarios u ON u.id=s.usuario_id "
)


def pagos_por_solicitud(ids):
    if not ids:
        return {}
    marcas = ",".join(["%s"] * len(ids))
    filas = consulta(
        f"SELECT * FROM pagos WHERE solicitud_id IN ({marcas}) ORDER BY id DESC", tuple(ids))
    resultado = {}
    for p in filas:
        resultado.setdefault(p["solicitud_id"], []).append(p)
    return resultado


def registrar_pago(solicitud_id, monto, nota, admin_id):
    """Devuelve None si todo salió bien, o un texto con el error."""
    con = conectar()
    try:
        cur = con.cursor(dictionary=True)
        cur.execute(
            "SELECT s.total, s.estado, "
            "COALESCE((SELECT SUM(p.monto) FROM pagos p WHERE p.solicitud_id=s.id),0) AS pagado "
            "FROM solicitudes s WHERE s.id=%s FOR UPDATE", (solicitud_id,))
        fila = cur.fetchone()
        if not fila or fila["estado"] != "Aprobada":
            return "Esta solicitud no está aprobada"
        saldo = float(fila["total"]) - float(fila["pagado"])
        if monto > saldo + 0.005:
            return f"El pago excede el saldo pendiente ({money(saldo)})"
        cur.execute(
            "INSERT INTO pagos (solicitud_id, monto, nota, registrado_por) "
            "VALUES (%s, %s, %s, %s)", (solicitud_id, monto, nota, admin_id))
        con.commit()
        return None
    finally:
        con.close()


# ---------------------------------------------------------------
# CÁLCULOS Y FORMATO
# ---------------------------------------------------------------
def calcular_cuota(monto, tasa_anual, n, periodos=12):
    i = tasa_anual / 100 / periodos
    if i == 0:
        return monto / n
    return monto * i / (1 - (1 + i) ** -n)


def tabla_amortizacion(monto, tasa_anual, n, periodos=12):
    i = tasa_anual / 100 / periodos
    cuota = calcular_cuota(monto, tasa_anual, n, periodos)
    saldo, filas = monto, []
    for k in range(1, n + 1):
        interes = saldo * i
        capital = cuota - interes
        saldo = max(saldo - capital, 0)
        filas.append((k, cuota, interes, capital, saldo))
    return filas


def money(v):
    return f"RD$ {float(v):,.2f}"


def money0(v):
    return f"RD$ {float(v):,.0f}"


def fmt(d):
    return d.strftime("%d/%m/%Y %H:%M") if d else ""


def opcion(texto):
    cls = getattr(ft, "DropdownOption", None) or ft.dropdown.Option
    return cls(key=texto, text=texto)


# ---------------------------------------------------------------
# INTERFAZ
# ---------------------------------------------------------------
def main(page: ft.Page):
    page.title = "Préstamos Bancarios"
    page.theme_mode = ft.ThemeMode.LIGHT
    page.theme = ft.Theme(color_scheme_seed=ft.Colors.INDIGO)
    page.bgcolor = C_FONDO
    page.padding = 16
    page.scroll = ft.ScrollMode.AUTO

    try:
        init_db()
    except mysql.connector.Error as err:
        page.add(ft.Text(f"No se pudo conectar a MySQL:\n{err}", color=ft.Colors.RED))
        return

    sesion = {"usuario": None}

    # ---------- utilidades de diseño ----------
    def aviso(texto):
        snack = ft.SnackBar(ft.Text(texto))
        if hasattr(page, "show_dialog"):  # Flet 1.0+
            page.show_dialog(snack)
        else:
            page.snack_bar = snack
            snack.open = True
            page.update()

    def mostrar(*controles):
        page.clean()
        page.add(ft.SafeArea(content=ft.Column(list(controles), spacing=14)))
        page.update()

    def tarjeta(*controles):
        return ft.Container(
            content=ft.Column(list(controles), spacing=8),
            padding=16, border_radius=16, bgcolor=ft.Colors.WHITE,
            shadow=ft.BoxShadow(blur_radius=10, color=ft.Colors.GREY_400,
                                offset=ft.Offset(0, 3)))

    def insignia(texto, color):
        return ft.Container(
            content=ft.Text(texto, color=ft.Colors.WHITE, size=12,
                            weight=ft.FontWeight.BOLD),
            bgcolor=color, padding=6, border_radius=12)

    def titulo(texto, icono=None):
        fila = []
        if icono:
            fila.append(ft.Icon(icono, color=C_PRIMARIO, size=26))
        fila.append(ft.Text(texto, size=22, weight=ft.FontWeight.BOLD, color=C_PRIMARIO))
        return ft.Row(fila, spacing=8)

    def stat(icono, etiqueta, valor, color):
        return ft.Container(
            content=ft.Column([
                ft.Icon(icono, color=color, size=22),
                ft.Text(valor, size=14, weight=ft.FontWeight.BOLD),
                ft.Text(etiqueta, size=11, color=ft.Colors.GREY_700),
            ], spacing=2),
            bgcolor=ft.Colors.WHITE, border_radius=14, padding=12, expand=True,
            shadow=ft.BoxShadow(blur_radius=8, color=ft.Colors.GREY_300,
                                offset=ft.Offset(0, 2)))

    def cabecera():
        u = sesion["usuario"]
        rol = "Administrador" if u["rol"] == "admin" else "Cliente"
        return ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.ACCOUNT_BALANCE, color=ft.Colors.WHITE, size=34),
                ft.Column([
                    ft.Text("Préstamos Bancarios", size=18, weight=ft.FontWeight.BOLD,
                            color=ft.Colors.WHITE),
                    ft.Text(f"{u['nombre']} · {rol}", size=12, color=ft.Colors.INDIGO_100),
                ], spacing=2, expand=True),
            ], spacing=12),
            bgcolor=C_PRIMARIO, padding=18, border_radius=20)

    def barra(opciones, activo):
        botones = []
        for nombre, icono, f in opciones:
            clase = ft.FilledButton if nombre == activo else ft.OutlinedButton
            botones.append(clase(nombre, icon=icono, on_click=lambda e, f=f: f()))
        botones.append(ft.TextButton("Salir", icon=ft.Icons.LOGOUT, on_click=cerrar_sesion))
        return ft.Row(botones, wrap=True, spacing=8, run_spacing=8)

    def detalle_prestamo(s, lista_pagos, admin=False):
        total = float(s["total"])
        pagado = float(s["pagado"])
        saldo = max(total - pagado, 0)
        aprobado = s["estado"] == "Aprobada"
        saldado = aprobado and saldo <= 0.005
        etiqueta = "Saldado" if saldado else s["estado"]
        color = ft.Colors.TEAL_700 if saldado else COLOR_ESTADO[s["estado"]]

        c = []
        if admin:
            c.append(ft.Text(f"#{s['id']} · {s['nombre']} · céd. {s['cedula']}",
                             size=13, weight=ft.FontWeight.BOLD))
        c.append(ft.Row([
            ft.Text(money(s["monto"]), size=22, weight=ft.FontWeight.BOLD, expand=True),
            insignia(etiqueta, color),
        ]))
        c.append(ft.Text(f"{s['frecuencia']} · {s['num_cuotas']} cuotas de "
                         f"{money(s['cuota'])} · {s['tasa']}% anual", size=12))
        c.append(ft.Text(f"Total a pagar: {money(total)}", size=13))
        c.append(ft.Text(f"Solicitado: {fmt(s['fecha'])}", size=11, color=ft.Colors.GREY_600))
        if aprobado:
            c.append(ft.ProgressBar(value=min(pagado / total, 1) if total else 0,
                                    color=ft.Colors.GREEN_600, bgcolor=ft.Colors.GREY_300,
                                    bar_height=10))
            c.append(ft.Row([
                ft.Text(f"Pagado: {money(pagado)}", size=12, color=ft.Colors.GREEN_800),
                ft.Text(f"Pendiente: {money(saldo)}", size=12, color=ft.Colors.RED_700,
                        weight=ft.FontWeight.BOLD),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN))
        if s["comentario"]:
            c.append(ft.Text(f"Respuesta: {s['comentario']}", size=12, italic=True))
        if lista_pagos:
            c.append(ft.Text("Últimos pagos", size=12, weight=ft.FontWeight.BOLD))
            for p in lista_pagos[:3]:
                nota = f" ({p['nota']})" if p["nota"] else ""
                c.append(ft.Text(f"• {fmt(p['fecha'])} — {money(p['monto'])}{nota}", size=12))
        return c, saldo

    # ---------------- LOGIN / REGISTRO ----------------
    def vista_login():
        usuario = ft.TextField(label="Usuario", border_radius=12, autofocus=True)
        clave = ft.TextField(label="Contraseña", password=True, can_reveal_password=True,
                             border_radius=12)

        def entrar(e):
            clave_usuario = usuario.value.strip().lower()
            if login_bloqueado(clave_usuario):
                aviso("Demasiados intentos fallidos. Espera 10 minutos")
                return
            try:
                u = consulta("SELECT * FROM usuarios WHERE usuario=%s",
                             (usuario.value.strip(),), uno=True)
            except mysql.connector.Error as err:
                aviso(f"Error de base de datos: {err}")
                return
            if not u or not verificar_clave(clave.value, u["clave_hash"]):
                registrar_fallo(clave_usuario)
                aviso("Usuario o contraseña incorrectos")
                return
            INTENTOS.pop(clave_usuario, None)
            sesion["usuario"] = u
            if u["rol"] == "admin":
                vista_pendientes()
            else:
                vista_simulador()

        clave.on_submit = entrar
        mostrar(
            ft.Container(height=10),
            ft.Container(
                content=ft.Column([
                    ft.Icon(ft.Icons.ACCOUNT_BALANCE, size=64, color=ft.Colors.WHITE),
                    ft.Text("Préstamos Bancarios", size=26, weight=ft.FontWeight.BOLD,
                            color=ft.Colors.WHITE),
                    ft.Text("Tu dinero, claro y al día", color=ft.Colors.INDIGO_100),
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=6),
                bgcolor=C_PRIMARIO, border_radius=24, padding=30),
            tarjeta(
                ft.Text("Iniciar sesión", size=18, weight=ft.FontWeight.BOLD),
                usuario, clave,
                ft.FilledButton("Entrar", icon=ft.Icons.LOGIN, on_click=entrar),
                ft.TextButton("Crear cuenta de cliente",
                              on_click=lambda e: vista_registro()),
            ),
        )

    def vista_registro():
        nombre = ft.TextField(label="Nombre completo", border_radius=12)
        cedula = ft.TextField(label="Cédula", keyboard_type=ft.KeyboardType.NUMBER,
                              border_radius=12)
        usuario = ft.TextField(label="Usuario", border_radius=12)
        clave = ft.TextField(label="Contraseña (mín. 6 caracteres)", password=True,
                             can_reveal_password=True, border_radius=12)
        clave2 = ft.TextField(label="Repite la contraseña", password=True, border_radius=12)

        def crear(e):
            if not all([nombre.value.strip(), cedula.value.strip(), usuario.value.strip()]):
                aviso("Completa todos los campos")
                return
            if len(clave.value) < 6:
                aviso("La contraseña debe tener al menos 6 caracteres")
                return
            if clave.value != clave2.value:
                aviso("Las contraseñas no coinciden")
                return
            try:
                consulta(
                    "INSERT INTO usuarios (nombre, cedula, usuario, clave_hash) "
                    "VALUES (%s, %s, %s, %s)",
                    (nombre.value.strip(), cedula.value.strip(),
                     usuario.value.strip(), hash_clave(clave.value)),
                    escribir=True)
            except mysql.connector.IntegrityError:
                aviso("Ese usuario o cédula ya está registrado")
                return
            except mysql.connector.Error as err:
                aviso(f"Error de base de datos: {err}")
                return
            aviso("Cuenta creada. Ya puedes iniciar sesión")
            vista_login()

        mostrar(
            titulo("Crear cuenta", ft.Icons.PERSON_ADD),
            tarjeta(nombre, cedula, usuario, clave, clave2,
                    ft.FilledButton("Registrarme", icon=ft.Icons.CHECK, on_click=crear),
                    ft.TextButton("Volver", on_click=lambda e: vista_login())),
        )

    def cerrar_sesion(e=None):
        sesion["usuario"] = None
        vista_login()

    # ---------------- CLIENTE ----------------
    ultima = {"monto": 0}

    def barra_cliente(activo):
        return barra([("Simulador", ft.Icons.CALCULATE, vista_simulador),
                      ("Solicitar", ft.Icons.SEND, vista_solicitar),
                      ("Mis préstamos", ft.Icons.SAVINGS, vista_mis_prestamos)], activo)

    def vista_simulador():
        monto = ft.TextField(label="Monto del préstamo (RD$)", value="50000",
                             keyboard_type=ft.KeyboardType.NUMBER, border_radius=12)
        tasa = ft.TextField(label="Tasa anual (%)", value="18",
                            keyboard_type=ft.KeyboardType.NUMBER, border_radius=12)
        frec = ft.Dropdown(label="Frecuencia de pago", value="Mensual",
                           options=[opcion(f) for f in FRECUENCIAS])
        meses = ft.Slider(min=1, max=12, divisions=11, value=6, label="{value} mes(es)")
        meses_txt = ft.Text("Plazo: 6 meses", weight=ft.FontWeight.BOLD)
        resultado = ft.Column()
        tabla = ft.Column(scroll=ft.ScrollMode.AUTO, height=300)
        tabla_caja = ft.Container(content=tabla, visible=False, bgcolor=ft.Colors.WHITE,
                                  border_radius=16, padding=12)

        def cambiar_plazo(e):
            p = int(meses.value)
            meses_txt.value = f"Plazo: {p} mes" if p == 1 else f"Plazo: {p} meses"
            page.update()

        meses.on_change = cambiar_plazo

        def simular(e):
            try:
                m = float(monto.value)
                t = float(tasa.value)
                plazo = int(meses.value)
                if m <= 0 or t < 0:
                    raise ValueError
            except ValueError:
                aviso("Revisa el monto y la tasa")
                return
            if frec.value not in FRECUENCIAS:
                aviso("Elige la frecuencia de pago")
                return

            periodos = FRECUENCIAS[frec.value]
            n = max(1, round(plazo * periodos / 12))
            cuota = calcular_cuota(m, t, n, periodos)
            total = cuota * n
            ultima.update(monto=m, tasa=t, frecuencia=frec.value, n=n,
                          plazo=plazo, cuota=cuota, total=total)

            resultado.controls = [ft.Container(
                content=ft.Column([
                    ft.Text(f"Cuota {frec.value.lower()}", size=13,
                            color=ft.Colors.INDIGO_100),
                    ft.Text(money(cuota), size=32, weight=ft.FontWeight.BOLD,
                            color=ft.Colors.WHITE),
                    ft.Text(f"{n} cuotas en {plazo} " + ("mes" if plazo == 1 else "meses"),
                            color=ft.Colors.WHITE),
                    ft.Text(f"Total a pagar: {money(total)}", color=ft.Colors.WHITE),
                    ft.Text(f"Intereses: {money(total - m)}", color=ft.Colors.WHITE),
                ], spacing=4),
                bgcolor=ft.Colors.INDIGO_600, border_radius=18, padding=18)]
            filas = [
                ft.Text(f"{k:>3} | Cuota {c:>10,.2f} | Int. {i:>9,.2f} | "
                        f"Cap. {cap:>10,.2f} | Saldo {sd:>11,.2f}",
                        size=11, font_family="monospace")
                for k, c, i, cap, sd in tabla_amortizacion(m, t, n, periodos)
            ]
            tabla.controls = [ft.Text("Tabla de amortización",
                                      weight=ft.FontWeight.BOLD)] + filas
            tabla_caja.visible = True
            page.update()

        mostrar(
            cabecera(), barra_cliente("Simulador"),
            titulo("Simula tu préstamo", ft.Icons.CALCULATE),
            tarjeta(monto, tasa, frec, meses_txt, meses,
                    ft.FilledButton("Calcular", icon=ft.Icons.CALCULATE, on_click=simular)),
            resultado, tabla_caja,
        )

    def vista_solicitar():
        u = sesion["usuario"]
        nombre = ft.TextField(label="Nombre completo", value=u["nombre"], read_only=True,
                              border_radius=12)
        cedula = ft.TextField(label="Cédula", value=u["cedula"], read_only=True,
                              border_radius=12)

        def solicitar(e):
            if ultima["monto"] <= 0:
                aviso("Primero simula un préstamo")
                return
            try:
                consulta(
                    "INSERT INTO solicitudes (usuario_id, monto, tasa, frecuencia, "
                    "num_cuotas, cuota, total) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (u["id"], round(ultima["monto"], 2), ultima["tasa"],
                     ultima["frecuencia"], ultima["n"], round(ultima["cuota"], 2),
                     round(ultima["total"], 2)),
                    escribir=True)
            except mysql.connector.Error as err:
                aviso(f"Error de base de datos: {err}")
                return
            aviso("Solicitud enviada. El administrador la revisará")
            vista_mis_prestamos()

        resumen = (f"Última simulación: {money(ultima['monto'])} · {ultima['frecuencia']} · "
                   f"{ultima['n']} cuotas de {money(ultima['cuota'])}"
                   if ultima["monto"] > 0 else "Aún no has simulado un préstamo.")
        mostrar(
            cabecera(), barra_cliente("Solicitar"),
            titulo("Solicitar préstamo", ft.Icons.SEND),
            tarjeta(ft.Text(resumen, weight=ft.FontWeight.BOLD), nombre, cedula,
                    ft.FilledButton("Enviar solicitud", icon=ft.Icons.SEND,
                                    on_click=solicitar)),
        )

    def vista_mis_prestamos():
        try:
            filas = consulta(SELECT_SOL + "WHERE s.usuario_id=%s ORDER BY s.id DESC",
                             (sesion["usuario"]["id"],))
            pagos = pagos_por_solicitud([s["id"] for s in filas])
        except mysql.connector.Error as err:
            aviso(f"Error de base de datos: {err}")
            return

        deuda = sum(max(float(s["total"]) - float(s["pagado"]), 0)
                    for s in filas if s["estado"] == "Aprobada")
        pagado = sum(float(s["pagado"]) for s in filas if s["estado"] == "Aprobada")
        activos = sum(1 for s in filas if s["estado"] == "Aprobada"
                      and float(s["total"]) - float(s["pagado"]) > 0.005)

        tarjetas = []
        for s in filas:
            c, _ = detalle_prestamo(s, pagos.get(s["id"], []))
            tarjetas.append(tarjeta(*c))
        if not tarjetas:
            tarjetas = [tarjeta(ft.Text("Aún no tienes solicitudes."))]

        mostrar(
            cabecera(), barra_cliente("Mis préstamos"),
            titulo("Mis préstamos", ft.Icons.SAVINGS),
            ft.Row([
                stat(ft.Icons.MONEY_OFF, "Deuda pendiente", money0(deuda), ft.Colors.RED_700),
                stat(ft.Icons.PAYMENTS, "Total pagado", money0(pagado), ft.Colors.GREEN_700),
                stat(ft.Icons.RECEIPT_LONG, "Préstamos activos", str(activos),
                     ft.Colors.INDIGO_700),
            ], spacing=10),
            *tarjetas,
        )

    # ---------------- ADMIN ----------------
    def barra_admin(activo):
        return barra([("Pendientes", ft.Icons.PENDING_ACTIONS, vista_pendientes),
                      ("Cobros", ft.Icons.ADD_CARD, vista_cobros),
                      ("Pagos", ft.Icons.HISTORY, vista_pagos),
                      ("Todas", ft.Icons.LIST_ALT, vista_todas)], activo)

    def responder(sid, estado, campo, volver):
        try:
            consulta(
                "UPDATE solicitudes SET estado=%s, comentario=%s, "
                "fecha_respuesta=NOW() WHERE id=%s AND estado='Pendiente'",
                (estado, campo.value.strip() or None, sid), escribir=True)
        except mysql.connector.Error as err:
            aviso(f"Error de base de datos: {err}")
            return
        aviso(f"Solicitud #{sid} {estado.lower()}")
        volver()

    def vista_pendientes():
        try:
            filas = consulta(SELECT_SOL + "WHERE s.estado='Pendiente' ORDER BY s.id")
        except mysql.connector.Error as err:
            aviso(f"Error de base de datos: {err}")
            return
        tarjetas = []
        for s in filas:
            c, _ = detalle_prestamo(s, [], admin=True)
            campo = ft.TextField(label="Comentario para el cliente (opcional)",
                                 border_radius=12)
            c += [campo, ft.Row([
                ft.FilledButton("Aprobar", icon=ft.Icons.CHECK,
                                on_click=lambda e, i=s["id"], k=campo:
                                responder(i, "Aprobada", k, vista_pendientes)),
                ft.OutlinedButton("Rechazar", icon=ft.Icons.CLOSE,
                                  on_click=lambda e, i=s["id"], k=campo:
                                  responder(i, "Rechazada", k, vista_pendientes)),
            ], spacing=8)]
            tarjetas.append(tarjeta(*c))
        if not tarjetas:
            tarjetas = [tarjeta(ft.Text("No hay solicitudes pendientes. ¡Todo al día!"))]
        mostrar(cabecera(), barra_admin("Pendientes"),
                titulo(f"Solicitudes pendientes ({len(filas)})", ft.Icons.PENDING_ACTIONS),
                *tarjetas)

    def vista_cobros():
        try:
            filas = consulta(SELECT_SOL + "WHERE s.estado='Aprobada' ORDER BY s.id")
            pagos = pagos_por_solicitud([s["id"] for s in filas])
            cobrado = float(consulta("SELECT COALESCE(SUM(monto),0) AS t FROM pagos",
                                     uno=True)["t"])
        except mysql.connector.Error as err:
            aviso(f"Error de base de datos: {err}")
            return

        prestado = sum(float(s["total"]) for s in filas)
        por_cobrar = max(prestado - cobrado, 0)

        def pagar(sid, campo_monto, campo_nota):
            try:
                m = float((campo_monto.value or "").replace(",", ""))
            except ValueError:
                aviso("Escribe un monto válido")
                return
            if m <= 0:
                aviso("El monto debe ser mayor que cero")
                return
            try:
                error = registrar_pago(sid, round(m, 2),
                                       (campo_nota.value or "").strip() or None,
                                       sesion["usuario"]["id"])
            except mysql.connector.Error as err:
                aviso(f"Error de base de datos: {err}")
                return
            if error:
                aviso(error)
                return
            aviso(f"Pago de {money(m)} registrado")
            vista_cobros()

        tarjetas = []
        for s in filas:
            c, saldo = detalle_prestamo(s, pagos.get(s["id"], []), admin=True)
            if saldo <= 0.005:
                continue  # ya saldado, no se muestra en cobros
            campo_monto = ft.TextField(
                label="Monto recibido en efectivo (RD$)",
                value=f"{min(float(s['cuota']), saldo):.2f}",
                keyboard_type=ft.KeyboardType.NUMBER, border_radius=12)
            campo_nota = ft.TextField(label="Nota (opcional)", border_radius=12)
            c += [ft.Divider(), campo_monto, campo_nota,
                  ft.FilledButton("Registrar pago", icon=ft.Icons.ADD_CARD,
                                  on_click=lambda e, i=s["id"], a=campo_monto, b=campo_nota:
                                  pagar(i, a, b))]
            tarjetas.append(tarjeta(*c))
        if not tarjetas:
            tarjetas = [tarjeta(ft.Text("No hay préstamos con saldo pendiente."))]

        mostrar(
            cabecera(), barra_admin("Cobros"),
            titulo("Registrar cobros", ft.Icons.ADD_CARD),
            ft.Row([
                stat(ft.Icons.ACCOUNT_BALANCE_WALLET, "Total aprobado", money0(prestado),
                     ft.Colors.INDIGO_700),
                stat(ft.Icons.PAYMENTS, "Cobrado", money0(cobrado), ft.Colors.GREEN_700),
                stat(ft.Icons.TRENDING_UP, "Por cobrar", money0(por_cobrar),
                     ft.Colors.RED_700),
            ], spacing=10),
            *tarjetas,
        )

    def vista_pagos():
        try:
            filas = consulta(
                "SELECT p.*, u.nombre FROM pagos p "
                "JOIN solicitudes s ON s.id=p.solicitud_id "
                "JOIN usuarios u ON u.id=s.usuario_id ORDER BY p.id DESC LIMIT 100")
        except mysql.connector.Error as err:
            aviso(f"Error de base de datos: {err}")
            return
        tarjetas = []
        for p in filas:
            nota = f" · {p['nota']}" if p["nota"] else ""
            tarjetas.append(tarjeta(
                ft.Row([
                    ft.Icon(ft.Icons.PAYMENTS, color=ft.Colors.GREEN_700),
                    ft.Column([
                        ft.Text(p["nombre"], weight=ft.FontWeight.BOLD),
                        ft.Text(f"Préstamo #{p['solicitud_id']} · {fmt(p['fecha'])}{nota}",
                                size=11, color=ft.Colors.GREY_700),
                    ], spacing=2, expand=True),
                    ft.Text(money(p["monto"]), weight=ft.FontWeight.BOLD,
                            color=ft.Colors.GREEN_800),
                ], spacing=10)))
        if not tarjetas:
            tarjetas = [tarjeta(ft.Text("Aún no hay pagos registrados."))]
        mostrar(cabecera(), barra_admin("Pagos"),
                titulo("Historial de pagos", ft.Icons.HISTORY), *tarjetas)

    def vista_todas():
        try:
            filas = consulta(SELECT_SOL + "ORDER BY s.id DESC")
            pagos = pagos_por_solicitud([s["id"] for s in filas])
        except mysql.connector.Error as err:
            aviso(f"Error de base de datos: {err}")
            return
        tarjetas = []
        for s in filas:
            c, _ = detalle_prestamo(s, pagos.get(s["id"], []), admin=True)
            tarjetas.append(tarjeta(*c))
        if not tarjetas:
            tarjetas = [tarjeta(ft.Text("No hay solicitudes para mostrar."))]
        mostrar(cabecera(), barra_admin("Todas"),
                titulo("Todas las solicitudes", ft.Icons.LIST_ALT), *tarjetas)

    vista_login()


ejecutar = ft.run if hasattr(ft, "run") else ft.app   # Flet 1.0+ / anterior

if PRODUCCION:
    # Servidor web: se publica detrás de Nginx con HTTPS
    ejecutar(main, view=ft.AppView.WEB_BROWSER,
             host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8000")))
else:
    ejecutar(main)
