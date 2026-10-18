import os
from datetime import date, datetime, timedelta
from typing import Optional

import psycopg
from psycopg import errors
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

app = FastAPI(title="Mueblería A&G API")

DATABASE_URL = os.getenv("DATABASE_URL")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")

if not DATABASE_URL:
    raise RuntimeError("Falta configurar DATABASE_URL en las variables de entorno.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# MODELOS
# ============================================================

class DatosLogin(BaseModel):
    cliente_id: str
    contrasena: str


class DatosAdminLogin(BaseModel):
    usuario: str
    contrasena: str


class NuevoCliente(BaseModel):
    id: str
    nombre: str
    contrasena: str

    @field_validator("id", "nombre", "contrasena")
    @classmethod
    def limpiar_texto(cls, value: str) -> str:
        return value.strip()


class NuevaVenta(BaseModel):
    cliente_id: int
    detalle_mueble: str = Field(min_length=1)
    monto_total: int = Field(gt=0)
    cantidad_cuotas: int = Field(gt=0, le=120)
    primer_vencimiento: str

    @field_validator("detalle_mueble")
    @classmethod
    def limpiar_detalle(cls, value: str) -> str:
        return value.strip()


class PagoCuota(BaseModel):
    cliente_id: int
    numero: str
    detalle_mueble: str
    vencimiento: str
    fecha_pago: Optional[str] = None


class AbonoCuota(BaseModel):
    cliente_id: int
    numero: str
    detalle_mueble: str
    vencimiento: str
    monto_abono: float = Field(gt=0)
    fecha_pago: Optional[str] = None
    aplicar_recargo: bool = False
    dias_gracia: int = Field(default=0, ge=0, le=90)


class EditarVencimiento(BaseModel):
    cliente_id: int
    numero: str
    detalle_mueble: str
    vencimiento_actual: str
    nuevo_vencimiento: str


# ============================================================
# CONEXIÓN A SUPABASE / POSTGRESQL
# ============================================================

def get_connection():
    """
    Usa Psycopg 3 en lugar de psycopg2.
    Esto evita el problema que tuvimos con:
    "server didn't return client encoding".
    """
    return psycopg.connect(
        DATABASE_URL,
        options="-c client_encoding=UTF8",
    )


# ============================================================
# UTILIDADES
# ============================================================

MESES = [
    "ENERO",
    "FEBRERO",
    "MARZO",
    "ABRIL",
    "MAYO",
    "JUNIO",
    "JULIO",
    "AGOSTO",
    "SEPTIEMBRE",
    "OCTUBRE",
    "NOVIEMBRE",
    "DICIEMBRE",
]


def formatear_fecha(valor: object):
    if valor is None:
        return None
    if hasattr(valor, "isoformat"):
        return valor.isoformat()
    return str(valor)


def parsear_fecha(valor: str) -> date:
    valor = valor.strip()

    formatos = (
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%d-%m-%Y",
    )

    for formato in formatos:
        try:
            return datetime.strptime(valor, formato).date()
        except ValueError:
            pass

    raise HTTPException(
        status_code=400,
        detail=(
            "La fecha no es válida. Usá formato YYYY-MM-DD "
            "(por ejemplo 2026-10-10)."
        ),
    )


def comprobar_admin_token(authorization: str | None):
    if not ADMIN_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="Falta configurar ADMIN_TOKEN en el servidor.",
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No autorizado")

    token = authorization[7:].strip()

    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="No autorizado")


def contraseña_numerica(valor: str) -> int:
    """
    La columna clientes.contrasena es int8.
    Por eso las contraseñas actuales deben ser numéricas.
    """
    valor = valor.strip()

    if not valor.isdigit():
        raise HTTPException(
            status_code=400,
            detail=(
                "La contraseña debe ser numérica porque la columna "
                "clientes.contrasena es int8."
            ),
        )

    numero = int(valor)

    if numero < 0 or numero > 9223372036854775807:
        raise HTTPException(status_code=400, detail="Contraseña fuera de rango.")

    return numero


# ============================================================
# LOGIN DE CLIENTES
# ============================================================

@app.post("/login")
def login(datos: DatosLogin):
    conn = None

    try:
        cliente_id = int(datos.cliente_id.strip())
        contrasena = contraseña_numerica(datos.contrasena)

        conn = get_connection()

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, nombre
                FROM clientes
                WHERE id = %s AND contrasena = %s
                """,
                (cliente_id, contrasena),
            )

            cliente = cur.fetchone()

            if not cliente:
                raise HTTPException(
                    status_code=401,
                    detail="Cliente o contraseña incorrectos",
                )

            cliente_id_db, nombre = cliente

            cur.execute(
                """
                SELECT detalle_mueble, numero, vencimiento, monto, estado, fecha_pago
                FROM cuotas
                WHERE cliente_id = %s
                ORDER BY
                    detalle_mueble,
                    numero
                """,
                (cliente_id_db,),
            )

            cuotas = cur.fetchall()

        lista_cuotas = []

        for detalle_mueble, numero, vencimiento, monto, estado, fecha_pago in cuotas:
            lista_cuotas.append(
                {
                    "detalle_mueble": detalle_mueble,
                    "numero": numero,
                    "vencimiento": formatear_fecha(vencimiento),
                    "monto": int(monto) if monto is not None else 0,
                    "estado": estado,
                    "fecha_pago": formatear_fecha(fecha_pago),
                }
            )

        return {
            "acceso": True,
            "nombre": nombre,
            "cuotas": lista_cuotas,
        }

    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="El ID del cliente debe ser numérico.",
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Error interno del servidor.",
        )
    finally:
        if conn:
            conn.close()


# ============================================================
# LOGIN ADMINISTRADOR / COBRADOR
# ============================================================

@app.post("/admin/login")
def admin_login(datos: DatosAdminLogin):
    if not ADMIN_PASSWORD:
        raise HTTPException(
            status_code=500,
            detail="Falta configurar ADMIN_PASSWORD en el servidor.",
        )

    if datos.usuario != ADMIN_USER or datos.contrasena != ADMIN_PASSWORD:
        raise HTTPException(
            status_code=401,
            detail="Usuario o contraseña de administrador incorrectos",
        )

    if not ADMIN_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="Falta configurar ADMIN_TOKEN en el servidor.",
        )

    return {
        "acceso": True,
        "access_token": ADMIN_TOKEN,
    }


# ============================================================
# ADMIN - CLIENTES
# ============================================================

@app.get("/admin/clientes")
def listar_clientes(authorization: str | None = Header(default=None)):
    comprobar_admin_token(authorization)

    conn = None

    try:
        conn = get_connection()

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, nombre, contrasena
                FROM clientes
                ORDER BY id
                """
            )

            filas = cur.fetchall()

        return [
            {
                "id": str(row[0]),
                "nombre": row[1],
                "contrasena": str(row[2]) if row[2] is not None else "",
            }
            for row in filas
        ]

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="No se pudieron obtener los clientes.",
        )
    finally:
        if conn:
            conn.close()


@app.post("/admin/clientes")
def agregar_cliente(
    cliente: NuevoCliente,
    authorization: str | None = Header(default=None),
):
    comprobar_admin_token(authorization)

    if not cliente.id:
        raise HTTPException(status_code=400, detail="El ID es obligatorio.")

    if not cliente.nombre:
        raise HTTPException(status_code=400, detail="El nombre es obligatorio.")

    if not cliente.contrasena:
        raise HTTPException(
            status_code=400,
            detail="La contraseña es obligatoria.",
        )

    try:
        cliente_id = int(cliente.id)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="El ID del cliente debe ser numérico.",
        )

    contrasena = contraseña_numerica(cliente.contrasena)

    conn = None

    try:
        conn = get_connection()

        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO clientes (id, nombre, contrasena)
                VALUES (%s, %s, %s)
                """,
                (cliente_id, cliente.nombre, contrasena),
            )

        conn.commit()

        return {
            "ok": True,
            "mensaje": "Cliente agregado correctamente",
            "cliente": {
                "id": str(cliente_id),
                "nombre": cliente.nombre,
            },
        }

    except errors.UniqueViolation:
        if conn:
            conn.rollback()

        raise HTTPException(
            status_code=409,
            detail="Ya existe un cliente con ese ID.",
        )

    except Exception as exc:
        if conn:
            conn.rollback()

        # Devolvemos el error de PostgreSQL para poder diagnosticarlo
        # desde el panel de administración.
        raise HTTPException(
            status_code=500,
            detail=f"No se pudo agregar el cliente: {str(exc)}",
        )

    finally:
        if conn:
            conn.close()


@app.delete("/admin/clientes/{cliente_id}")
def eliminar_cliente(
    cliente_id: str,
    authorization: str | None = Header(default=None),
):
    comprobar_admin_token(authorization)

    try:
        cliente_id_int = int(cliente_id)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="El ID del cliente debe ser numérico.",
        )

    conn = None

    try:
        conn = get_connection()

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM cuotas
                WHERE cliente_id = %s
                """,
                (cliente_id_int,),
            )

            cantidad_cuotas = cur.fetchone()[0]

            if cantidad_cuotas > 0:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "No se puede eliminar este cliente porque tiene "
                        f"{cantidad_cuotas} cuota(s) asociada(s)."
                    ),
                )

            cur.execute(
                """
                DELETE FROM clientes
                WHERE id = %s
                RETURNING id
                """,
                (cliente_id_int,),
            )

            eliminado = cur.fetchone()

            if not eliminado:
                raise HTTPException(
                    status_code=404,
                    detail="Cliente no encontrado.",
                )

        conn.commit()

        return {
            "ok": True,
            "mensaje": "Cliente eliminado correctamente",
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise

    except Exception as exc:
        if conn:
            conn.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"No se pudo eliminar el cliente: {str(exc)}",
        )

    finally:
        if conn:
            conn.close()


def fecha_fin_gracia_habil(vencimiento: date, dias_gracia: int) -> date:
    """Devuelve el último día de gracia, contando solo lunes a viernes posteriores al vencimiento."""
    actual = vencimiento
    contados = 0
    while contados < dias_gracia:
        actual += timedelta(days=1)
        if actual.weekday() < 5:
            contados += 1
    return actual


def asegurar_tabla_pagos(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pagos_cuotas (
            id BIGSERIAL PRIMARY KEY,
            cliente_id BIGINT NOT NULL,
            numero TEXT NOT NULL,
            detalle_mueble TEXT NOT NULL,
            vencimiento TEXT NOT NULL,
            monto_aplicado NUMERIC(14,2) NOT NULL,
            recargo_monto NUMERIC(14,2) NOT NULL DEFAULT 0,
            fecha_pago TEXT NOT NULL,
            aplicar_recargo BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)


# ============================================================
# ADMIN - CUOTAS DE UN CLIENTE
# ============================================================

@app.get("/admin/clientes/{cliente_id}/cuotas")
def listar_cuotas_cliente(
    cliente_id: int,
    authorization: str | None = Header(default=None),
):
    comprobar_admin_token(authorization)
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            asegurar_tabla_pagos(cur)
            cur.execute("ALTER TABLE cuotas ADD COLUMN IF NOT EXISTS dias_gracia INTEGER NOT NULL DEFAULT 0")
            cur.execute("""
                SELECT q.cliente_id, q.nombre, q.detalle_mueble, q.mes, q.numero,
                       q.vencimiento, q.monto, q.estado, q.fecha_pago, COALESCE(q.dias_gracia,0),
                       COALESCE(p.total_abonado,0), COALESCE(p.total_recargo,0), COALESCE(p.cantidad_pagos,0), p.ultimo_pago
                FROM cuotas q
                LEFT JOIN (
                    SELECT cliente_id, numero, detalle_mueble, vencimiento,
                           SUM(monto_aplicado) AS total_abonado,
                           SUM(recargo_monto) AS total_recargo,
                           COUNT(*) AS cantidad_pagos,
                           MAX(fecha_pago) AS ultimo_pago
                    FROM pagos_cuotas
                    GROUP BY cliente_id, numero, detalle_mueble, vencimiento
                ) p ON p.cliente_id=q.cliente_id AND p.numero=q.numero
                    AND p.detalle_mueble=q.detalle_mueble AND p.vencimiento=q.vencimiento::text
                WHERE q.cliente_id = %s
                ORDER BY q.detalle_mueble, q.numero
            """, (cliente_id,))
            filas = cur.fetchall()
        conn.commit()  # Persiste la creación inicial de pagos_cuotas y dias_gracia.
        return [{
            "cliente_id": row[0], "nombre": row[1], "detalle_mueble": row[2], "mes": row[3],
            "numero": row[4], "vencimiento": formatear_fecha(row[5]), "monto": float(row[6] or 0),
            "estado": row[7], "fecha_pago": formatear_fecha(row[8]), "dias_gracia": int(row[9] or 0),
            "monto_abonado": (float(row[10] or 0) if float(row[10] or 0) > 0 else (float(row[6] or 0) if str(row[7] or "").strip().lower() == "pagado" else 0)),
            "recargo_abonado": float(row[11] or 0), "cantidad_pagos": int(row[12] or 0),
            "ultimo_abono": formatear_fecha(row[13]),
            "saldo_pendiente": 0 if str(row[7] or "").strip().lower() == "pagado" else max(0, float(row[6] or 0)-float(row[10] or 0))
        } for row in filas]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"No se pudieron obtener las cuotas: {str(exc)}")
    finally:
        if conn:
            conn.close()


# ============================================================
# ADMIN - NUEVA VENTA A CRÉDITO
# ============================================================

@app.post("/admin/ventas")
def crear_venta(
    venta: NuevaVenta,
    authorization: str | None = Header(default=None),
):
    comprobar_admin_token(authorization)

    primer_vencimiento = parsear_fecha(venta.primer_vencimiento)

    conn = None

    try:
        conn = get_connection()

        with conn.cursor() as cur:
            # Comprobar que el cliente exista.
            cur.execute(
                """
                SELECT id, nombre
                FROM clientes
                WHERE id = %s
                """,
                (venta.cliente_id,),
            )

            cliente = cur.fetchone()

            if not cliente:
                raise HTTPException(
                    status_code=404,
                    detail="El cliente no existe.",
                )

            cliente_id_db, nombre_cliente = cliente

            # Reparto exacto del monto total.
            monto_base = venta.monto_total // venta.cantidad_cuotas
            resto = venta.monto_total % venta.cantidad_cuotas

            for i in range(venta.cantidad_cuotas):
                numero_cuota = i + 1

                # Si hay resto, se agrega a la última cuota.
                monto_cuota = monto_base

                if numero_cuota == venta.cantidad_cuotas:
                    monto_cuota += resto

                vencimiento = (
                    primer_vencimiento.year,
                    primer_vencimiento.month,
                    primer_vencimiento.day,
                )

                # Para mantener compatibilidad con tu tabla actual,
                # las fechas se guardan como texto DD/MM/YYYY.
                fecha_texto = (
                    f"{vencimiento[2]:02d}/"
                    f"{vencimiento[1]:02d}/"
                    f"{vencimiento[0]}"
                )

                mes = MESES[primer_vencimiento.month - 1]

                cur.execute(
                    """
                    INSERT INTO cuotas (
                        cliente_id,
                        nombre,
                        detalle_mueble,
                        mes,
                        numero,
                        vencimiento,
                        monto,
                        estado,
                        fecha_pago
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        cliente_id_db,
                        nombre_cliente,
                        venta.detalle_mueble,
                        mes,
                        f"{numero_cuota} de {venta.cantidad_cuotas}",
                        fecha_texto,
                        monto_cuota,
                        "Pendiente",
                        None,
                    ),
                )

                # Sumar un mes manteniendo el día cuando sea posible.
                if primer_vencimiento.month == 12:
                    nuevo_anio = primer_vencimiento.year + 1
                    nuevo_mes = 1
                else:
                    nuevo_anio = primer_vencimiento.year
                    nuevo_mes = primer_vencimiento.month + 1

                # Evitar problemas con días como 31 al pasar a meses
                # de 30 días o febrero.
                import calendar

                ultimo_dia = calendar.monthrange(nuevo_anio, nuevo_mes)[1]
                nuevo_dia = min(primer_vencimiento.day, ultimo_dia)

                primer_vencimiento = date(
                    nuevo_anio,
                    nuevo_mes,
                    nuevo_dia,
                )

        conn.commit()

        return {
            "ok": True,
            "mensaje": "Venta a crédito creada correctamente.",
            "cliente_id": cliente_id_db,
            "nombre": nombre_cliente,
            "detalle_mueble": venta.detalle_mueble,
            "monto_total": venta.monto_total,
            "cantidad_cuotas": venta.cantidad_cuotas,
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise

    except Exception as exc:
        if conn:
            conn.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"No se pudo crear la venta: {str(exc)}",
        )

    finally:
        if conn:
            conn.close()


# ============================================================
# ADMIN - MARCAR UNA CUOTA COMO PAGADA
# ============================================================

@app.put("/admin/cuota/pagar")
def marcar_cuota_pagada(
    datos: PagoCuota,
    authorization: str | None = Header(default=None),
):
    comprobar_admin_token(authorization)

    fecha_pago = datos.fecha_pago.strip() if datos.fecha_pago else (
        date.today().strftime("%d/%m/%Y")
    )

    conn = None

    try:
        conn = get_connection()

        with conn.cursor() as cur:
            # Primero verificamos cuántas filas coinciden.
            cur.execute(
                """
                SELECT COUNT(*)
                FROM cuotas
                WHERE cliente_id = %s
                  AND numero = %s
                  AND detalle_mueble = %s
                  AND vencimiento = %s
                """,
                (
                    datos.cliente_id,
                    datos.numero.strip(),
                    datos.detalle_mueble.strip(),
                    datos.vencimiento.strip(),
                ),
            )

            cantidad = cur.fetchone()[0]

            if cantidad == 0:
                raise HTTPException(
                    status_code=404,
                    detail="No se encontró la cuota indicada.",
                )

            if cantidad > 1:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Hay más de una cuota que coincide con esos datos. "
                        "No se modificó ninguna."
                    ),
                )

            cur.execute(
                """
                UPDATE cuotas
                SET estado = %s,
                    fecha_pago = %s
                WHERE cliente_id = %s
                  AND numero = %s
                  AND detalle_mueble = %s
                  AND vencimiento = %s
                """,
                (
                    "pagado",
                    fecha_pago,
                    datos.cliente_id,
                    datos.numero.strip(),
                    datos.detalle_mueble.strip(),
                    datos.vencimiento.strip(),
                ),
            )

        conn.commit()

        return {
            "ok": True,
            "mensaje": "Cuota marcada como pagada.",
            "fecha_pago": fecha_pago,
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise

    except Exception as exc:
        if conn:
            conn.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"No se pudo marcar la cuota como pagada: {str(exc)}",
        )

    finally:
        if conn:
            conn.close()


# ============================================================
# ADMIN - EDITAR FECHA DE VENCIMIENTO
# ============================================================

@app.put("/admin/cuota/editar-vencimiento")
def editar_vencimiento(
    datos: EditarVencimiento,
    authorization: str | None = Header(default=None),
):
    comprobar_admin_token(authorization)

    nuevo = datos.nuevo_vencimiento.strip()
    actual = datos.vencimiento_actual.strip()

    if not nuevo:
        raise HTTPException(status_code=400, detail="La nueva fecha es obligatoria.")

    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM cuotas
                WHERE cliente_id = %s
                  AND numero = %s
                  AND detalle_mueble = %s
                  AND vencimiento = %s
                """,
                (
                    datos.cliente_id,
                    datos.numero.strip(),
                    datos.detalle_mueble.strip(),
                    actual,
                ),
            )

            cantidad = cur.fetchone()[0]

            if cantidad == 0:
                raise HTTPException(
                    status_code=404,
                    detail="No se encontró la cuota con esa fecha de vencimiento.",
                )

            if cantidad > 1:
                raise HTTPException(
                    status_code=409,
                    detail="Hay más de una cuota que coincide con esos datos. No se modificó ninguna.",
                )

            cur.execute(
                """
                UPDATE cuotas
                SET vencimiento = %s
                WHERE cliente_id = %s
                  AND numero = %s
                  AND detalle_mueble = %s
                  AND vencimiento = %s
                """,
                (
                    nuevo,
                    datos.cliente_id,
                    datos.numero.strip(),
                    datos.detalle_mueble.strip(),
                    actual,
                ),
            )

        conn.commit()
        return {
            "ok": True,
            "mensaje": "Fecha de vencimiento actualizada correctamente.",
            "nuevo_vencimiento": nuevo,
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception as exc:
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"No se pudo actualizar la fecha: {str(exc)}",
        )
    finally:
        if conn:
            conn.close()


# ============================================================
# ADMIN - REGISTRAR ABONOS PARCIALES / TOTALES
# ============================================================

@app.post("/admin/cuota/abono")
def registrar_abono_cuota(datos: AbonoCuota, authorization: str | None = Header(default=None)):
    comprobar_admin_token(authorization)
    fecha_pago = (datos.fecha_pago or date.today().strftime("%d/%m/%Y")).strip()
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            asegurar_tabla_pagos(cur)
            cur.execute("ALTER TABLE cuotas ADD COLUMN IF NOT EXISTS dias_gracia INTEGER NOT NULL DEFAULT 0")
            cur.execute("""SELECT monto, estado, COALESCE(dias_gracia,0) FROM cuotas
                WHERE cliente_id=%s AND numero=%s AND detalle_mueble=%s AND vencimiento::text=%s FOR UPDATE""",
                (datos.cliente_id, datos.numero.strip(), datos.detalle_mueble.strip(), datos.vencimiento.strip()))
            filas = cur.fetchall()
            if len(filas) == 0:
                raise HTTPException(status_code=404, detail="No se encontró la cuota indicada.")
            if len(filas) > 1:
                raise HTTPException(status_code=409, detail="Hay más de una cuota coincidente; no se registró el abono.")
            monto_cuota, estado, gracia_actual = filas[0]
            if str(estado or '').strip().lower() == 'pagado':
                raise HTTPException(status_code=409, detail="Esta cuota ya está pagada.")
            cur.execute("""SELECT COALESCE(SUM(monto_aplicado),0) FROM pagos_cuotas
                WHERE cliente_id=%s AND numero=%s AND detalle_mueble=%s AND vencimiento=%s""",
                (datos.cliente_id, datos.numero.strip(), datos.detalle_mueble.strip(), datos.vencimiento.strip()))
            abonado_previo = float(cur.fetchone()[0] or 0)
            saldo = max(0.0, float(monto_cuota or 0)-abonado_previo)
            principal = round(float(datos.monto_abono), 2)
            if principal > saldo + 0.01:
                raise HTTPException(status_code=400, detail=f"El abono supera el saldo pendiente ({saldo:.2f}).")
            cur.execute("UPDATE cuotas SET dias_gracia=%s WHERE cliente_id=%s AND numero=%s AND detalle_mueble=%s AND vencimiento::text=%s",
                (datos.dias_gracia, datos.cliente_id, datos.numero.strip(), datos.detalle_mueble.strip(), datos.vencimiento.strip()))
            try:
                venc = parsear_fecha(datos.vencimiento)
                hoy = date.today()
                fin_gracia = fecha_fin_gracia_habil(venc, datos.dias_gracia)
                dias_atraso = max(0, (hoy - fin_gracia).days)
            except Exception:
                dias_atraso = 0
            recargo = round(saldo * 0.01 * dias_atraso, 2) if datos.aplicar_recargo else 0.0
            cur.execute("""INSERT INTO pagos_cuotas
                (cliente_id, numero, detalle_mueble, vencimiento, monto_aplicado, recargo_monto, fecha_pago, aplicar_recargo)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (datos.cliente_id, datos.numero.strip(), datos.detalle_mueble.strip(), datos.vencimiento.strip(), principal, recargo, fecha_pago, datos.aplicar_recargo))
            abonado_total = round(abonado_previo + principal, 2)
            pagada = abonado_total >= float(monto_cuota or 0) - 0.01
            if pagada:
                cur.execute("UPDATE cuotas SET estado='pagado', fecha_pago=%s WHERE cliente_id=%s AND numero=%s AND detalle_mueble=%s AND vencimiento::text=%s",
                    (fecha_pago, datos.cliente_id, datos.numero.strip(), datos.detalle_mueble.strip(), datos.vencimiento.strip()))
            else:
                cur.execute("UPDATE cuotas SET estado='Pendiente', fecha_pago=NULL WHERE cliente_id=%s AND numero=%s AND detalle_mueble=%s AND vencimiento::text=%s",
                    (datos.cliente_id, datos.numero.strip(), datos.detalle_mueble.strip(), datos.vencimiento.strip()))
        conn.commit()
        return {"ok": True, "estado": "pagado" if pagada else "parcial", "monto_cuota": float(monto_cuota or 0),
                "abonado_acumulado": abonado_total, "saldo_pendiente": max(0, float(monto_cuota or 0)-abonado_total),
                "monto_abono": principal, "recargo": recargo, "total_recibido": round(principal+recargo,2),
                "fecha_pago": fecha_pago, "mensaje": "Cuota pagada." if pagada else "Abono parcial registrado; la cuota continúa pendiente."}
    except HTTPException:
        if conn: conn.rollback()
        raise
    except Exception as exc:
        if conn: conn.rollback()
        raise HTTPException(status_code=500, detail=f"No se pudo registrar el abono: {str(exc)}")
    finally:
        if conn: conn.close()


@app.get("/admin/reportes/datos")
def datos_reportes(authorization: str | None = Header(default=None)):
    comprobar_admin_token(authorization)
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            asegurar_tabla_pagos(cur)
            cur.execute("SELECT id, nombre FROM clientes ORDER BY nombre")
            clientes = [{"id": r[0], "nombre": r[1]} for r in cur.fetchall()]
            cur.execute("""SELECT cliente_id, numero, detalle_mueble, vencimiento, monto_aplicado,
                recargo_monto, fecha_pago, aplicar_recargo, created_at FROM pagos_cuotas ORDER BY created_at""")
            pagos = [{"cliente_id":r[0],"numero":r[1],"detalle_mueble":r[2],"vencimiento":r[3],"monto":float(r[4] or 0),
                "recargo":float(r[5] or 0),"fecha_pago":r[6],"aplicar_recargo":r[7],"created_at":r[8].isoformat() if r[8] else None} for r in cur.fetchall()]
        conn.commit()
        return {"clientes":clientes,"pagos":pagos}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"No se pudieron cargar los datos del reporte: {str(exc)}")
    finally:
        if conn: conn.close()


# ============================================================
# SALUD DE LA API
# ============================================================

@app.get("/")
def inicio():
    return {
        "ok": True,
        "mensaje": "API Mueblería A&G funcionando",
    }


@app.get("/health")
def health():
    conn = None

    try:
        conn = get_connection()

        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()

        return {
            "ok": True,
            "database": "conectada",
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Base de datos no disponible: {str(exc)}",
        )

    finally:
        if conn:
            conn.close()



# ============================================================
# ADMIN - EDITAR DATOS DE CLIENTE
# ============================================================

class EditarCliente(BaseModel):
    nombre: Optional[str] = None
    contrasena: Optional[str] = None

    @field_validator("nombre")
    @classmethod
    def limpiar_nombre(cls, value):
        return value.strip() if value is not None else value


@app.put("/admin/clientes/{cliente_id}")
def editar_cliente(
    cliente_id: str,
    datos: EditarCliente,
    authorization: str | None = Header(default=None),
):
    comprobar_admin_token(authorization)
    try:
        cliente_id_int = int(cliente_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="El ID del cliente debe ser numérico.")

    if datos.nombre is None and datos.contrasena is None:
        raise HTTPException(status_code=400, detail="Indicá el nombre o la contraseña a modificar.")
    if datos.nombre is not None and not datos.nombre:
        raise HTTPException(status_code=400, detail="El nombre no puede quedar vacío.")

    nueva_contrasena = (
        contraseña_numerica(datos.contrasena)
        if datos.contrasena is not None and datos.contrasena.strip()
        else None
    )
    if datos.contrasena is not None and not datos.contrasena.strip():
        raise HTTPException(status_code=400, detail="La contraseña no puede quedar vacía.")

    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM clientes WHERE id = %s", (cliente_id_int,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Cliente no encontrado.")

            if datos.nombre is not None and nueva_contrasena is not None:
                cur.execute(
                    "UPDATE clientes SET nombre = %s, contrasena = %s WHERE id = %s",
                    (datos.nombre, nueva_contrasena, cliente_id_int),
                )
            elif datos.nombre is not None:
                cur.execute(
                    "UPDATE clientes SET nombre = %s WHERE id = %s",
                    (datos.nombre, cliente_id_int),
                )
            else:
                cur.execute(
                    "UPDATE clientes SET contrasena = %s WHERE id = %s",
                    (nueva_contrasena, cliente_id_int),
                )

            if datos.nombre is not None:
                cur.execute(
                    "UPDATE cuotas SET nombre = %s WHERE cliente_id = %s",
                    (datos.nombre, cliente_id_int),
                )
        conn.commit()
        return {"ok": True, "mensaje": "Datos del cliente actualizados."}
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail="No se pudieron actualizar los datos del cliente.")
    finally:
        if conn:
            conn.close()


# ============================================================
# ADMIN - EDITAR UNA CUOTA (MONTO, MUEBLE Y VENCIMIENTO)
# ============================================================

class EditarCuota(BaseModel):
    cliente_id: int
    numero: str
    detalle_mueble_actual: str
    vencimiento_actual: str
    nuevo_monto: Optional[int] = Field(default=None, gt=0)
    nuevo_detalle_mueble: Optional[str] = None
    nuevo_vencimiento: Optional[str] = None
    nuevo_dias_gracia: Optional[int] = Field(default=None, ge=0, le=90)


@app.put("/admin/cuota/editar")
def editar_cuota(
    datos: EditarCuota,
    authorization: str | None = Header(default=None),
):
    comprobar_admin_token(authorization)
    if datos.nuevo_monto is None and datos.nuevo_detalle_mueble is None and datos.nuevo_vencimiento is None and datos.nuevo_dias_gracia is None:
        raise HTTPException(status_code=400, detail="No se indicó ningún cambio.")
    if datos.nuevo_detalle_mueble is not None and not datos.nuevo_detalle_mueble.strip():
        raise HTTPException(status_code=400, detail="El detalle del mueble no puede quedar vacío.")

    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE cuotas ADD COLUMN IF NOT EXISTS dias_gracia INTEGER NOT NULL DEFAULT 0")
            cur.execute(
                """
                SELECT estado FROM cuotas
                WHERE cliente_id = %s AND numero = %s
                  AND detalle_mueble = %s AND vencimiento = %s
                """,
                (datos.cliente_id, datos.numero.strip(), datos.detalle_mueble_actual.strip(),
                 datos.vencimiento_actual.strip()),
            )
            filas = cur.fetchall()
            if not filas:
                raise HTTPException(status_code=404, detail="No se encontró la cuota indicada.")
            if len(filas) > 1:
                raise HTTPException(status_code=409, detail="La cuota no es única; no se modificó nada.")

            asegurar_tabla_pagos(cur)
            cur.execute("""SELECT COALESCE(SUM(monto_aplicado),0) FROM pagos_cuotas
                WHERE cliente_id=%s AND numero=%s AND detalle_mueble=%s AND vencimiento=%s""",
                (datos.cliente_id, datos.numero.strip(), datos.detalle_mueble_actual.strip(), datos.vencimiento_actual.strip()))
            abonado = float(cur.fetchone()[0] or 0)
            cambia_clave = ((datos.nuevo_detalle_mueble is not None and datos.nuevo_detalle_mueble.strip() != datos.detalle_mueble_actual.strip()) or
                            (datos.nuevo_vencimiento is not None and datos.nuevo_vencimiento.strip() != datos.vencimiento_actual.strip()))
            if abonado > 0 and cambia_clave:
                raise HTTPException(status_code=409, detail="Esta cuota ya tiene abonos registrados. Para conservar el historial, no cambies el mueble ni el vencimiento; podés editar el importe si no queda por debajo de lo abonado.")
            if datos.nuevo_monto is not None and datos.nuevo_monto < abonado:
                raise HTTPException(status_code=400, detail=f"El nuevo importe no puede ser menor a lo ya abonado ({abonado:.2f}).")

            nuevo_detalle = (
                datos.nuevo_detalle_mueble.strip()
                if datos.nuevo_detalle_mueble is not None
                else datos.detalle_mueble_actual.strip()
            )
            nuevo_vencimiento = (
                datos.nuevo_vencimiento.strip()
                if datos.nuevo_vencimiento is not None
                else datos.vencimiento_actual.strip()
            )
            if datos.nuevo_vencimiento is not None:
                parsear_fecha(datos.nuevo_vencimiento)

            campos = []
            valores = []
            if datos.nuevo_monto is not None:
                campos.append("monto = %s")
                valores.append(datos.nuevo_monto)
            if datos.nuevo_detalle_mueble is not None:
                campos.append("detalle_mueble = %s")
                valores.append(nuevo_detalle)
            if datos.nuevo_vencimiento is not None:
                campos.append("vencimiento = %s")
                valores.append(nuevo_vencimiento)
            if datos.nuevo_dias_gracia is not None:
                campos.append("dias_gracia = %s")
                valores.append(datos.nuevo_dias_gracia)

            valores.extend([
                datos.cliente_id, datos.numero.strip(),
                datos.detalle_mueble_actual.strip(), datos.vencimiento_actual.strip()
            ])
            cur.execute(
                f"""UPDATE cuotas SET {', '.join(campos)}
                    WHERE cliente_id = %s AND numero = %s
                      AND detalle_mueble = %s AND vencimiento = %s""",
                tuple(valores),
            )
        conn.commit()
        return {"ok": True, "mensaje": "Cuota actualizada correctamente."}
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail="No se pudo actualizar la cuota.")
    finally:
        if conn:
            conn.close()


# ============================================================
# ADMIN - MODIFICAR CANTIDAD DE CUOTAS DE UNA VENTA
# Solo permite recalcular ventas sin cuotas pagadas para proteger el historial.
# ============================================================

class EditarVenta(BaseModel):
    cliente_id: int
    detalle_mueble_actual: str
    nuevo_detalle_mueble: str = Field(min_length=1)
    monto_total: int = Field(gt=0)
    cantidad_cuotas: int = Field(gt=0, le=120)
    primer_vencimiento: str


@app.put("/admin/ventas/editar")
def editar_venta(
    venta: EditarVenta,
    authorization: str | None = Header(default=None),
):
    comprobar_admin_token(authorization)
    primer_vencimiento = parsear_fecha(venta.primer_vencimiento)
    nuevo_detalle = venta.nuevo_detalle_mueble.strip()
    if not nuevo_detalle:
        raise HTTPException(status_code=400, detail="El detalle del mueble es obligatorio.")

    conn = None
    try:
        import calendar
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT estado, numero FROM cuotas
                WHERE cliente_id = %s AND detalle_mueble = %s
                ORDER BY numero
                """,
                (venta.cliente_id, venta.detalle_mueble_actual.strip()),
            )
            filas = cur.fetchall()
            if not filas:
                raise HTTPException(status_code=404, detail="No se encontró la venta indicada.")
            if any(str(f[0]).strip().lower() in ("pagado", "pago", "paid") for f in filas):
                raise HTTPException(
                    status_code=409,
                    detail="Esta venta tiene cuotas pagadas. Para proteger el historial, no se puede recalcular completa; editá solo las cuotas pendientes.",
                )
            asegurar_tabla_pagos(cur)
            cur.execute("SELECT COUNT(*) FROM pagos_cuotas WHERE cliente_id=%s AND detalle_mueble=%s",
                        (venta.cliente_id, venta.detalle_mueble_actual.strip()))
            if int(cur.fetchone()[0] or 0) > 0:
                raise HTTPException(status_code=409, detail="Esta venta ya tiene abonos registrados. Para conservar el historial, no se puede recalcular completa; editá las cuotas pendientes individualmente.")

            cur.execute(
                "DELETE FROM cuotas WHERE cliente_id = %s AND detalle_mueble = %s",
                (venta.cliente_id, venta.detalle_mueble_actual.strip()),
            )
            cur.execute("SELECT nombre FROM clientes WHERE id = %s", (venta.cliente_id,))
            cliente = cur.fetchone()
            if not cliente:
                raise HTTPException(status_code=404, detail="Cliente no encontrado.")

            base = venta.monto_total // venta.cantidad_cuotas
            resto = venta.monto_total % venta.cantidad_cuotas
            for i in range(venta.cantidad_cuotas):
                nro = i + 1
                monto = base + (resto if nro == venta.cantidad_cuotas else 0)
                fecha_texto = primer_vencimiento.strftime("%d/%m/%Y")
                mes = MESES[primer_vencimiento.month - 1]
                cur.execute(
                    """
                    INSERT INTO cuotas
                    (cliente_id, nombre, detalle_mueble, mes, numero, vencimiento, monto, estado, fecha_pago)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (venta.cliente_id, cliente[0], nuevo_detalle, mes,
                     f"{nro} de {venta.cantidad_cuotas}", fecha_texto, monto, "Pendiente", None),
                )
                mes_nuevo = primer_vencimiento.month + 1
                anio_nuevo = primer_vencimiento.year
                if mes_nuevo > 12:
                    mes_nuevo = 1
                    anio_nuevo += 1
                dia = min(primer_vencimiento.day, calendar.monthrange(anio_nuevo, mes_nuevo)[1])
                primer_vencimiento = date(anio_nuevo, mes_nuevo, dia)

        conn.commit()
        return {"ok": True, "mensaje": "Venta actualizada correctamente."}
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail="No se pudo actualizar la venta.")
    finally:
        if conn:
            conn.close()
