import os
from datetime import date, datetime
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
            cur.execute(
                """
                SELECT
                    cliente_id,
                    nombre,
                    detalle_mueble,
                    mes,
                    numero,
                    vencimiento,
                    monto,
                    estado,
                    fecha_pago
                FROM cuotas
                WHERE cliente_id = %s
                ORDER BY detalle_mueble, numero
                """,
                (cliente_id,),
            )

            filas = cur.fetchall()

        return [
            {
                "cliente_id": row[0],
                "nombre": row[1],
                "detalle_mueble": row[2],
                "mes": row[3],
                "numero": row[4],
                "vencimiento": formatear_fecha(row[5]),
                "monto": int(row[6]) if row[6] is not None else 0,
                "estado": row[7],
                "fecha_pago": formatear_fecha(row[8]),
            }
            for row in filas
        ]

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="No se pudieron obtener las cuotas.",
        )
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
