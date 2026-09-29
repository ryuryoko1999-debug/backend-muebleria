import os
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
from psycopg2 import errors

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


def get_connection():
    return psycopg2.connect(DATABASE_URL)


@app.post("/login")
def login(datos: DatosLogin):
    conn = None
    cur = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT id, nombre
            FROM clientes
            WHERE id::text = %s AND contrasena = %s
            """,
            (datos.cliente_id, datos.contrasena),
        )

        cliente = cur.fetchone()

        if not cliente:
            raise HTTPException(
                status_code=401,
                detail="Cliente o contraseña incorrectos",
            )

        cliente_id, nombre = cliente

        cur.execute(
            """
            SELECT detalle_mueble, numero, vencimiento, monto, estado, fecha_pago
            FROM cuotas
            WHERE cliente_id::text = %s
            ORDER BY numero
            """,
            (str(cliente_id),),
        )

        cuotas = cur.fetchall()
        lista_cuotas = []

        for cuota in cuotas:
            detalle_mueble, numero, vencimiento, monto, estado, fecha_pago = cuota

            lista_cuotas.append(
                {
                    "detalle_mueble": detalle_mueble,
                    "numero": numero,
                    "vencimiento": vencimiento.isoformat()
                    if hasattr(vencimiento, "isoformat")
                    else vencimiento,
                    "monto": float(monto) if monto is not None else 0,
                    "estado": estado,
                    "fecha_pago": fecha_pago.isoformat()
                    if hasattr(fecha_pago, "isoformat")
                    else fecha_pago,
                }
            )

        return {
            "acceso": True,
            "nombre": nombre,
            "cuotas": lista_cuotas,
        }

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Error interno del servidor",
        )
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


def comprobar_admin_token(authorization: str | None):
    if not ADMIN_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="Falta configurar ADMIN_TOKEN en el servidor.",
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="No autorizado")

    if authorization[7:].strip() != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="No autorizado")


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

    return {"acceso": True, "access_token": ADMIN_TOKEN}


@app.get("/admin/clientes")
def listar_clientes(authorization: str | None = Header(default=None)):
    comprobar_admin_token(authorization)

    conn = None
    cur = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT id, nombre, contrasena
            FROM clientes
            ORDER BY id
            """
        )

        return [
            {
                "id": str(row[0]),
                "nombre": row[1],
                "contrasena": row[2],
            }
            for row in cur.fetchall()
        ]

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="No se pudieron obtener los clientes",
        )
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.post("/admin/clientes")
def agregar_cliente(
    cliente: NuevoCliente,
    authorization: str | None = Header(default=None),
):
    comprobar_admin_token(authorization)

    if not cliente.id.strip():
        raise HTTPException(status_code=400, detail="El ID es obligatorio.")
    if not cliente.nombre.strip():
        raise HTTPException(status_code=400, detail="El nombre es obligatorio.")
    if not cliente.contrasena.strip():
        raise HTTPException(status_code=400, detail="La contraseña es obligatoria.")

    conn = None
    cur = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO clientes (id, nombre, contrasena)
            VALUES (%s, %s, %s)
            """,
            (cliente.id.strip(), cliente.nombre.strip(), cliente.contrasena),
        )

        conn.commit()
        return {"ok": True, "mensaje": "Cliente agregado correctamente"}

    except errors.UniqueViolation:
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=409,
            detail="Ya existe un cliente con ese ID.",
        )
    except Exception:
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail="No se pudo agregar el cliente.",
        )
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.delete("/admin/clientes/{cliente_id}")
def eliminar_cliente(
    cliente_id: str,
    authorization: str | None = Header(default=None),
):
    comprobar_admin_token(authorization)

    conn = None
    cur = None

    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT COUNT(*)
            FROM cuotas
            WHERE cliente_id::text = %s
            """,
            (cliente_id,),
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
            WHERE id::text = %s
            RETURNING id
            """,
            (cliente_id,),
        )

        if not cur.fetchone():
            raise HTTPException(
                status_code=404,
                detail="Cliente no encontrado.",
            )

        conn.commit()
        return {"ok": True, "mensaje": "Cliente eliminado correctamente"}

    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception:
        if conn:
            conn.rollback()
        raise HTTPException(
            status_code=500,
            detail="No se pudo eliminar el cliente.",
        )
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.get("/")
def inicio():
    return {"ok": True, "mensaje": "API Mueblería A&G funcionando"}
