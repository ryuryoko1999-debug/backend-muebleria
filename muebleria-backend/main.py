from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = "postgresql://postgres.aqjqgritnnnmuvtqktgv:42001935Aa._@aws-0-us-east-1.pooler.supabase.com:6543/postgres"

class DatosLogin(BaseModel):
    cliente_id: str
    contrasena: str

@app.post("/login")
def iniciar_sesion(datos: DatosLogin):
    try:
        conexion = psycopg2.connect(DATABASE_URL)
        cursor = conexion.cursor()

        # 1. Buscamos al cliente (usamos %s::text para evitar errores de tipo si id es int)
        query_cliente = """
            SELECT id, nombre FROM clientes 
            WHERE id::text = %s AND contrasena = %s
        """
        cursor.execute(query_cliente, (str(datos.cliente_id).strip(), str(datos.contrasena).strip()))
        cliente = cursor.fetchone()

        if not cliente:
            cursor.close()
            conexion.close()
            raise HTTPException(status_code=401, detail="ID de cliente o contraseña incorrectos")

        cliente_id_db = cliente[0]
        nombre_cliente = cliente[1]

        # 2. Buscamos las cuotas asociadas al cliente
        query_cuotas = """
            SELECT detalle_mueble, numero, vencimiento, monto, estado, fecha_pago 
            FROM cuotas 
            WHERE cliente_id::text = %s
        """
        cursor.execute(query_cuotas, (str(cliente_id_db).strip(),))
        cuotas_db = cursor.fetchall()

        cursor.close()
        conexion.close()

        # 3. Procesamos y limpiamos las cuotas
        lista_cuotas = []
        for c in cuotas_db:
            # Limpieza del monto en caso de que venga formateado como texto con $ o comas
            raw_monto = str(c[3]).replace('$', '').replace('.', '').replace(',', '.').strip() if c[3] is not None else '0'
            try:
                monto_float = float(raw_monto)
            except ValueError:
                monto_float = 0.0

            lista_cuotas.append({
                "detalle": c[0],
                "numero": c[1],
                "vencimiento": str(c[2]) if c[2] else "-",
                "monto": monto_float,
                "estado": c[4],
                "fecha_pago": str(c[5]) if c[5] else "-"
            })

        return {
            "acceso": "Permitido",
            "nombre_cliente": nombre_cliente,
            "cuotas": lista_cuotas
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error detallado en backend: {e}")
        # Devuelve el detalle del error exacto para depurar fácilmente
        raise HTTPException(status_code=500, detail=f"Error en base de datos: {str(e)}")