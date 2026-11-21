# Fixtures de prueba para seguridad/lab3/regla-lab1.yml
# `ruleid:` = caso vulnerable que la regla DEBE detectar y bloquear.
# `ok:`     = caso seguro (control aplicado) que NO debe disparar falso positivo.
import sqlite3
import jwt


def buscar_productos(con: sqlite3.Connection, q: str, campo: str, valor: str, usuario: str):
    # Caso vulnerable 1 (Lab 1 Tienda UCP): SQLi por f-string en buscador
    # ruleid: ucp.lab3.sqli-interpolacion-consulta
    con.execute(f"SELECT id, nombre, precio FROM productos WHERE nombre LIKE '%{q}%'")

    # Caso vulnerable 2 (Lab 2 Billetera UCP): SQLi / Mass Assignment por f-string en UPDATE
    # ruleid: ucp.lab3.sqli-interpolacion-consulta
    con.execute(f"UPDATE usuarios SET {campo} = ? WHERE usuario = ?", (valor, usuario))

    # Caso seguro 1 (Control ASVS V1.2.4): consulta parametrizada con placeholder ?
    # ok: ucp.lab3.sqli-interpolacion-consulta
    con.execute("SELECT id, nombre, precio FROM productos WHERE nombre LIKE ?", (f"%{q}%",))

    # Caso seguro 2 (Control ASVS V1.2.4 / V8.2.2): columna fija de lista blanca y valor parametrizado
    # ok: ucp.lab3.sqli-interpolacion-consulta
    con.execute("UPDATE usuarios SET nombre = ? WHERE usuario = ?", (valor, usuario))


def validar_token(token: str, secreto: str):
    # Caso vulnerable (Amenaza #3 Lab 1 / Lab 2): desactivar verificación de firma JWT
    # ruleid: ucp.lab3.jwt-sin-verificar-firma
    datos_inseguros = jwt.decode(token, options={"verify_signature": False})

    # Caso seguro (Control ASVS V9.2.1): firma verificada con algoritmo fijo HS256
    # ok: ucp.lab3.jwt-sin-verificar-firma
    datos_seguros = jwt.decode(token, secreto, algorithms=["HS256"])
    return datos_inseguros, datos_seguros
