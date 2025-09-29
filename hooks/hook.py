#!/usr/bin/env python3
"""
Pre-commit hook para validar código mediante API con OAuth2.0
Versión integrada con autenticación automática
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import requests

# Importar el gestor de autenticación
from .auth_manager import AuthenticationManager


def get_staged_python_files():
    """Obtiene la lista de archivos Python en el staging area."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True,
        )

        files = result.stdout.strip().split("\n")
        python_files = [f for f in files if f.endswith(".py") and f]

        return python_files
    except subprocess.CalledProcessError as e:
        print(f"❌ ERROR al obtener archivos staged: {e}")
        return []


def get_file_changes(filepath):
    """Obtiene los cambios (diff) de un archivo específico."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--", filepath],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"❌ ERROR al obtener cambios de {filepath}: {e}")
        return None


def get_file_content(filepath):
    """Obtiene el contenido completo del archivo después de los cambios."""
    try:
        result = subprocess.run(
            ["git", "show", f":{filepath}"], capture_output=True, text=True, check=True
        )
        return result.stdout
    except subprocess.CalledProcessError:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            print(f"⚠️  No se pudo leer el contenido de {filepath}: {e}")
            return None


def collect_changes():
    """Recopila todos los cambios en archivos Python."""
    python_files = get_staged_python_files()

    if not python_files:
        print("ℹ️  No hay archivos Python en el commit")
        return None

    print(f"📁 Archivos Python detectados: {len(python_files)}")

    changes = []
    for filepath in python_files:
        print(f"   • {filepath}")

        diff = get_file_changes(filepath)
        content = get_file_content(filepath)

        file_data = {"filepath": filepath, "diff": diff, "content": content}
        changes.append(file_data)

    return changes


def check_api_health(base_url, token):
    """Verifica el estado de salud de la API con autenticación."""
    health_url = f"{base_url}/health"
    headers = {"Authorization": f"Bearer {token}"}

    try:
        print(f"🏥 Verificando estado de la API: {health_url}")
        response = requests.get(health_url, headers=headers, timeout=10)

        if response.status_code == 200:
            print("✅ API está disponible")
            return True
        elif response.status_code == 401:
            print("⚠️  Token no autorizado para este endpoint")
            # Aún retornamos True porque el servidor está disponible
            return True
        else:
            print(f"❌ API retornó estado: {response.status_code}")
            return False

    except requests.exceptions.Timeout:
        print("❌ ERROR: Timeout al conectar con la API")
        return False
    except requests.exceptions.ConnectionError:
        print(f"❌ ERROR: No se pudo conectar a la API en {health_url}")
        return False
    except Exception as e:
        print(f"❌ ERROR al verificar salud de la API: {str(e)}")
        return False


def format_changes_as_string(changes):
    """Formatea los cambios como un string para enviar a la API."""
    formatted_parts = []

    for file_data in changes:
        filepath = file_data["filepath"]
        content = file_data["content"]
        diff = file_data["diff"]

        file_section = f"=== File: {filepath} ===\n"
        file_section += f"{content}\n"
        file_section += f"\n=== Diff for {filepath} ===\n"
        file_section += f"{diff}\n"

        formatted_parts.append(file_section)

    return "\n".join(formatted_parts)


def evaluate_code(base_url, token, changes):
    """Envía el código para evaluación a la API."""
    evaluate_url = f"{base_url}/evaluate"

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    code_string = format_changes_as_string(changes)
    payload = {"code": code_string}

    try:
        print(f"📤 Enviando código para evaluación...")
        response = requests.post(
            evaluate_url, headers=headers, json=payload, timeout=30
        )

        if response.status_code == 200:
            print("✅ Código evaluado exitosamente")
            result = response.json()

            if "result" in result:
                for item in result["result"]:
                    print(f"\nCategoría evaluada: {item.get('owasp_name', 'N/A')}")
                    print(item.get("response", "Sin respuesta"))

            return result.get("status") == "success"

        elif response.status_code == 401:
            print("❌ ERROR: Token de autenticación inválido o expirado")
            print("💡 El token será renovado automáticamente en el próximo intento")
            # Limpiar token inválido
            from auth_manager import AuthenticationManager

            manager = AuthenticationManager()
            manager.storage.clear_tokens()
            return False

        elif response.status_code == 403:
            print("❌ ERROR: Acceso prohibido. Verifica tus permisos")
            return False

        else:
            print(f"❌ ERROR: La API retornó estado {response.status_code}")
            try:
                error_detail = response.json()
                print(f"Detalles: {error_detail}")
            except:
                print(f"Respuesta: {response.text}")
            return False

    except requests.exceptions.Timeout:
        print("❌ ERROR: Timeout al evaluar el código")
        return False
    except requests.exceptions.ConnectionError:
        print(f"❌ ERROR: No se pudo conectar a {evaluate_url}")
        return False
    except Exception as e:
        print(f"❌ ERROR al evaluar el código: {str(e)}")
        return False


def main():
    """Función principal del pre-commit hook."""
    print("\n" + "=" * 60)
    print("🚀 Ejecutando pre-commit hook")
    print("=" * 60 + "\n")

    # Obtener la URL del servidor
    server_url = os.environ.get("SERVER_URL")
    if not server_url:
        print("❌ ERROR: Variable de ambiente SERVER_URL no está definida")
        sys.exit(1)

    server_url = server_url.rstrip("/")

    # Inicializar gestor de autenticación
    auth_manager = AuthenticationManager()

    # Obtener token válido (se autenticará si es necesario)
    try:
        token = auth_manager.ensure_authenticated()
        print("✅ Token de autenticación obtenido")
    except SystemExit:
        # El gestor ya imprimió los mensajes de error
        sys.exit(1)

    # Recopilar cambios en archivos Python
    changes = collect_changes()
    if not changes:
        print("\nℹ️  No hay cambios en archivos Python para validar")
        print("✅ COMMIT APROBADO")
        sys.exit(0)

    # Verificar salud de la API
    if not check_api_health(server_url, token):
        print("\n❌ COMMIT RECHAZADO: API no está disponible")
        sys.exit(1)

    # Evaluar el código
    if not evaluate_code(server_url, token, changes):
        print("\n❌ COMMIT RECHAZADO: Error en la evaluación del código")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("✅ COMMIT APROBADO: Todas las validaciones pasaron")
    print("=" * 60 + "\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
