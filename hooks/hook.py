#!/usr/bin/env python3
"""
Pre-commit hook para validar código mediante API con OAuth2.0
"""
import json
import os
import sys

import requests
from dotenv import load_dotenv

# Load env
load_dotenv()


def load_auth_token():
    """Carga el token de autenticación desde el archivo JSON."""
    token_path = os.environ.get("AUTH_TOKEN_PATH")

    if not token_path:
        print("❌ ERROR: Variable de ambiente AUTH_TOKEN_PATH no está definida")
        return None

    if not os.path.exists(token_path):
        print(f"❌ ERROR: Archivo de token no encontrado en: {token_path}")
        return None

    try:
        with open(token_path, "r") as f:
            token_data = json.load(f)

        # Asumiendo que el token está en el campo 'access_token'
        token = token_data.get("access_token")
        if not token:
            print("❌ ERROR: Campo 'access_token' no encontrado en el archivo de token")
            return None

        return token
    except json.JSONDecodeError:
        print(f"❌ ERROR: Archivo de token no es un JSON válido: {token_path}")
        return None
    except Exception as e:
        print(f"❌ ERROR al leer el archivo de token: {str(e)}")
        return None


def check_api_health(base_url):
    """Verifica el estado de salud de la API."""
    health_url = f"{base_url}/health"

    try:
        print(f"🔍 Verificando estado de la API: {health_url}")
        response = requests.get(health_url, timeout=10)

        if response.status_code == 200:
            print("✅ API está disponible")
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


def evaluate_code(base_url, token):
    """Envía el código para evaluación a la API."""
    evaluate_url = f"{base_url}/evaluate"

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    payload = {"code": "test"}

    try:
        print(f"📤 Enviando código para evaluación...")
        response = requests.post(
            evaluate_url, headers=headers, json=payload, timeout=30
        )

        if response.status_code == 200:
            print("✅ Código evaluado exitosamente")
            for item in response.json()["result"]:
                print(f"Categoría evaluada: {item['owasp_name']}")
                print(item["response"])
            return True
        elif response.status_code == 401:
            print("❌ ERROR: Token de autenticación inválido o expirado")
            print("🔄 Por favor, renueva tu token de autenticación")
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

    # Remover trailing slash si existe
    server_url = server_url.rstrip("/")

    # Cargar el token de autenticación
    token = load_auth_token()
    if not token:
        sys.exit(1)

    # Verificar salud de la API
    if not check_api_health(server_url):
        print("\n❌ COMMIT RECHAZADO: API no está disponible")
        sys.exit(1)

    # Evaluar el código
    if not evaluate_code(server_url, token):
        print("\n❌ COMMIT RECHAZADO: Error en la evaluación del código")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("✅ COMMIT APROBADO: Todas las validaciones pasaron")
    print("=" * 60 + "\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
