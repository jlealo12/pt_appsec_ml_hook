#!/usr/bin/env python3
"""
OAuth2.0 + PKCE Authentication Script
Etapa 1: Preparación PKCE y estructura base
"""

import base64
import hashlib
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import requests
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field


class PKCEParams(BaseModel):
    """Parámetros para el flujo PKCE"""

    code_verifier: str = Field(..., min_length=43, max_length=128)
    code_challenge: str = Field(..., min_length=1)
    code_challenge_method: str = Field(default="S256")
    state: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    """Respuesta de tokens de Auth0"""

    access_token: str
    refresh_token: Optional[str] = None
    expires_in: int
    token_type: str = Field(default="Bearer")
    scope: Optional[str] = None


@dataclass
class Auth0Config:
    """Configuración de Auth0"""

    domain: str
    client_id: str
    audience: str  # Tu API identifier
    scopes: list[str]
    redirect_port: int = 8080

    @classmethod
    def load_from_env(cls, env_file: Optional[str] = None) -> "Auth0Config":
        """
        Carga la configuración desde variables de entorno

        Args:
            env_file: Ruta opcional al archivo .env

        Variables de entorno esperadas:
            - AUTH0_DOMAIN: El dominio de Auth0 (ej: tu-app.auth0.com)
            - AUTH0_CLIENT_ID: Client ID de la aplicación
            - AUTH0_AUDIENCE: API Identifier de tu API
            - AUTH0_SCOPES: Scopes separados por coma (ej: openid,profile,offline_access)
            - AUTH0_REDIRECT_PORT: Puerto para callback (opcional, default: 8080)
        """
        # Cargar archivo .env si se especifica
        if env_file:
            load_dotenv(env_file)
        else:
            load_dotenv()  # Busca .env en el directorio actual

        # Obtener variables requeridas
        domain = os.getenv("AUTH0_DOMAIN")
        if not domain:
            raise ValueError("AUTH0_DOMAIN es requerida en las variables de entorno")

        client_id = os.getenv("AUTH0_CLIENT_ID")
        if not client_id:
            raise ValueError("AUTH0_CLIENT_ID es requerida en las variables de entorno")

        audience = os.getenv("AUTH0_AUDIENCE")
        if not audience:
            raise ValueError("AUTH0_AUDIENCE es requerida en las variables de entorno")

        # Procesar scopes
        scopes_str = os.getenv("AUTH0_SCOPES", "openid,profile,offline_access")
        scopes = [scope.strip() for scope in scopes_str.split(",")]

        # Puerto con valor por defecto
        redirect_port = int(os.getenv("AUTH0_REDIRECT_PORT", "8080"))

        return cls(
            domain=domain,
            client_id=client_id,
            audience=audience,
            scopes=scopes,
            redirect_port=redirect_port,
        )


class PKCEGenerator:
    """Generador de parámetros PKCE según RFC 7636"""

    @staticmethod
    def generate_code_verifier() -> str:
        """
        Genera un code_verifier aleatorio.
        Debe ser un string de 43-128 caracteres usando [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
        """
        # Generamos 32 bytes aleatorios y los codificamos en base64url (sin padding)
        # Esto produce exactamente 43 caracteres
        random_bytes = secrets.token_bytes(32)
        code_verifier = (
            base64.urlsafe_b64encode(random_bytes).decode("utf-8").rstrip("=")
        )
        return code_verifier

    @staticmethod
    def generate_code_challenge(code_verifier: str) -> str:
        """
        Genera el code_challenge a partir del code_verifier.
        code_challenge = BASE64URL(SHA256(code_verifier))
        """
        # Calculamos SHA256 del code_verifier
        digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        # Codificamos en base64url sin padding
        code_challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
        return code_challenge

    @staticmethod
    def generate_state() -> str:
        """Genera un parámetro state aleatorio para prevenir CSRF"""
        return secrets.token_urlsafe(32)

    @classmethod
    def generate_pkce_params(cls) -> PKCEParams:
        """Genera todos los parámetros PKCE necesarios"""
        code_verifier = cls.generate_code_verifier()
        code_challenge = cls.generate_code_challenge(code_verifier)
        state = cls.generate_state()

        return PKCEParams(
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            code_challenge_method="S256",
            state=state,
        )


class TokenStorage:
    """Manejo seguro del almacenamiento de tokens"""

    def __init__(self, app_name: str = "oauth-precommit"):
        self.app_name = app_name
        self.config_dir = Path.home() / ".config" / app_name
        self.token_file = self.config_dir / "tokens.json"

        # Crear directorio si no existe
        self.config_dir.mkdir(parents=True, exist_ok=True)

        # Establecer permisos restrictivos (solo el usuario puede leer/escribir)
        os.chmod(self.config_dir, 0o700)

    def save_tokens(self, tokens: TokenResponse) -> None:
        """Guarda los tokens de forma segura"""
        token_data = {
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "expires_in": tokens.expires_in,
            "token_type": tokens.token_type,
            "scope": tokens.scope,
            "saved_at": secrets.token_hex(16),  # timestamp ofuscado para validación
        }

        with open(self.token_file, "w") as f:
            json.dump(token_data, f, indent=2)

        # Establecer permisos restrictivos en el archivo
        os.chmod(self.token_file, 0o600)
        print(f"✓ Tokens guardados en: {self.token_file}")

    def load_tokens(self) -> Optional[Dict[str, Any]]:
        """Carga los tokens guardados"""
        if not self.token_file.exists():
            return None

        try:
            with open(self.token_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"⚠ Error cargando tokens: {e}")
            return None

    def clear_tokens(self) -> None:
        """Elimina los tokens guardados"""
        if self.token_file.exists():
            self.token_file.unlink()
            print("✓ Tokens eliminados")


class OAuth2PKCEFlow:
    """Flujo principal de OAuth2.0 con PKCE"""

    def __init__(self, config: Auth0Config):
        self.config = config
        self.storage = TokenStorage()
        self.pkce_params: Optional[PKCEParams] = None
        self.authorization_code: Optional[str] = None
        self.callback_received = threading.Event()
        self.callback_error: Optional[str] = None

    def build_authorization_url(self) -> str:
        """Construye la URL de autorización con parámetros PKCE"""
        # Generar parámetros PKCE
        self.pkce_params = PKCEGenerator.generate_pkce_params()

        # Construir redirect_uri
        redirect_uri = f"http://localhost:{self.config.redirect_port}/callback"

        # Parámetros de la URL de autorización
        auth_params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.config.scopes),
            "code_challenge": self.pkce_params.code_challenge,
            "code_challenge_method": self.pkce_params.code_challenge_method,
            "state": self.pkce_params.state,
            "audience": self.config.audience,
        }

        # Construir URL completa
        base_url = f"https://{self.config.domain}/authorize"
        auth_url = f"{base_url}?{urlencode(auth_params)}"

        return auth_url

    def validate_callback_params(self, callback_url: str) -> tuple[str, bool]:
        """
        Valida los parámetros recibidos en el callback
        Retorna: (authorization_code, is_valid)
        """
        parsed_url = urlparse(callback_url)
        params = parse_qs(parsed_url.query)

        # Verificar si hay error
        if "error" in params:
            error = params["error"][0]
            error_desc = params.get("error_description", [""])[0]
            print(f"❌ Error en autorización: {error}")
            if error_desc:
                print(f"   Descripción: {error_desc}")
            return "", False

        # Verificar que tenemos los parámetros necesarios
        if "code" not in params or "state" not in params:
            print("❌ Parámetros faltantes en callback")
            return "", False

        # Verificar state parameter (prevención CSRF)
        received_state = params["state"][0]
        if not self.pkce_params or received_state != self.pkce_params.state:
            print("❌ State parameter inválido - posible ataque CSRF")
            return "", False

        code = params["code"][0]
        print("✓ Callback válido - código de autorización recibido")
        return code, True

    def create_callback_server(self) -> FastAPI:
        """Crea el servidor FastAPI para manejar el callback"""
        app = FastAPI()

        @app.get("/callback")
        async def callback(request: Request):
            """Endpoint que maneja el callback de Auth0"""
            try:
                # Construir URL completa del callback
                callback_url = str(request.url)

                # Validar parámetros del callback
                code, is_valid = self.validate_callback_params(callback_url)

                if is_valid:
                    self.authorization_code = code
                    self.callback_error = None

                    # Página de éxito
                    success_html = """
                    <html>
                        <head><title>Autenticación Exitosa</title></head>
                        <body style="font-family: Arial; text-align: center; padding: 50px;">
                            <h1 style="color: green;">✓ Autenticación Exitosa</h1>
                            <p>Ya puedes cerrar esta ventana y regresar a la terminal.</p>
                            <script>
                                setTimeout(() => window.close(), 3000);
                            </script>
                        </body>
                    </html>
                    """
                    response_content = success_html
                else:
                    self.callback_error = "Parámetros de callback inválidos"

                    # Página de error
                    error_html = """
                    <html>
                        <head><title>Error de Autenticación</title></head>
                        <body style="font-family: Arial; text-align: center; padding: 50px;">
                            <h1 style="color: red;">❌ Error de Autenticación</h1>
                            <p>Hubo un problema con la autenticación. Revisa la terminal para más detalles.</p>
                            <script>
                                setTimeout(() => window.close(), 5000);
                            </script>
                        </body>
                    </html>
                    """
                    response_content = error_html

                # Señalar que el callback fue recibido
                self.callback_received.set()

                return HTMLResponse(content=response_content)

            except Exception as e:
                self.callback_error = f"Error procesando callback: {str(e)}"
                self.callback_received.set()
                raise HTTPException(status_code=500, detail=str(e))

        return app

    def start_callback_server(self) -> threading.Thread:
        """Inicia el servidor de callback en un hilo separado"""
        app = self.create_callback_server()

        def run_server():
            uvicorn.run(
                app,
                host="127.0.0.1",
                port=self.config.redirect_port,
                log_level="error",  # Solo mostrar errores
            )

        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()

        # Esperar un poco para que el servidor arranque
        time.sleep(2)
        return server_thread

    def exchange_code_for_tokens(self, authorization_code: str) -> TokenResponse:
        """Intercambia el código de autorización por tokens"""
        if not self.pkce_params:
            raise ValueError("Parámetros PKCE no disponibles")

        token_url = f"https://{self.config.domain}/oauth/token"
        redirect_uri = f"http://localhost:{self.config.redirect_port}/callback"

        # Datos para el intercambio
        token_data = {
            "grant_type": "authorization_code",
            "client_id": self.config.client_id,
            "code": authorization_code,
            "redirect_uri": redirect_uri,
            "code_verifier": self.pkce_params.code_verifier,
        }

        # Realizar petición
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        print("🔄 Intercambiando código por tokens...")
        response = requests.post(token_url, data=token_data, headers=headers)

        if response.status_code != 200:
            error_msg = f"Error obteniendo tokens: {response.status_code}"
            try:
                error_detail = response.json()
                error_msg += f" - {error_detail.get('error_description', error_detail.get('error', ''))}"
            except:
                error_msg += f" - {response.text}"
            raise Exception(error_msg)

        # Parsear respuesta
        token_json = response.json()
        print("✓ Tokens obtenidos exitosamente")

        return TokenResponse(**token_json)

    def test_api_connection(self, access_token: str) -> bool:
        """Prueba la conexión con la API usando el access token"""
        # Esta es una prueba básica - ajustar según tu API
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            # Puedes cambiar esta URL por un endpoint de tu API
            test_url = f"{self.config.audience}/test"  # endpoint de prueba
            response = requests.get(test_url, headers=headers, timeout=10)

            if response.status_code == 200:
                print("✓ Conexión con API confirmada")
                return True
            else:
                print(f"⚠ API respondió con status {response.status_code}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"⚠ No se pudo probar conexión con API: {e}")
            return False

    def run_authentication_flow(self) -> bool:
        """Ejecuta el flujo completo de autenticación"""
        try:
            print("🚀 Iniciando flujo de autenticación OAuth2.0 + PKCE")

            # Paso 1: Iniciar servidor de callback
            print("🔧 Iniciando servidor local para callback...")
            server_thread = self.start_callback_server()

            # Paso 2: Construir URL de autorización
            auth_url = self.build_authorization_url()
            print(f"🔗 URL de autorización generada")

            # Paso 3: Abrir navegador
            print("🌐 Abriendo navegador para autenticación...")
            print("   (Si no se abre automáticamente, copia esta URL en tu navegador)")
            print(f"   {auth_url}")

            # if webbrowser.open(auth_url):
            #     print("✓ Navegador abierto")
            # else:
            #     print("⚠ No se pudo abrir el navegador automáticamente")

            # Paso 4: Esperar callback (con timeout)
            print("⏳ Esperando autorización del usuario...")
            callback_received = self.callback_received.wait(timeout=300)  # 5 minutos

            if not callback_received:
                print("❌ Timeout esperando autorización del usuario")
                return False

            if self.callback_error:
                print(f"❌ Error en callback: {self.callback_error}")
                return False

            if not self.authorization_code:
                print("❌ No se recibió código de autorización")
                return False

            # Paso 5: Intercambiar código por tokens
            tokens = self.exchange_code_for_tokens(self.authorization_code)

            # Paso 6: Guardar tokens
            self.storage.save_tokens(tokens)

            # Paso 7: Probar conexión con API
            self.test_api_connection(tokens.access_token)

            print("🎉 ¡Autenticación completada exitosamente!")
            return True

        except Exception as e:
            print(f"❌ Error en flujo de autenticación: {e}")
            return False


def main():
    """Función principal para testing"""
    try:
        # Cargar configuración desde variables de entorno
        config = Auth0Config.load_from_env()
        print(f"✓ Configuración cargada: {config.domain}")

    except ValueError as e:
        print(f"❌ Error de configuración: {e}")
        print("\n📋 Variables de entorno requeridas:")
        print("   AUTH0_DOMAIN=tu-dominio.auth0.com")
        print("   AUTH0_CLIENT_ID=tu_client_id")
        print("   AUTH0_AUDIENCE=https://tu-api.com")
        print("   AUTH0_SCOPES=openid,profile,offline_access  # opcional")
        print("   AUTH0_REDIRECT_PORT=8080  # opcional")
        print("\n💡 Crea un archivo .env con estas variables")
        return

    # Crear instancia del flujo OAuth
    oauth_flow = OAuth2PKCEFlow(config)

    # Verificar si ya tenemos tokens válidos
    existing_tokens = oauth_flow.storage.load_tokens()
    if existing_tokens:
        print("🔍 Tokens existentes encontrados")
        # Aquí podrías implementar lógica para verificar si el access token aún es válido
        # Por ahora, procedemos con nueva autenticación

    # Ejecutar flujo completo de autenticación
    success = oauth_flow.run_authentication_flow()

    if success:
        print("\n✅ Proceso completado exitosamente")
        print("Los tokens están guardados y listos para usar en el precommit-hook")
    else:
        print("\n❌ Proceso falló")
        print("Revisa la configuración y vuelve a intentar")


if __name__ == "__main__":
    main()
