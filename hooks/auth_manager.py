#!/usr/bin/env python3
"""
Gestor de autenticación y tokens para pre-commit hook
Maneja el ciclo de vida completo de los tokens OAuth2
"""

import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

import requests

from .oauth_login import Auth0Config, OAuth2PKCEFlow, TokenStorage


class AuthenticationManager:
    """Administra tokens y flujo de autenticación para el pre-commit hook"""

    def __init__(self):
        self.storage = TokenStorage()
        self.config = None
        self._load_config()

    def _load_config(self) -> None:
        """Carga la configuración de Auth0 desde variables de entorno"""
        try:
            self.config = Auth0Config.load_from_env()
        except ValueError as e:
            print(f"⚠️  Advertencia: No se pudo cargar configuración OAuth: {e}")
            self.config = None

    def get_valid_token(self) -> Optional[str]:
        """
        Obtiene un token válido, renovándolo si es necesario.
        Retorna None si no se puede obtener un token válido.
        """
        # Intentar obtener token desde variable de entorno (legacy)
        env_token_path = os.environ.get("AUTH_TOKEN_PATH")
        if env_token_path and os.path.exists(env_token_path):
            token = self._load_token_from_file(env_token_path)
            if token and self._is_token_valid(token):
                return token

        # Intentar obtener token desde storage local
        tokens = self.storage.load_tokens()
        if tokens:
            # Verificar si el token aún es válido
            if self._is_token_fresh(tokens):
                return tokens.get("access_token")

            # Intentar renovar con refresh token
            if tokens.get("refresh_token"):
                print("🔄 Token expirado, intentando renovar...")
                new_tokens = self._refresh_access_token(tokens["refresh_token"])
                if new_tokens:
                    return new_tokens.get("access_token")

        # Si llegamos aquí, necesitamos autenticación completa
        return None

    def _load_token_from_file(self, token_path: str) -> Optional[str]:
        """Carga token desde archivo JSON (compatibilidad con método legacy)"""
        try:
            with open(token_path, "r") as f:
                token_data = json.load(f)
            return token_data.get("access_token")
        except (json.JSONDecodeError, IOError, KeyError):
            return None

    def _is_token_valid(self, token: str) -> bool:
        """Verifica si un token es válido haciendo una petición de prueba"""
        server_url = os.environ.get("SERVER_URL")
        if not server_url:
            return False

        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.get(
                f"{server_url.rstrip('/')}/health", headers=headers, timeout=5
            )
            return response.status_code in [
                200,
                401,
            ]  # 401 significa que el endpoint existe
        except requests.exceptions.RequestException:
            return False

    def _is_token_fresh(self, tokens: Dict[str, Any]) -> bool:
        """
        Verifica si el token aún está dentro de su periodo de validez.
        Considera un margen de 5 minutos para evitar expiración durante uso.
        """
        if "saved_at" not in tokens or "expires_in" not in tokens:
            return False

        try:
            # Intentar obtener timestamp del token guardado
            # Como saved_at es un hash, usamos la fecha de modificación del archivo
            token_file = self.storage.token_file
            if not token_file.exists():
                return False

            saved_time = datetime.fromtimestamp(token_file.stat().st_mtime)
            expires_in = tokens["expires_in"]

            # Calcular tiempo de expiración con margen de seguridad
            expiration_time = saved_time + timedelta(
                seconds=expires_in - 300
            )  # 5 min margen

            return datetime.now() < expiration_time
        except (ValueError, OSError):
            return False

    def _refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """Renueva el access token usando el refresh token"""
        if not self.config:
            return None

        token_url = f"https://{self.config.domain}/oauth/token"

        token_data = {
            "grant_type": "refresh_token",
            "client_id": self.config.client_id,
            "refresh_token": refresh_token,
        }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        try:
            response = requests.post(
                token_url, data=token_data, headers=headers, timeout=10
            )

            if response.status_code == 200:
                new_tokens = response.json()
                # Preservar el refresh token si no viene en la respuesta
                if "refresh_token" not in new_tokens:
                    new_tokens["refresh_token"] = refresh_token

                # Guardar nuevos tokens
                from oauth_login import TokenResponse

                token_response = TokenResponse(**new_tokens)
                self.storage.save_tokens(token_response)

                print("✅ Token renovado exitosamente")
                return new_tokens
            else:
                print(f"⚠️  No se pudo renovar el token: {response.status_code}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"⚠️  Error renovando token: {e}")
            return None

    def authenticate_user(self) -> Optional[str]:
        """
        Inicia el flujo completo de autenticación OAuth.
        Retorna el access token si tiene éxito, None en caso contrario.
        """
        if not self.config:
            print("❌ No se puede autenticar: configuración OAuth no disponible")
            print("\n📋 Configura las siguientes variables de entorno:")
            print("   AUTH0_DOMAIN=tu-dominio.auth0.com")
            print("   AUTH0_CLIENT_ID=tu_client_id")
            print("   AUTH0_AUDIENCE=https://tu-api.com")
            print("   AUTH0_SCOPES=openid,profile,offline_access")
            return None

        print("\n" + "=" * 60)
        print("🔐 Se requiere autenticación")
        print("=" * 60)

        oauth_flow = OAuth2PKCEFlow(self.config)
        success = oauth_flow.run_authentication_flow()

        if success:
            tokens = self.storage.load_tokens()
            return tokens.get("access_token") if tokens else None

        return None

    def ensure_authenticated(self) -> str:
        """
        Garantiza que hay un token válido disponible.
        Si no existe o está expirado, inicia el flujo de autenticación.

        Raises:
            SystemExit: Si no se puede obtener un token válido
        """
        # Intentar obtener token válido existente
        token = self.get_valid_token()
        if token:
            return token

        # Necesitamos autenticación
        print("\n⚠️  No se encontró un token válido")

        token = self.authenticate_user()
        if token:
            return token

        # Si llegamos aquí, la autenticación falló
        print("\n❌ No se pudo obtener un token de autenticación")
        print("El commit no puede continuar sin autenticación válida")
        raise SystemExit(1)

    def clear_credentials(self) -> None:
        """Elimina las credenciales almacenadas"""
        self.storage.clear_tokens()
        print("✅ Credenciales eliminadas. Será necesario autenticarse nuevamente.")


def main():
    """Función de prueba del gestor de autenticación"""
    manager = AuthenticationManager()

    print("🧪 Probando AuthenticationManager\n")

    # Verificar token existente
    token = manager.get_valid_token()
    if token:
        print(f"✅ Token válido encontrado: {token[:20]}...")
    else:
        print("⚠️  No hay token válido")

        # Intentar autenticación
        print("\n🔐 Iniciando autenticación...")
        token = manager.authenticate_user()

        if token:
            print(f"✅ Autenticación exitosa: {token[:20]}...")
        else:
            print("❌ Autenticación fallida")


if __name__ == "__main__":
    main()
