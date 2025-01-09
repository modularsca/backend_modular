import requests
import logging

# Configura el logger para registrar errores
logger = logging.getLogger(__name__)

class WazuhAPIClient:
    def __init__(self, base_url, username, password):
        """
        Inicializa el cliente de la API de Wazuh.
        """
        self.base_url = base_url
        self.username = username
        self.password = password
        self.token = None

    def get_token(self):
        """
        Obtiene el token de autenticación usando credenciales de usuario y contraseña.
        Equivale al comando: 
        TOKEN=$(curl -u username:password -k -X GET "https://localhost:55000/security/user/authenticate?raw=true")
        """
        url = f"{self.base_url}/security/user/authenticate?raw=true"
        try:
            response = requests.get(
                url,
                auth=(self.username, self.password),  # Autenticación básica
                verify=False  # Desactiva verificación SSL para certificados autofirmados
            )
            response.raise_for_status()
            self.token = response.text.strip()  # Obtiene el token directamente
            if not self.token:
                logger.error("No se pudo obtener el token.")
                raise Exception("No se pudo obtener el token.")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Error obteniendo el token: {e}")

    def fetch_agents(self):
        """
        Obtiene la lista de agentes usando el token.
        Equivale al comando:
        curl -k -X GET "https://localhost:55000/agents" -H "Authorization: Bearer $TOKEN"
        """
        if not self.token:
            self.get_token()  # Autentica si no hay token disponible

        url = f"{self.base_url}/agents"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.get(
                url,
                headers=headers,
                verify=False  # Desactiva verificación SSL
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error obteniendo la lista de agentes: {e}")
            raise Exception(f"Error obteniendo agentes: {e}")
