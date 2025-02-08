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
            return response.json().get("data", {}).get("affected_items", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Error obteniendo la lista de agentes: {e}")
            raise Exception(f"Error obteniendo agentes: {e}")

    def fetch_agent_info(self, agent_id):
        """
        Obtiene información adicional de un agente, incluyendo políticas y último escaneo.
        """
        try:
            # Endpoint para SCA del agente
            sca_url = f"{self.base_url}/sca/{agent_id}/"
            response = requests.get(
                sca_url,
                headers={"Authorization": f"Bearer {self.token}"},
                verify=False
            )
            response.raise_for_status()
            data = response.json().get("data", {}).get("affected_items", [])

            # Si no hay datos en la respuesta
            if not data:
                logger.warning(f"No se encontraron políticas para el agente {agent_id}")
                return {
                    "passed_policies": 0,
                    "failed_policies": 0,
                    "na_policies": 0,
                    "last_scan": None,
                    "policy_name": None
                }

            # Extraer información de la primera política
            policy_info = data[0]
            passed_policies = policy_info.get("pass", 0)
            failed_policies = policy_info.get("fail", 0)
            invalid_policies = policy_info.get("invalid", 0)
            last_scan = policy_info.get("end_scan", None)
            policy_name = policy_info.get("name")  # Nuevo campo

            return {
                "passed_policies": passed_policies,
                "failed_policies": failed_policies,
                "na_policies": invalid_policies,
                "last_scan": last_scan,
                "policy_name": policy_name  # Incluye el nombre de la política
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"Error obteniendo información del agente {agent_id}: {e}")
            return {
                "passed_policies": 0,
                "failed_policies": 0,
                "na_policies": 0,
                "last_scan": None,
                "policy_name": None,
                "error": str(e)
            }


    def fetch_all_agents_info(self):
        """
        Obtiene la información completa para todos los agentes.
        """
        try:
            agents = self.fetch_agents()
            if not agents:
                logger.warning("No se encontraron agentes")
                return []

            all_agents_info = []
            for agent in agents:
                agent_id = agent.get("id")
                agent_info = self.fetch_agent_info(agent_id)
                all_agents_info.append(agent_info)

            return all_agents_info
        except Exception as e:
            logger.error(f"Error obteniendo la información de todos los agentes: {e}")
            raise
        
    def fetch_agents(self):
        """
        Obtiene la lista de agentes usando el token.
        """
        if not self.token:
            self.get_token()  # Autentica si no hay token disponible

        url = f"{self.base_url}/agents"
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            return response.json().get("data", {}).get("affected_items", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Error obteniendo la lista de agentes: {e}")
            raise Exception(f"Error obteniendo agentes: {e}")

    def fetch_policy_checks(self, agent_id, policy_id):
        """
        Obtiene los policy checks de un agente en una política específica.
        """
        if not self.token:
            self.get_token()

        url = f"{self.base_url}/sca/{agent_id}/checks/{policy_id}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            data = response.json().get("data", {}).get("affected_items", [])

            return data  # Devolvemos directamente la lista de policy checks

        except requests.exceptions.RequestException as e:
            logger.error(f"Error obteniendo policy checks para {agent_id}: {e}")
            return []
