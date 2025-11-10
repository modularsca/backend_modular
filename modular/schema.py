import graphene
from graphene_django import DjangoObjectType
from .cve_utils import get_failed_cves_probabilities
from .wazuh_client import WazuhAPIClient
from .models import ( AgentFailedChecksSummary, GlobalFailedChecksHistory)
import graphql_jwt
from graphql_jwt.decorators import login_required

# --- AÑADIMOS IMPORTACIONES DE DJANGO PARA MANEJAR USUARIOS ---
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
# -----------------------------------------------------------

# Configuración
from dotenv import load_dotenv
load_dotenv()
import os
from pathlib import Path

current_dir = Path(__file__).resolve().parent
env_path = current_dir.parent / ".env"
load_dotenv(env_path)

WAZUH_BASE_URL = os.getenv("WAZUH_BASE_URL")
WAZUH_USERNAME = os.getenv("WAZUH_USERNAME")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")

########################## INPUT TYPES ##############################


class AgenteWazuhInput(graphene.InputObjectType):
    id = graphene.String(required=True)
    name = graphene.String(required=True)
    ip = graphene.String(required=True)
    status = graphene.String(required=True)
    passed_policies = graphene.Int(required=True)
    failed_policies = graphene.Int(required=True)
    na_policies = graphene.Int(required=True)
    # Recibiremos el datetime como string ISO (ej: "2025-01-03T17:42:38+00:00")
    last_scan = graphene.String()
    policy_id = graphene.String()


########################## OBJECT TYPES ##############################

class AgenteWazuhObjectType(graphene.ObjectType):
    id = graphene.String()
    name = graphene.String()
    ip = graphene.String()
    status = graphene.String()
    passed_policies = graphene.Int()
    failed_policies = graphene.Int()
    na_policies = graphene.Int()
    last_scan = graphene.String()
    policy_id = graphene.String()
    policy_name = graphene.String()
        

class ComplianceObjectType(graphene.ObjectType):
    key = graphene.String()
    value = graphene.String()


class RuleObjectType(graphene.ObjectType):
    rule = graphene.String()
    type = graphene.String()


class PolicyCheckObjectType(graphene.ObjectType):
    id = graphene.Int()
    policy_id = graphene.String()
    result = graphene.String()
    remediation = graphene.String()
    command = graphene.String()
    description = graphene.String()
    title = graphene.String()
    condition = graphene.String()
    rationale = graphene.String()
    compliance = graphene.List(ComplianceObjectType)
    rules = graphene.List(RuleObjectType)

    # --- Object Type para el nuevo modelo (si quieres devolverlo) ---



# --- Input Type para la mutación para populate policys ---
class PolicyCheckTestInput(graphene.InputObjectType):
    # Campos del check que esperamos recibir
    check_id_in_policy = graphene.Int(required=True, description="ID numérico del check")
    policy_id_test = graphene.String(required=True, description="ID de la política de prueba")
    result = graphene.String(required=True)
    remediation = graphene.String()
    command = graphene.String()
    description = graphene.String()
    title = graphene.String(required=True)
    condition = graphene.String()
    rationale = graphene.String()
    compliance_json = graphene.JSONString(description="Cumplimiento como JSON string")
    rules_json = graphene.JSONString(required=True, description="Reglas como JSON string")


class CveProbabilityType(graphene.ObjectType):
    """Representa la probabilidad de riesgo para un CVE específico."""
    cve_id = graphene.String(description="Identificador del CVE")
    probability = graphene.Int(description="Probabilidad de riesgo calculada (0-100)")
    description = graphene.String(description="Descripción del CVE (opcional)")
    possible_risks = graphene.String(description="Lista de riesgos posibles asociados al CVE") 


# Todo: hacer para produccion
class AgentFailedChecksSummaryType(DjangoObjectType):
    class Meta:
        model = AgentFailedChecksSummary
        fields = "__all__"

    formatted_data = graphene.String()

    def resolve_formatted_data(self, info):
        day = self.timestamp.day
        month_names_es = ["", "enero", "febrero", "marzo", "abril", "mayo", "junio",
                          "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"]
        month_name = month_names_es[self.timestamp.month]
        return f"{day} {month_name} {self.timestamp.hour:02d}:{self.timestamp.minute:02d}"


class GlobalFailedChecksHistoryType(DjangoObjectType):
    class Meta:
        model = GlobalFailedChecksHistory
        fields = "__all__"

    formatted_data = graphene.String()

    def resolve_formatted_data(self, info):
        day = self.timestamp.day
        month_names_es = ["", "enero", "febrero", "marzo", "abril", "mayo", "junio",
                          "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"]
        month_name = month_names_es[self.timestamp.month]
        return f"{day} {month_name} {self.timestamp.hour:02d}:{self.timestamp.minute:02d}"

        return f"{total_failed_count} - {day} {month_name}"


########################## QUERIES ##############################


class Query(graphene.ObjectType):
    agentes_wazuh = graphene.List(AgenteWazuhObjectType)
    policy_checks = graphene.List(PolicyCheckObjectType, agent_id=graphene.String(required=True), policy_id=graphene.String(required=True))
    failed_checks_ids = graphene.List(
        graphene.Int,
        agent_id=graphene.String(required=True, description="ID del agente Wazuh"),
        policy_id=graphene.String(required=True, description="ID de la política SCA")
    )
    cve_probabilities = graphene.List(
        CveProbabilityType,
        failed_check_ids=graphene.List(graphene.Int, required=True, description="Lista de IDs (índices 0-based) de los checks fallados")
    )
    cve_probabilities_for_policy = graphene.List(
        CveProbabilityType,
        agent_id=graphene.String(required=True, description="ID del agente Wazuh"),
        policy_id=graphene.String(required=True, description="ID de la política SCA")
    )
    historical_failed_checks_by_agent = graphene.List(
        AgentFailedChecksSummaryType,
        agent_id=graphene.String(required=True),
        limit=graphene.Int(default_value=5)
    )
    general_latest_failed_checks_summary = graphene.List(
        GlobalFailedChecksHistoryType, # ¡Ahora usa el tipo del historial GLOBAL!
        limit=graphene.Int(default_value=10) # Los últimos 10 puntos de cambio globales
    )

    
    @login_required
    def resolve_agentes_wazuh(self, info):
        client = WazuhAPIClient(WAZUH_BASE_URL, WAZUH_USERNAME, WAZUH_PASSWORD)
        try:
            # Obtener la lista de agentes
            agents_data = client.fetch_agents()  # Aquí ya sabemos que es una lista directamente
            result = []
            for agent in agents_data:
                agent_id = agent.get("id")
                print(f"Processing Agent ID: {agent_id}")  # Diagnóstico
                try:
                    # Obtener información adicional del agente
                    additional_info = client.fetch_agent_info(agent_id)
                    print(f"Additional Info for {agent_id}:", additional_info)  # Diagnóstico
                except Exception:
                    additional_info = {
                        "passed_policies": 0,
                        "failed_policies": 0,
                        "na_policies": 0,
                        "last_scan": None,
                    }
                # Agregar información al resultado
                result.append(
                    AgenteWazuhObjectType(
                        id=agent.get("id"),
                        name=agent.get("name"),
                        ip=agent.get("ip", "N/A"),
                        status=agent.get("status"),
                        passed_policies=additional_info.get("passed_policies", 0),
                        failed_policies=additional_info.get("failed_policies", 0),
                        na_policies=additional_info.get("na_policies", 0),
                        last_scan=additional_info.get("last_scan"),
                        policy_id=additional_info.get("policy_id"),
                        policy_name=additional_info.get("policy_name")
                    )
                )
            print("Result:", result)  # Diagnóstico final
            result.pop(0)  # Elimina el primer agente ya que es el server
            return result
        except Exception as e:
            raise Exception(f"Error resolving agents: {e}")
    
    @login_required
    def resolve_policy_checks(self, info, agent_id, policy_id):
        client = WazuhAPIClient(WAZUH_BASE_URL, WAZUH_USERNAME, WAZUH_PASSWORD)
        checks_data = client.fetch_policy_checks(agent_id, policy_id)

        return [
            PolicyCheckObjectType(
                id=check.get("id"),
                policy_id=check.get("policy_id"),
                result=check.get("result"),
                remediation=check.get("remediation"),
                command=check.get("command"),
                description=check.get("description"),
                title=check.get("title"),
                condition=check.get("condition"),
                rationale=check.get("rationale"),
                compliance=[
                    ComplianceObjectType(key=c["key"], value=c["value"])
                    for c in check.get("compliance", [])
                ],
                rules=[
                    RuleObjectType(rule=r["rule"], type=r["type"])
                    for r in check.get("rules", [])
                ]
            )
            for check in checks_data
        ]
    
    @login_required
    def resolve_failed_checks_ids(self, info, agent_id, policy_id):
        """
        Devuelve una lista de IDs de los checks fallidos para un agente
        y política específicos, consultando la API de Wazuh (PRODUCCIÓN).
        """
        # Reutiliza el cliente API
        # Necesitas tener WAZUH_BASE_URL, USERNAME, PASSWORD definidos globalmente o pasarlos
        client = WazuhAPIClient(WAZUH_BASE_URL, WAZUH_USERNAME, WAZUH_PASSWORD)
        try:
            # Obtiene todos los checks para esa política/agente desde la API
            checks_data = client.fetch_policy_checks(agent_id, policy_id) #
            if not checks_data:
                return []

            # Filtra los checks por resultado "failed" y extrae sus IDs
            failed_ids = [
                check.get("id")
                for check in checks_data
                if check.get("result") == "failed" and check.get("id") is not None
            ]
            return failed_ids
        except Exception as e:
            # Maneja errores (e.g., loggear, lanzar error GraphQL)
            print(f"Error en resolve_failed_check_ids: {e}")
            return [] # Devolver lista vacía en caso de error


    @login_required
    def resolve_cve_probabilities_for_policy(self, info, agent_id, policy_id):
        """
        COMBINADO (PROD): Obtiene IDs fallidos (1-based) de la API, los convierte
        a 0-based y calcula probabilidades CVE.
        """
        failed_ids_1_based = []
        # Paso 1: Obtener IDs fallidos (1-based) de la API
        client = WazuhAPIClient(WAZUH_BASE_URL, WAZUH_USERNAME, WAZUH_PASSWORD) # Asegúrate que estas variables estén accesibles
        try:
            checks_data = client.fetch_policy_checks(agent_id, policy_id) #
            if checks_data:
                failed_ids_1_based = [
                    check.get("id") # Estos son IDs como 1, 3, 5...
                    for check in checks_data
                    if check.get("result") == "failed" and check.get("id") is not None
                ]
        except Exception as e:
            print(f"Error obteniendo checks fallidos en paso 1 (PROD): {e}")
            return []

        if not failed_ids_1_based:
            print("No se encontraron checks fallidos (PROD).")
            return []

        # --- Ajuste importante: Convertir IDs a 0-based ---
        failed_indices_0_based = [id - 1 for id in failed_ids_1_based if id > 0]
        print(f"(PROD) IDs fallidos (1-based): {failed_ids_1_based}")
        print(f"(PROD) Índices a pasar a la función (0-based): {failed_indices_0_based}")
        # -------------------------------------------------

        # Paso 2: Calcular probabilidades usando los índices 0-based
        try:
            results_dictionaries = get_failed_cves_probabilities(failed_indices_0_based)
            
            probabilities = []
            for cve_data in results_dictionaries:
                probabilities.append(
                    CveProbabilityType(
                        cve_id=cve_data.get("cve_name"),
                        probability=cve_data.get("probability_percentage"),
                        description=cve_data.get("description"),
                        possible_risks=cve_data.get("impact_if_unpatched")
                    )
                )
            return probabilities
        except FileNotFoundError as e:
            print(f"Error calculando probabilidades en paso 2 (PROD): {e}")
            raise Exception(f"Error al calcular probabilidades: Archivo de modelo no encontrado. Detalles: {e}")
        except Exception as e:
            print(f"Error inesperado calculando probabilidades en paso 2 (PROD): {e}")
            raise Exception(f"Error inesperado al calcular probabilidades de CVE: {e}")

    @login_required
    def resolve_historical_failed_checks_by_agent(self, info, agent_id, limit):
        data = AgentFailedChecksSummary.objects.filter(
            agent_id=agent_id
        ).order_by('-timestamp')[:limit]
        return data
    
    @login_required
    def resolve_general_latest_failed_checks_summary(self, info, limit):
        # Consulta directamente el modelo GlobalFailedChecksHistory
        # que ya guarda los cambios secuenciales del total global.
        return GlobalFailedChecksHistory.objects.order_by('-timestamp')[:limit]

########################## MUTATIONS ##############################

# --- INICIA MUTACIÓN PERSONALIZADA PARA CAMBIAR CONTRASEÑA ---
class CustomPasswordChange(graphene.Mutation):
    # Campos que devolverá la mutación
    success = graphene.Boolean()
    errors = graphene.JSONString() # Devolveremos errores como un JSON

    class Arguments:
        # Argumentos que acepta la mutación
        old_password = graphene.String(required=True)
        new_password1 = graphene.String(required=True)
        new_password2 = graphene.String(required=True)

    @login_required
    def mutate(self, info, old_password, new_password1, new_password2):
        user = info.context.user
        
        # 1. Verificar la contraseña antigua
        if not user.check_password(old_password):
            return CustomPasswordChange(success=False, errors={'old_password': [{'message': 'La contraseña actual es incorrecta.'}]})
            
        # 2. Verificar que las nuevas contraseñas coincidan
        if new_password1 != new_password2:
            return CustomPasswordChange(success=False, errors={'new_password2': [{'message': 'Las nuevas contraseñas no coinciden.'}]})
            
        # 3. Validar la nueva contraseña con los validadores de Django
        try:
            validate_password(new_password1, user=user)
        except ValidationError as e:
            # Convertir errores de validación a un formato JSON
            return CustomPasswordChange(success=False, errors={'new_password2': e.message_dict.get('__all__', [])})

        # 4. Si todo está bien, guardar la nueva contraseña
        user.set_password(new_password1)
        user.save()
        
        # 5. Actualizar la sesión del usuario para que no sea deslogueado (opcional pero recomendado)
        update_session_auth_hash(info.context, user)
        
        return CustomPasswordChange(success=True, errors=None)

# --- FIN DE MUTACIÓN PERSONALIZADA ---


class Mutation(graphene.ObjectType):
    token_auth = graphql_jwt.ObtainJSONWebToken.Field()
    verify_token = graphql_jwt.Verify.Field()
    refresh_token = graphql_jwt.Refresh.Field()
    
    # --- USAMOS NUESTRA MUTACIÓN PERSONALIZADA ---
    custom_password_change = CustomPasswordChange.Field()


schema = graphene.Schema(query=Query, mutation=Mutation)