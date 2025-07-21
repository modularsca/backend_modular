import graphene
from graphene_django import DjangoObjectType
from .cve_utils import get_failed_cves_probabilities
from .wazuh_client import WazuhAPIClient
from .models import (AgenteTest, AgentFailedChecksSummary, GlobalFailedChecksHistory,
    PolicyChecksTest)
from django.db import transaction
from django.db.models.functions import TruncDay
from django.db.models import Sum 
import calendar 
# Configuración
WAZUH_BASE_URL = "https://18.188.253.184:55000"
WAZUH_USERNAME = "wazuh"
WAZUH_PASSWORD = "LfCGrwMI7VLLil6ZJH5d*OjXC*Xp3A8b"

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
    policy_name = graphene.String()


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


class PolicyChecksTestType(DjangoObjectType):
    class Meta:
        model = PolicyChecksTest
        fields = "__all__"


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

    # ... (Tus tipos existentes AgenteTestType, PolicyChecksTestType, CveType, CurrentFailedCheckType) ...


# tipos para los checks fallados, y la grafica historica
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
        # Aquí puedes añadir la hora si es relevante para la precisión intradía del agente
        return f"{day} {month_name} {self.timestamp.hour:02d}:{self.timestamp.minute:02d}"


# --- NUEVO TIPO para el historial GLOBAL detallado ---
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
    # TODO: REVISAR QUE QUERIES PROD FUNCIONE CORRECTAMENTE
    agentes_wazuh = graphene.List(AgenteWazuhObjectType)
    agentes_wazuh_test = graphene.List(AgenteWazuhObjectType)
    policy_checks = graphene.List(PolicyCheckObjectType, agent_id=graphene.String(required=True), policy_id=graphene.String(required=True))
    policy_checks_test = graphene.List(
        PolicyCheckObjectType, # Devuelve el mismo tipo que la query de prod
        agent_id=graphene.String(required=True, description="ID del AgenteTest a consultar"),
        policy_id=graphene.String(description="Opcional: ID de la política de prueba a filtrar")
    )
    failed_check_ids = graphene.List( # Para producción
        graphene.Int,
        agent_id=graphene.String(required=True, description="ID del agente Wazuh"),
        policy_id=graphene.String(required=True, description="ID de la política SCA")
    )
    failed_check_ids_test = graphene.List( # Para testing
        graphene.Int,
        agent_id=graphene.String(required=True, description="ID del AgenteTest"),
        policy_id=graphene.String(required=True, description="ID de la política de prueba")
    )
    cve_probabilities = graphene.List(
        CveProbabilityType,  # <- Usa el nuevo tipo de objeto
        failed_check_ids=graphene.List(graphene.Int, required=True, description="Lista de IDs (índices 0-based) de los checks fallados")
    )

    cve_probabilities_for_policy = graphene.List( # Para Producción
        CveProbabilityType,
        agent_id=graphene.String(required=True, description="ID del agente Wazuh"),
        policy_id=graphene.String(required=True, description="ID de la política SCA")
    )
    cve_probabilities_for_policy_test = graphene.List( # Para Testing
        CveProbabilityType,
        agent_id=graphene.String(required=True, description="ID del AgenteTest"),
        policy_id=graphene.String(required=True, description="ID de la política de prueba")
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
                        policy_name=additional_info.get("policy_name") 
                    )
                )

            print("Result:", result)  # Diagnóstico final
            return result

        except Exception as e:
            raise Exception(f"Error resolving agents: {e}")
    
    # TEST
    def resolve_agentes_wazuh_test(self, info):
        return AgenteTest.objects.all()
    
    # PROD
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
    
    # --- NUEVO RESOLVER PARA DATOS DE TEST CON FORMATO DE PRODUCCIÓN ---

    def resolve_policy_checks_test(self, info, agent_id, policy_id=None):
        # Buscamos en el modelo de Test usando el agent_id proporcionado
        try:
            agent_test = AgenteTest.objects.get(pk=agent_id)
        except AgenteTest.DoesNotExist:
            # Puedes devolver lista vacía o lanzar un error GraphQL
            return []

        # Filtramos los checks de prueba para ese agente
        queryset = PolicyChecksTest.objects.filter(agent_test=agent_test)

        # Filtramos opcionalmente por policy_id si se proporciona
        if policy_id:
            queryset = queryset.filter(policy_id_test=policy_id)

        # Transformamos los resultados del modelo al ObjectType deseado
        results = []
        for test_check in queryset:
            # Parsear compliance_json
            compliance_list = []
            try:
                compliance_data = test_check.compliance_json  # Esto ya debería ser una lista/dict si usas JSONField
                if isinstance(compliance_data, list):
                    # Asumiendo que guardaste una lista de dicts {'key': k, 'value': v}
                    # O ajusta según cómo guardaste los datos en la mutación
                    for item in compliance_data:
                        # Adaptar esto si la estructura guardada es diferente
                        if isinstance(item, dict):
                            compliance_list.append(ComplianceObjectType(key=item.get('key'), value=item.get('value')))
                        # else: maneja otros formatos si es necesario
            except Exception as e:
                print(f"Error parsing compliance_json for check {test_check.id}: {e}") # Log error

            # Parsear rules_json
            rules_list = []
            try:
                rules_data = test_check.rules_json  #  Esto ya debería ser una lista/dict
                if isinstance(rules_data, list):
                    for item in rules_data:
                        if isinstance(item, dict):
                            rules_list.append(RuleObjectType(rule=item.get('rule'), type=item.get('type')))
            except Exception as e:
                print(f"Error parsing rules_json for check {test_check.id}: {e}")  # Log error


            # Creamos la instancia del ObjectType que el frontend espera
            results.append(
                PolicyCheckObjectType(
                    id=test_check.check_id_in_policy,  # Mapeo de nombre
                    policy_id=test_check.policy_id_test,  # Mapeo de nombre
                    result=test_check.result,
                    remediation=test_check.remediation,
                    command=test_check.command,
                    description=test_check.description,
                    title=test_check.title,
                    condition=test_check.condition,
                    rationale=test_check.rationale,
                    compliance=compliance_list,  # Lista parseada
                    rules=rules_list  # Lista parseada
                )
            )
        return results
    
    def resolve_failed_check_ids(self, info, agent_id, policy_id):
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
            # Podrías lanzar un error GraphQL aquí si prefieres
            # raise Exception(f"Error fetching failed checks: {e}")
            return [] # Devolver lista vacía en caso de error

    def resolve_failed_check_ids_test(self, info, agent_id, policy_id):
        """
        Devuelve una lista de IDs de los checks fallidos para un agente
        y política específicos, consultando la base de datos de prueba (TESTING).
        """
        try:
            # Verifica que el AgenteTest exista (opcional pero buena práctica)
            if not AgenteTest.objects.filter(pk=agent_id).exists():
                 return []

            # Filtra directamente en la base de datos por agente, política y resultado
            # y obtén solo los IDs de los checks
            failed_ids_qs = PolicyChecksTest.objects.filter(
                agent_test_id=agent_id,
                policy_id_test=policy_id,
                result="failed"
            ).values_list('check_id_in_policy', flat=True) # Obtiene solo los IDs como una lista plana

            return list(failed_ids_qs) # Convierte el QuerySet a una lista

        except Exception as e:
            # Maneja errores
            print(f"Error en resolve_failed_check_ids_test: {e}")
            return []
        
    def resolve_cve_probabilities(self, info, failed_check_ids):
        """
        Calcula y devuelve las probabilidades de riesgo para los CVEs afectados
        por una lista de checks fallidos, usando la función externa.
        """
        try:
            # Llama a tu función importada de cve_utils.py
            # Asegúrate que los IDs en failed_check_ids sean los índices 0-based
            # que espera tu función (ajusta si es necesario).
            # Si los IDs vienen de `failed_check_ids_test`, que son `check_id_in_policy`,
            # podrías necesitar mapearlos a índices 0-based si tu función los espera así.
            # Por ahora, asumimos que los IDs pasados son los correctos.
            results_tuples = get_failed_cves_probabilities(failed_check_ids)

            # Transforma la lista de tuplas en una lista de CveProbabilityType
            probabilities = [
                CveProbabilityType(cve_id=cve, probability=prob)
                for cve, prob in results_tuples
            ]
            return probabilities

        except FileNotFoundError as e:
            # Maneja el caso específico donde el archivo del modelo no se encuentra
            print(f"Error en resolve_cve_probabilities: {e}")
            # Puedes lanzar un error GraphQL más informativo
            raise Exception(f"Error al calcular probabilidades: Archivo de modelo no encontrado. Detalles: {e}")
        except Exception as e:
            # Maneja otros errores generales
            print(f"Error inesperado en resolve_cve_probabilities: {e}")
            raise Exception(f"Error inesperado al calcular probabilidades de CVE: {e}")

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
            # Pasa la lista de índices 0-based a tu función
            results_tuples = get_failed_cves_probabilities(failed_indices_0_based) # <- Usa la lista ajustada
            probabilities = [
                CveProbabilityType(cve_id=cve, probability=prob)
                for cve, prob in results_tuples
            ]
            return probabilities
        except FileNotFoundError as e:
            print(f"Error calculando probabilidades en paso 2 (PROD): {e}")
            raise Exception(f"Error al calcular probabilidades: Archivo de modelo no encontrado. Detalles: {e}")
        except Exception as e:
            print(f"Error inesperado calculando probabilidades en paso 2 (PROD): {e}")
            raise Exception(f"Error inesperado al calcular probabilidades de CVE: {e}")

    def resolve_cve_probabilities_for_policy_test(self, info, agent_id, policy_id):
        """
        COMBINADO (TEST): Obtiene IDs fallidos (1-based) de la DB de prueba,
        los convierte a 0-based y calcula probabilidades CVE.
        """
        failed_ids_1_based = []
        # Paso 1: Obtener IDs fallidos (check_id_in_policy, que son 1-based)
        try:
            if not AgenteTest.objects.filter(pk=agent_id).exists():
                return []

            failed_ids_qs = PolicyChecksTest.objects.filter(
                agent_test_id=agent_id,
                policy_id_test=policy_id,
                result="failed"
            ).values_list('check_id_in_policy', flat=True) # Obtiene IDs como 1, 3, 5...
            failed_ids_1_based = list(failed_ids_qs)

        except Exception as e:
            print(f"Error obteniendo checks fallidos en paso 1 (TEST): {e}")
            return []

        if not failed_ids_1_based:
            print("No se encontraron checks fallidos (TEST).")
            return []

        # --- Ajuste importante: Convertir IDs a 0-based ---
        failed_indices_0_based = [id - 1 for id in failed_ids_1_based if id > 0]
        print(f"(TEST) IDs fallidos (1-based): {failed_ids_1_based}")
        print(f"(TEST) Índices a pasar a la función (0-based): {failed_indices_0_based}")
        # -------------------------------------------------
        probabilities = []
        # Paso 2: Calcular probabilidades usando los índices 0-based
        try:
            # TODO: Agregar 
            # Pasa la lista de índices 0-based a tu función
            results_dictionaries = get_failed_cves_probabilities(failed_indices_0_based) # <- Usa la lista ajustada
            for cve_data in results_dictionaries:
                probabilities.append(
                    CveProbabilityType(
                        cve_id=cve_data["cve_name"],
                        probability=cve_data["probability_percentage"],
                        description=cve_data["description"], # Agregado
                        possible_risks=cve_data["impact_if_unpatched"] # Agregado
                    )
                )
            return probabilities
        except FileNotFoundError as e:
            print(f"Error calculando probabilidades en paso 2 (TEST): {e}")
            raise Exception(f"Error al calcular probabilidades: Archivo de modelo no encontrado. Detalles: {e}")
        except Exception as e:
            print(f"Error inesperado calculando probabilidades en paso 2 (TEST): {e}")
            raise Exception(f"Error inesperado al calcular probabilidades de CVE: {e}")

    # test: TODO: hacer para produccion

    def resolve_historical_failed_checks_by_agent(self, info, agent_id, limit):
        return AgentFailedChecksSummary.objects.filter(
            agent__id=agent_id
        ).order_by('-timestamp')[:limit]
    
    # test: TODO: hacer para produccion
    def resolve_general_latest_failed_checks_summary(self, info, limit):
        # Consulta directamente el modelo GlobalFailedChecksHistory
        # que ya guarda los cambios secuenciales del total global.
        return GlobalFailedChecksHistory.objects.order_by('-timestamp')[:limit]

########################## MUTATIONS ##############################


class PopulateAgentesWazuh(graphene.Mutation):
    # Es para poblar base de datos de prueba.
    # Definimos los campos que retornará la mutación
    ok = graphene.Boolean()
    agentes = graphene.List(AgenteWazuhObjectType)

    # Definimos los argumentos de entrada
    class Arguments:
        agentes = graphene.List(AgenteWazuhInput, required=True)

    def mutate(self, info, agentes):
        # Importa tu modelo; asegúrate de ajustar la ruta según tu estructura 

        agentes_created = []

        for agente in agentes:
            # Actualiza o crea el registro según el id del agente
            obj, created = AgenteTest.objects.update_or_create(
                id=agente.id,  # Asumiendo que en el modelo tienes el campo 'agent_id'
                defaults={
                    "name": agente.name,
                    "ip": agente.ip,
                    "status": agente.status,
                    "passed_policies": agente.passed_policies or 0,
                    "failed_policies": agente.failed_policies or 0,
                    "na_policies": agente.na_policies or 0,
                    "last_scan": agente.last_scan,
                    "policy_name": agente.policy_name,
                }
            )
            agentes_created.append(obj)

        # Convertimos los objetos del modelo al formato que espera nuestro ObjectType
        agentes_return = [
            AgenteWazuhObjectType(
                id=agente.id,
                name=agente.name,
                ip=agente.ip,
                status=agente.status,
                passed_policies=agente.passed_policies,
                failed_policies=agente.failed_policies,
                na_policies=agente.na_policies,
                last_scan=str(agente.last_scan) if agente.last_scan else None,
                policy_name=agente.policy_name,
            )
            for agente in agentes_created
        ]

        return PopulateAgentesWazuh(ok=True, agentes=agentes_return)


class PopulatePolicyChecksTest(graphene.Mutation):
    class Arguments:
        agent_test_id = graphene.String(required=True, description="ID del AgenteTest al que asociar los checks")
        checks = graphene.List(PolicyCheckTestInput, required=True, description="Lista de checks de prueba a guardar")

    # Qué devuelve la mutación
    success = graphene.Boolean()
    errors = graphene.List(graphene.String)
    created_count = graphene.Int()

    @staticmethod
    def mutate(root, info, agent_test_id, checks):
        errors = []
        created_count = 0

        # Verificar que el AgenteTest existe
        try:
            agent_test = AgenteTest.objects.get(pk=agent_test_id)
        except AgenteTest.DoesNotExist:
            return PopulatePolicyChecksTest(success=False, errors=[f"AgenteTest with id {agent_test_id} not found."])

        # Usar transacción para asegurar atomicidad
        try:
            with transaction.atomic():
                # Borrar checks anteriores para este agente si es necesario (opcional)
                # PolicyChecksTest.objects.filter(agent_test=agent_test).delete()

                # Crear los nuevos checks de prueba
                for check_data in checks:
                    PolicyChecksTest.objects.create(
                        agent_test=agent_test,
                        check_id_in_policy=check_data.check_id_in_policy,
                        policy_id_test=check_data.policy_id_test,
                        result=check_data.result,
                        remediation=check_data.remediation or "",
                        command=check_data.command or "",
                        description=check_data.description or "",
                        title=check_data.title,
                        condition=check_data.condition or "",
                        rationale=check_data.rationale,
                        compliance_json=check_data.compliance_json or [],
                        rules_json=check_data.rules_json or [],
                        # date_recorded se establece por defecto
                    )
                    created_count += 1

        except Exception as e:
            errors.append(f"An error occurred during database transaction: {str(e)}")
            return PopulatePolicyChecksTest(success=False, errors=errors, created_count=0)

        # Si todo fue bien
        return PopulatePolicyChecksTest(
            success=True,
            errors=errors,
            created_count=created_count
        )

# Clase de mutaciones

class Mutation(graphene.ObjectType):
    # create_agente = CreateAgente.Field()
    populate_agentes_wazuh = PopulateAgentesWazuh.Field()
    populate_policy_checks_test = PopulatePolicyChecksTest.Field()


schema = graphene.Schema(query=Query, mutation=Mutation)
