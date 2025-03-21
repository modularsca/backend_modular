import graphene
from graphene_django import DjangoObjectType
from .wazuh_client import WazuhAPIClient
from .models import AgenteTest
from dateutil import parser
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

########################## QUERYS ##############################

class Query(graphene.ObjectType):
    agentes_wazuh = graphene.List(AgenteWazuhObjectType)
    agentes_wazuh_test = graphene.List(AgenteWazuhObjectType)
    nombres = graphene.List(graphene.String)
    policy_checks = graphene.List(PolicyCheckObjectType, agent_id=graphene.String(required=True), policy_id=graphene.String(required=True))

    # PROD
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
                except Exception as e:
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


########################## MUTATIONS ##############################

class PopulateAgentesWazuh(graphene.Mutation):
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




# Clase de mutaciones
class Mutation(graphene.ObjectType):
    # create_agente = CreateAgente.Field()
    populate_agentes_wazuh = PopulateAgentesWazuh.Field()




schema = graphene.Schema(query=Query, mutation=Mutation)