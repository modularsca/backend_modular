import graphene
from graphene_django import DjangoObjectType
from .wazuh_client import WazuhAPIClient
from .models import Agente

# Configuración
WAZUH_BASE_URL = "https://18.188.253.184:55000"
WAZUH_USERNAME = "wazuh"
WAZUH_PASSWORD = "LfCGrwMI7VLLil6ZJH5d*OjXC*Xp3A8b"

class AgenteObjectType(DjangoObjectType):
    class Meta:
        model = Agente
        fields = ("name", "os",)

class AgenteWazuhObjectType(graphene.ObjectType):
    id = graphene.String()
    name = graphene.String()
    ip = graphene.String()
    status = graphene.String()
    passed_policies = graphene.Int()
    failed_policies = graphene.Int()
    na_policies = graphene.Int()
    last_scan = graphene.String()
    policy_name = graphene.String()  # Nuevo campo


class Query(graphene.ObjectType):
    agentes = graphene.List(AgenteObjectType)
    agentes_wazuh = graphene.List(AgenteWazuhObjectType)
    nombres = graphene.List(graphene.String)

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



    def resolve_agentes(self, info):
        return Agente.objects.all()
    
    def resolve_agentes_nombre(self, info):
        return Agente.objects.name()

# Mutación para crear un agente
class CreateAgente(graphene.Mutation):
    class Arguments:
        name = graphene.String(required=True)
        os = graphene.String(required=True)

    # Campo que retorna la mutación
    agente = graphene.Field(AgenteObjectType)

    def mutate(self, info, name, os):
        agente = Agente.objects.create(name=name, os=os)
        return CreateAgente(agente=agente)

# Clase de mutaciones
class Mutation(graphene.ObjectType):
    create_agente = CreateAgente.Field()

schema = graphene.Schema(query=Query, mutation=Mutation)