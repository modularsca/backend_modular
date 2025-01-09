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


class Query(graphene.ObjectType):
    agentes = graphene.List(AgenteObjectType)
    agentes_wazuh = graphene.List(AgenteWazuhObjectType)
    nombres = graphene.List(graphene.String)

    def resolve_agentes_wazuh(self, info):
        
        client = WazuhAPIClient(WAZUH_BASE_URL, WAZUH_USERNAME, WAZUH_PASSWORD)

        try:
            data = client.fetch_agents()
            # Filtrar y ajustar el formato según la respuesta de la API
            agents_data = data.get("data", {}).get("affected_items", [])
            return [
                AgenteWazuhObjectType(
                    id=agent.get("id"),
                    name=agent.get("name"),
                    ip=agent.get("ip", "N/A"),  # Algunas respuestas pueden no incluir IP
                    status=agent.get("status"),
                )
                for agent in agents_data
            ]
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