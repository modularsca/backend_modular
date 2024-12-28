import graphene
from graphene_django import DjangoObjectType

from .models import Agente

class AgenteObjectType(DjangoObjectType):
    class Meta:
        model = Agente
        fields = ("name", "os",)


class Query(graphene.ObjectType):
    agentes = graphene.List(AgenteObjectType)

    nombres = graphene.List(graphene.String)

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