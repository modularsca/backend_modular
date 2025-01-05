# blog_project/urls.py

from django.contrib import admin
from django.urls import path, include
from django.views.decorators.csrf import csrf_exempt
from graphene_django.views import GraphQLView
from modular.schema import schema  # Importa el esquema desde tu app

urlpatterns = [
    path('admin/', admin.site.urls),
    # path("graphql/", include("modular.urls"))
    path('graphql/', csrf_exempt(GraphQLView.as_view(graphiql=True, schema=schema))),
]