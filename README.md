# Conexion con Front

Agregar tu localhost en settings.py en los siguientes arreglos :

ALLOWED_HOSTS = ['localhost', '127.0.0.1']

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:5173/graphql/",  # reemplazar por tu localhosto
    "http://localhost:3000",  # También puedes permitir otros orígenes si los necesitas
    'http://localhost:5173',  # Agrega la URL del frontend
    'http://127.0.0.1:5173',  # Opcional, por si usas la IP directa

]
