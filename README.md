## Como instalar el back.

# Clonar y correr el repositorio.
1.- Crea una carpeta y dentro clona el repositorio.
2.- afuera del repositorio crea tu entorno virutal  ->  python -m venv venv
3.- activalo -> .\venv\Scripts\Activate
4.- muevete al repo (BACKEND_MODULAR)
5.- corre el siguiente comando (importante con tu env activado) para instalar las dependencias ->  pip install -r requirements.txt
6.- Corre el siguiente comando para generar la base de datos -> python manage.py migrate
7.- Corre el siguiente comando para crear tu usario para el admin de django -> python manage.py createsuperuser
8.- Con esto lo corres -> python manage.py runserver

** Tu base de datos va a estar vacia, añade tus datos de prueba, lo puedes hacer en el /admin de manera mas sencilla. 

# Para desarrollar.
Si estás desarrollando nuevos modelos o cambiando la estructura de la base de datos, necesitarás crear nuevas migraciones.

Crear migraciones Genera las migraciones para los cambios realizados en los modelos:

bash
Copiar código
python manage.py makemigrations
Aplicar las migraciones Después de generar las migraciones, aplícalas a la base de datos:

bash
Copiar código
python manage.py migrate

# Setear debugger.
Opcional, si quieren usar el debugger para poner breakpoints y demas.
1. Visual Studio Code (VS Code)
VS Code necesita estar configurado para usar el intérprete Python de tu entorno virtual.

Paso 1: Selecciona el intérprete del entorno virtual
Presiona Ctrl + Shift + P (o Cmd + Shift + P en Mac).
Escribe y selecciona Python: Select Interpreter.
Elige la opción que apunta a tu entorno virtual. Por ejemplo:
.\venv\Scripts\python.exe
Si no la ves o no estas seguro, busca manualmente esta carpeta donde creaste tu entorno virtual y selecciona python.exe

Paso 2: Configura launch.json para usar el entorno virtual
Ve al menú de depuración (ícono de triángulo con un insecto).

Haz clic en "Crear un archivo launch.json".

Selecciona "Django" como configuración.

Abre el archivo launch.json generado y edítalo para incluir la ruta a tu entorno virtual:

json
Copiar código
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Django",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/manage.py",
            "args": [
                "runserver"
            ],
            "django": true,
            "pythonPath": "${workspaceFolder}/venv/Scripts/python"
        }
    ]
}
Guarda los cambios y ejecuta el depurador (F5).

# Conexion con Front
En caso de que no tengas conectado back y front: 
Agregar tu localhost en settings.py en los siguientes arreglos :

ALLOWED_HOSTS = ['localhost', '127.0.0.1']

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:5173/graphql/",  # reemplazar por tu localhosto
    "http://localhost:3000",  # También puedes permitir otros orígenes si los necesitas
    'http://localhost:5173',  # Agrega la URL del frontend
    'http://127.0.0.1:5173',  # Opcional, por si usas la IP directa

]


