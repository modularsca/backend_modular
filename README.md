
# Backend Modular

Este proyecto contiene la configuración del backend del sistema modular. Sigue los pasos a continuación para instalar y desarrollar.

---

## **Cómo instalar el backend**

### 1. Clonar y correr el repositorio
1. Crea una carpeta y dentro clona este repositorio:
   ```bash
   git clone <URL_DEL_REPOSITORIO>
   ```
2. Fuera del repositorio, crea un entorno virtual:
   ```bash
   python -m venv venv
   ```
3. Activa tu entorno virtual:
   - **Windows (PowerShell):**
     ```bash
     .\venv\Scripts\Activate
     ```
   - **Linux/Mac:**
     ```bash
     source venv/bin/activate
     ```
4. Muévete al directorio del repositorio (por ejemplo, `BACKEND_MODULAR`):
   ```bash
   cd BACKEND_MODULAR
   ```
5. Instala las dependencias con el entorno virtual activado:
   ```bash
   pip install -r requirements.txt
   ```
6. Genera la base de datos aplicando las migraciones:
   ```bash
   python manage.py migrate
   ```
7. Crea un superusuario para acceder al panel de administración de Django:
   ```bash
   python manage.py createsuperuser
   ```
8. Inicia el servidor:
   ```bash
   python manage.py runserver
   ```

   Ahora puedes acceder al backend en [http://127.0.0.1:8000](http://127.0.0.1:8000).

### **Nota**:
Tu base de datos estará vacía inicialmente. Puedes añadir datos de prueba desde el panel de administración en [http://127.0.0.1:8000/admin](http://127.0.0.1:8000/admin) para mayor facilidad.

---

## **Para desarrollar**

Si estás trabajando en nuevos modelos o cambiando la estructura de la base de datos, sigue estos pasos:

1. **Generar migraciones** para los cambios realizados en los modelos:
   ```bash
   python manage.py makemigrations
   ```
2. **Aplicar las migraciones** a la base de datos:
   ```bash
   python manage.py migrate
   ```

---

## **Configurar el debugger**

Si quieres usar el debugger en **Visual Studio Code (VS Code)** para depurar el proyecto, sigue estos pasos:

### Paso 1: Selecciona el intérprete del entorno virtual
1. Presiona `Ctrl + Shift + P` (o `Cmd + Shift + P` en Mac).
2. Escribe y selecciona `Python: Select Interpreter`.
3. Elige la opción que apunta a tu entorno virtual. Por ejemplo:
   ```
   .\venv\Scripts\python.exe
   ```
   Si no aparece, busca manualmente esta carpeta donde creaste tu entorno virtual y selecciona `python.exe`.

### Paso 2: Configura `launch.json` para usar el entorno virtual
1. Ve al menú de depuración (ícono de triángulo con un insecto).
2. Haz clic en "Crear un archivo `launch.json`".
3. Selecciona "Django" como configuración.
4. Abre el archivo `launch.json` generado y edítalo para incluir la ruta a tu entorno virtual:
   ```json
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
   ```
5. Guarda los cambios y ejecuta el depurador (`F5`).

---

## **Conexión con el Frontend**

En caso de que no tengas conectado el backend y el frontend, agrega tu `localhost` en `settings.py` en los siguientes arreglos:

```python
ALLOWED_HOSTS = ['localhost', '127.0.0.1']

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:5173/graphql/",  # Reemplazar por tu localhost si es necesario
    "http://localhost:3000",  # También puedes permitir otros orígenes si los necesitas
    'http://localhost:5173',  # Agrega la URL del frontend
    'http://127.0.0.1:5173',  # Opcional, por si usas la IP directa
]
```

