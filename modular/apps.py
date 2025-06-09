# modular/apps.py
from django.apps import AppConfig
import threading # Necesario para crear el hilo
# import os # Ya no se usa para validaciones aquí
# import sys # Ya no se usa para validaciones aquí
# import traceback # Opcional, para imprimir errores detallados

# Variable global en este módulo para asegurar que el hilo se inicie solo una vez
# por proceso, independientemente de cuántas veces se llame a ready().
app_polling_thread_started = False

class ModularConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'modular'

    def ready(self):
        """
        Intenta iniciar el hilo de polling cuando Django está listo.
        La lógica para evitar múltiples hilos reales reside en la variable
        global app_polling_thread_started.
        """
        global app_polling_thread_started
        
        print(f"[APPS.PY] ready() llamado. app_polling_thread_started={app_polling_thread_started}")

        if not app_polling_thread_started:
            print("[APPS.PY] Hilo aún no iniciado en este proceso. Intentando iniciar...")
            try:
                # Importa la función polling_loop directamente desde utils.py
                # Esta función contiene el "while True:"
                from .utils import polling_loop 

                thread = threading.Thread(target=polling_loop, daemon=True)
                thread.start()
                app_polling_thread_started = True # Marcar como iniciado para este proceso
                print("[APPS.PY] Hilo de polling iniciado exitosamente (o intento realizado).")

            except ImportError:
                 print("[APPS.PY ERROR] No se pudo importar 'polling_loop' desde .utils. Verifica la ruta y el nombre del archivo.")
            except Exception as e:
                 print(f"[APPS.PY ERROR] Error general al intentar iniciar el hilo de polling: {e}")
                 # import traceback
                 # traceback.print_exc() # Descomenta para ver el traceback completo del error
        else:
            print("[APPS.PY] Hilo de polling ya marcado como iniciado en este proceso. No se inicia de nuevo.")
        
        print("[APPS.PY] Fin de la ejecución de ready().")



