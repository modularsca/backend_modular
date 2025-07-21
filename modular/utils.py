# modular/utils.py (o donde prefieras)

from django.db import transaction

import django.utils 
from django.utils import timezone
from .models import (AgenteTest, AgentFailedChecksSummary, CurrentFailedCheck,
    GlobalFailedChecksHistory, PolicyChecksTest)
import time
from typing import List
from django.db.models import Count

def overwrite_failed_checks(agent_id, policy_id, current_failed_ids):
    """
    Sobrescribe los checks fallidos en la BD para un agente y política específicos.

    Primero elimina todos los registros existentes para ese agente/política
    y luego inserta nuevos registros basados en la lista `current_failed_ids`.
    """
    if agent_id is None or policy_id is None:
        print("Se requiere agent_id y policy_id para sobrescribir.")
        return

    print(f"Sobrescribiendo checks fallidos para Agente: {agent_id}, Política: {policy_id}")

    # Asegurarse de que current_failed_ids sea una lista (puede ser vacía)
    failed_ids_list = current_failed_ids if current_failed_ids is not None else []
    print(f"IDs fallidos recibidos para inserción: {failed_ids_list}")

    try:
        with transaction.atomic():
            # 1. Borrar TODOS los registros existentes para este agente y política
            deleted_count, _ = CurrentFailedCheck.objects.filter(
                agent_id=agent_id,
                policy_id=policy_id
            ).delete()
            if deleted_count > 0:
                print(f"Eliminados {deleted_count} registros antiguos para Agente {agent_id}, Política {policy_id}.")

            # 2. Crear nuevos registros para cada ID en la lista actual
            checks_to_create = []
            for check_id in failed_ids_list:
                checks_to_create.append(
                    CurrentFailedCheck(
                        agent_id=agent_id,
                        policy_id=policy_id,
                        check_id=check_id
                        # 'last_seen' se establecerá automáticamente
                    )
                )

            # Usar bulk_create para eficiencia si hay muchos checks
            if checks_to_create:
                CurrentFailedCheck.objects.bulk_create(checks_to_create)
                print(f"Insertados {len(checks_to_create)} nuevos registros para Agente {agent_id}, Política {policy_id}.")
            else:
                print(f"No hay checks fallidos para insertar para Agente {agent_id}, Política {policy_id}.")

        print(f"Sobrescritura completada para Agente: {agent_id}, Política: {policy_id}")

    except Exception as e:
        print(f"Error durante la sobrescritura para Agente: {agent_id}, Política: {policy_id}. Error: {e}", exc_info=True)




# TODO: REVISAR QUE POLLING FUNCIONE CON PROD
# --- Lógica Principal del Polling ---
def poll_and_overwrite_all_failed_checks_logic():
    """
    Obtiene agentes (primero test, luego prod comentado),
    consulta sus checks fallidos para la política fija,
    y llama a overwrite_failed_checks para cada uno.
    """
    FIXED_POLICY_ID = "laboratorio_computo_windows"
    print(f"[INFO] Ejecutando ciclo de polling para política: {FIXED_POLICY_ID}...")

    # --- 1. Procesar Agentes de Prueba ---
    print("[INFO] Procesando agentes de prueba...")
    test_agents_processed = 0
    try:
        test_agents = AgenteTest.objects.all()  # Obtener todos los agentes de prueba
        print(f"[DEBUG] {test_agents.count()} agentes de prueba encontrados.")

        # Iterar sobre cada agente de prueba
        for agent_test in test_agents:
            agent_id = agent_test.id  # El ID viene del modelo AgenteTest
            print(f"[DEBUG] Procesando agente prueba: {agent_id}")
            failed_ids_test: List[int] = []  # Lista para guardar IDs fallidos

            try:
                # Obtener los IDs de checks fallidos para este agente y la política fija
                failed_ids_test = list(
                    PolicyChecksTest.objects.filter(  # Filtrar en PolicyChecksTest
                        agent_test=agent_test,        # Asociado a este agente
                        policy_id_test=FIXED_POLICY_ID,  # Para la política correcta
                        result="failed"               # Solo los fallidos
                    ).values_list('check_id_in_policy', flat=True)  # Obtener solo los IDs
                )
                print(f"[DEBUG] Agente prueba {agent_id}: {len(failed_ids_test)} checks fallidos encontrados en BD.")

                # --- Lógica para guardar el resumen histórico en el NUEVO MODELO ---
                current_failed_count = len(failed_ids_test)
                last_summary = AgentFailedChecksSummary.objects.filter(
                    agent=agent_test
                ).order_by('-timestamp').first()

                if not last_summary or last_summary.failed_checks_count != current_failed_count:
                    AgentFailedChecksSummary.objects.create(
                        agent=agent_test,
                        failed_checks_count=current_failed_count,
                        timestamp=timezone.now()
                    )
                    print(f"[INFO] Guardado nuevo resumen para Agente {agent_id}: {current_failed_count} checks fallidos.")
                else:
                    print(f"[INFO] Conteo de checks fallidos para Agente {agent_id} no ha cambiado ({current_failed_count}). No se guarda nuevo resumen.")


                # Llamar a la función que borra e inserta en CurrentFailedCheck
                overwrite_failed_checks(
                    agent_id=agent_id,            # ID del AgenteTest
                    policy_id=FIXED_POLICY_ID,    # Política fija
                    current_failed_ids=failed_ids_test  # Lista de IDs fallidos
                )
                test_agents_processed += 1

            except Exception as e:
                # Error procesando un agente de prueba específico, continuar con el siguiente
                print(f"[ERROR] Error procesando agente de prueba {agent_id} para política {FIXED_POLICY_ID}: {e}")
                # traceback.print_exc() # Descomenta para ver el traceback completo
            
                # --- Lógica para guardar el historial GLOBAL de checks fallidos ---
        print("[INFO] Guardando resumen global de checks fallidos...")
        try:
            # Calcular el total de checks fallidos en CurrentFailedCheck (que es el estado actual de todos)
            # o, si prefieres, sumar los últimos de cada AgentFailedChecksSummary
            current_global_failed_count_result = CurrentFailedCheck.objects.aggregate(total_sum=Count('check_id'))
            current_global_failed_count = current_global_failed_count_result['total_sum'] if current_global_failed_count_result['total_sum'] is not None else 0

            last_global_summary = GlobalFailedChecksHistory.objects.order_by('-timestamp').first()

            if not last_global_summary or last_global_summary.total_failed_count != current_global_failed_count:
                GlobalFailedChecksHistory.objects.create(
                    total_failed_count=current_global_failed_count,
                    timestamp=timezone.now()
                )
                print(f"[INFO] Guardado nuevo resumen GLOBAL: {current_global_failed_count} checks fallidos.")
            else:
                print(f"[INFO] Conteo global de checks fallidos no ha cambiado ({current_global_failed_count}). No se guarda nuevo resumen global.")

        except Exception as e:
            print(f"[ERROR] Error al procesar o guardar el resumen global de checks fallidos: {e}")


    except Exception as e:
        # Error obteniendo la lista general de agentes de prueba (ej: BD no disponible)
        print(f"[ERROR] Error crítico al obtener o iterar agentes de prueba: {e}")
        # traceback.print_exc()

    print(f"[INFO] {test_agents_processed} agentes de prueba procesados.")


def polling_loop():  # <--- ¡AQUÍ ESTÁ TU BUCLE!
    """
    Bucle infinito que llama a la lógica de polling cada 30 segundos.
    Esta función será el target del hilo.
    """
    print("Hilo de polling iniciado, entrando en bucle while True...")
    while True:  # <--------------------- EL WHILE TRUE
        try:
            # Llama a la función que hace el trabajo pesado
            poll_and_overwrite_all_failed_checks_logic()
        except Exception as e:
            print(f"Error inesperado en el bucle principal de polling: {e}")

        # Esperar 30 segundos
        print("Polling loop durmiendo por 30 segundos...")
        time.sleep(30) # <----------------- LA PAUSA
