# cve_utils.py

import os
from collections import defaultdict

import torch

# Importar desde tu script principal
from .modelo_grafos import (checks, data, device, features_originales, GCNProbabilidad,
 node_to_index, model_file_path)


def get_failed_cves_probabilities(failed_checks):
    """
    Simula un fallo en una serie de checks y devuelve la probabilidad
    predicha para cada CVE afectado, formateada como entero porcentual (0–100).

    Parámetros:
    - failed_checks (list[int]): Lista de índices de checks fallados (0-based).

    Retorna:
    - List[Tuple[str, int]]: Lista de tuplas (cve_id, probabilidad_entero).
    """
    # 1. Verificar que existe el modelo entrenado
    if not os.path.exists(model_file_path):
        raise FileNotFoundError(f"Modelo no encontrado: {model_file_path}")

    # 2. Cargar el modelo
    model = GCNProbabilidad(input_dim=data.x.shape[1], hidden_dim=128).to(device)
    model.load_state_dict(torch.load(model_file_path), strict=False)
    model.eval()

    # 3. Preparar features y simular la falla
    x_mod = features_originales.clone()
    count_per_cve = defaultdict(int)
    for chk_idx in failed_checks:
        for cve in checks[chk_idx]:
            count_per_cve[cve] += 1

    for cve, count in count_per_cve.items():
        idx = node_to_index[cve]
        x_mod[idx, 0] = 10.0               # elevar CVSS
        x_mod[idx, 1] = 1.0                # activar exploit
        x_mod[idx, 2] = count / 5.0        # intensidad según número de checks

    # 4. Inferencia
    with torch.no_grad():
        preds = model(x_mod.to(device), data.edge_index.to(device)).view(-1).cpu()

    # 5. Opcional: evitar valores demasiado bajos
    preds = torch.clamp(preds, min=0.30)

    # 6. Convertir a entero porcentual y recolectar resultados
    results = []
    for cve, _ in count_per_cve.items():
        idx = node_to_index[cve]
        pct = int((preds[idx].item() * 100) + 0.5)  # redondear al entero más cercano
        results.append((cve, pct))

    return results


if __name__ == "__main__":
    test = get_failed_cves_probabilities([0, 1, 2])
    print(test)