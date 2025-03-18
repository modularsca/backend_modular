import torch
from torch_geometric.data import Data

# Definir los nodos del grafo (IDs de CVEs)
nodes = [
    # Check 1: Contraseñas seguras
    "CVE-2023-36050", "CVE-2023-36045", "CVE-2023-36042",
    # Check 2: Usuarios sin privilegios innecesarios
    "CVE-2023-36055", "CVE-2023-36048", "CVE-2023-36041",
    # Check 3: Firewall activado
    "CVE-2023-32049", "CVE-2023-35359", "CVE-2023-36884",
    # Check 4: Antivirus activo (Windows Defender)
    "CVE-2023-36036", "CVE-2023-36033", "CVE-2023-36025",
    # Check 5: Bloqueo de pantalla activo
    "CVE-2023-36052", "CVE-2023-36047", "CVE-2023-36044",
    # Check 6: Deshabilitar dispositivos USB no autorizados
    "CVE-2023-36060", "CVE-2023-36061", "CVE-2023-36062",
    # Check 7: Registro de eventos activado y con retención adecuada
    "CVE-2023-36063", "CVE-2023-36064", "CVE-2023-36065",
    # Check 8: No permitir que modifiquen el escritorio
    "CVE-2023-36066", "CVE-2023-36067", "CVE-2023-36068",
    # Check 9: Deshabilitar ciertos sitios web
    "CVE-2023-36069", "CVE-2023-36070", "CVE-2023-36071",
    # Check 10: Deshabilitar el administrador de tareas
    "CVE-2023-36072", "CVE-2023-36073", "CVE-2023-36074",
    # Check 11: No abrir cmd
    "CVE-2023-36075", "CVE-2023-36076", "CVE-2023-36077",
    # Check 12: No abrir PowerShell
    "CVE-2023-36078", "CVE-2023-36079", "CVE-2023-36080",
    # Check 13: No permitir que modifiquen la barra de tareas
    "CVE-2023-36081", "CVE-2023-36082", "CVE-2023-36083",
    # Check 14: No permitir que modifiquen los accesos directos del escritorio
    "CVE-2023-36084", "CVE-2023-36085", "CVE-2023-36086",
    # Check 15: Evitar que los usuarios accedan al registro de Windows
    "CVE-2023-36087", "CVE-2023-36088", "CVE-2023-36089"
]

# Mapear cada CVE a un índice único
node_to_index = {cve: idx for idx, cve in enumerate(nodes)}

# Definir las conexiones entre CVEs (cómo una vulnerabilidad facilita otra)
edges = []
for i in range(0, len(nodes), 3):  # Cada check tiene 3 CVEs
    cve1 = nodes[i]
    cve2 = nodes[i+1]
    cve3 = nodes[i+2]
    edges.append([node_to_index[cve1], node_to_index[cve2]])
    edges.append([node_to_index[cve2], node_to_index[cve3]])

# Convertir a tensor
edges = torch.tensor(edges, dtype=torch.long).t()

# Crear el grafo en PyTorch Geometric
data = Data(edge_index=edges, num_nodes=len(nodes))

# Imprimir información del grafo
print("Nodos (CVEs):", nodes)
print("Conexiones (edges):", edges.t().tolist())
print("Grafo creado:", data)