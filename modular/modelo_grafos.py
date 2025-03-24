import torch
from torch_geometric.data import Data

# --------------------------------------------------------------------------------
# Listado único de CVEs empleados en los 15 checks (sin duplicados)
# --------------------------------------------------------------------------------
nodes = [
    "CVE-2017-0144",  # (1) EternalBlue
    "CVE-2019-0708",  # (2) BlueKeep
    "CVE-2020-1472",  # (3) Zerologon
    "CVE-2021-34527", # (4) PrintNightmare
    "CVE-2020-16898", # (5) Bad Neighbor (TCP/IP RCE)
    "CVE-2022-30190", # (6) Follina (MSDT RCE)
    "CVE-2022-26925", # (7) Windows LSA Spoofing
    "CVE-2023-23397", # (8) Outlook Elevation of Privilege
    "CVE-2022-22047", # (9) Windows CSRSS Elevation of Privilege
    "CVE-2021-26411", # (10) IE Memory Corruption (RCE)
    "CVE-2023-28252", # (11) Windows CLFS Elevation of Privilege
    "CVE-2021-44228", # (12) Log4Shell
    "CVE-2014-0160",  # (13) Heartbleed
    "CVE-2017-5638",  # (14) Apache Struts RCE
    "CVE-2021-45046"  # (15) Variante de Log4Shell
]
# Mapear cada CVE a un índice (para PyTorch Geometric)
node_to_index = {cve: idx for idx, cve in enumerate(nodes)}

# --------------------------------------------------------------------------------
# Definimos los 15 checks y sus 3 CVE asociados
# Cada check es un arreglo [CVE_1, CVE_2, CVE_3]
# --------------------------------------------------------------------------------
checks = [
    # CHK_01 (Contraseñas seguras)
    ["CVE-2017-0144", "CVE-2019-0708", "CVE-2020-1472"],

    # CHK_02 (Usuarios sin privilegios innecesarios)
    ["CVE-2019-0708", "CVE-2021-34527", "CVE-2022-26925"],

    # CHK_03 (Firewall activado)
    ["CVE-2017-0144", "CVE-2021-34527", "CVE-2020-16898"],

    # CHK_04 (Antivirus activo)
    ["CVE-2020-1472", "CVE-2020-16898", "CVE-2023-23397"],

    # CHK_05 (Bloqueo de pantalla activo)
    ["CVE-2022-30190", "CVE-2022-26925", "CVE-2022-22047"],

    # CHK_06 (Deshabilitar USB no autorizados)
    ["CVE-2019-0708", "CVE-2022-30190", "CVE-2021-26411"],

    # CHK_07 (Registro de eventos activado y con retención adecuada)
    ["CVE-2017-0144", "CVE-2021-26411", "CVE-2021-44228"],

    # CHK_08 (No permitir que modifiquen el escritorio)
    ["CVE-2020-1472", "CVE-2022-22047", "CVE-2023-28252"],

    # CHK_09 (Deshabilitar ciertos sitios web)
    ["CVE-2021-34527", "CVE-2023-23397", "CVE-2021-44228"],

    # CHK_10 (Deshabilitar el administrador de tareas)
    ["CVE-2020-16898", "CVE-2022-30190", "CVE-2014-0160"],

    # CHK_11 (No abrir cmd)
    ["CVE-2022-26925", "CVE-2022-22047", "CVE-2017-5638"],

    # CHK_12 (No abrir PowerShell)
    ["CVE-2023-23397", "CVE-2021-26411", "CVE-2014-0160"],

    # CHK_13 (No permitir que modifiquen la barra de tareas)
    ["CVE-2023-28252", "CVE-2017-5638", "CVE-2021-45046"],

    # CHK_14 (No permitir que modifiquen los accesos directos)
    ["CVE-2021-44228", "CVE-2014-0160", "CVE-2021-45046"],

    # CHK_15 (Evitar que los usuarios accedan al registro)
    ["CVE-2017-0144", "CVE-2023-28252", "CVE-2021-45046"]
]
# --------------------------------------------------------------------------------
# Crear las aristas (edges) uniendo CVEs de cada check:
# - Para un check con 3 CVE => se generan edges (CVE1->CVE2) y (CVE2->CVE3)
# --------------------------------------------------------------------------------
edges = []
for check in checks:
    # Conectar consecutivamente los 3 CVEs dentro del mismo check
    edges.append([node_to_index[check[0]], node_to_index[check[1]]])
    edges.append([node_to_index[check[1]], node_to_index[check[2]]])

# Convertir la lista de edges a tensor y trasponer (PyG usa shape [2, num_edges])
edge_index = torch.tensor(edges, dtype=torch.long).t()

# Crear el objeto Data de PyTorch Geometric
data = Data(edge_index=edge_index, num_nodes=len(nodes))

# --------------------------------------------------------------------------------
# Impresión básica para verificar
# --------------------------------------------------------------------------------
print("Nodos (CVEs):")
for i, cve in enumerate(nodes):
    print(f"  {i}: {cve}")

print("\nConexiones (edges):")
print(edge_index.t().tolist())

print("\nGrafo creado (PyTorch Geometric):")
print(data)
