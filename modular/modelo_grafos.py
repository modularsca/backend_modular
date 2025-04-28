import torch
from torch_geometric.data import Data
import pandas as pd
import torch.nn.functional as F
from torch_geometric.nn import GCNConv
from collections import defaultdict
import os
import numpy as np

# --- Construye la ruta absoluta al archivo CSV ---
# 1. Obtiene la ruta del directorio donde está ESTE script (modelo_grafos.py)
script_dir = os.path.dirname(os.path.abspath(__file__))
# 2. Une esa ruta con el nombre del archivo CSV
csv_file_path = os.path.join(script_dir, "cve_features.csv")

# --- Construye la ruta absoluta al archivo del modelo ---
# 1. Obtiene la ruta del directorio donde está ESTE script (cve_utils.py)
script_dir_cve_utils = os.path.dirname(os.path.abspath(__file__))
# 2. Define el nombre del archivo del modelo
model_filename = 'modelo_entrenado.pth'
# 3. Une esa ruta con el nombre del archivo del modelo
model_file_path = os.path.join(script_dir_cve_utils, model_filename)

# --------------------------------------------------------------------------------
# Listado único de CVEs empleados en los 15 checks (sin duplicados)
# --------------------------------------------------------------------------------
nodes = [
    "CVE-2017-0144",  # EternalBlue (MS17-010)
    "CVE-2019-0708",  # BlueKeep
    "CVE-2020-1472",  # Zerologon
    "CVE-2020-0796",  # SMBGhost
    "CVE-2022-21907",  # HTTP.sys RCE
    "CVE-2022-30190",  # Follina (MSDT RCE)
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2022-26925",  # Windows LSA Spoofing
    "CVE-2014-4113",  # Win32k.sys EoP
    "CVE-2016-7255",  # Kernel EoP
    "CVE-2021-36934",  # HiveNightmare
    "CVE-2020-16898",  # Bad Neighbor (TCP/IP RCE)
    "CVE-2003-0352",  # DCOM RPC RCE
    "CVE-2003-0533",  # LSASS RCE (Sasser)
    "CVE-2023-23397",  # Outlook Elevation of Privilege
    "CVE-2012-0158",  # MSCOMCTL ActiveX
    "CVE-2014-6332",  # OLE VBScript EoP
    "CVE-2018-8174",  # Double Kill (VBScript RCE)
    "CVE-2022-22047",  # Windows CSRSS EoP
    "CVE-2023-21768",  # Win32k EoP
    "CVE-2022-41099",  # SmartScreen Security Feature Bypass
    "CVE-2022-41040",  # ProxyNotShell (Exchange)
    "CVE-2021-26411",  # IE Memory Corruption (RCE)
    "CVE-2010-2568",  # LNK vulnerability (Stuxnet)
    "CVE-2015-0096",  # Shell Link Path Overflow
    "CVE-2017-8464",  # Windows Shell RCE via .lnk
    "CVE-2021-44228",  # Log4Shell (Apache Log4j)
    "CVE-2020-0601",  # CurveBall (CryptoAPI spoofing)
    "CVE-2021-40444",  # MSHTML RCE
    "CVE-2015-1701",  # Win32k EoP
    "CVE-2023-28252",  # Windows CLFS EoP
    "CVE-2016-3309",  # Adobe Flash + Win32k sandbox bypass
    "CVE-2019-1388",  # Windows Certificate Dialog EoP
    "CVE-2022-41128",  # Chromium V8 RCE
    "CVE-2021-34473",  # Microsoft Exchange SSRF
    "CVE-2021-34523",  # Exchange Elevation of Privilege
    "CVE-2014-0160",  # Heartbleed (OpenSSL)
    "CVE-2012-0002",  # RDP RCE
    "CVE-2013-3660",  # NDProxy Elevation of Privilege
    "CVE-2017-5638",  # Apache Struts RCE
    "CVE-2016-0099",  # Secondary Logon EoP
    "CVE-2017-0143",  # ETERNALBLUE exploit kit subcomponent (MS17-010)
    "CVE-2019-1402",  # Windows Shell RCE
    "CVE-2018-0992",  # PowerShell Editor Services RCE
    "CVE-2020-1325",  # PowerShell Remote Jobs
    "CVE-2021-34484",  # User Profile Service EoP
    "CVE-2021-45046",  # Variante de Log4Shell
    "CVE-2021-1675",  # PrintNightmare (variante inicial)
    "CVE-2019-1069",  # Task Scheduler EoP
    "CVE-2020-1350",  # SIGRed (Windows DNS Server RCE)
    "CVE-2019-1040"  # NTLM Tampering
]

# Mapear cada CVE a un índice (para PyTorch Geometric)
node_to_index = {cve: idx for idx, cve in enumerate(nodes)}

# --------------------------------------------------------------------------------
# Asignación de CVEs a cada uno de los 15 checks, tal como se
# listó inicialmente con 6 CVEs para cada control de seguridad.
# --------------------------------------------------------------------------------

checks = [
    # CHK_01 (Contraseñas seguras)
    [
        "CVE-2017-0144",
        "CVE-2019-0708",
        "CVE-2020-1472",
        "CVE-2020-0796",
        "CVE-2022-21907",
        "CVE-2022-30190",
        # 🔁 Añadidos:
        "CVE-2021-44228",  # Log4Shell
        "CVE-2023-23397",  # Outlook
        "CVE-2021-34527",  # PrintNightmare
        "CVE-2014-0160"    # Heartbleed
    ],

    # CHK_02 (Usuarios sin privilegios innecesarios)
    [
        "CVE-2019-0708",
        "CVE-2021-34527",
        "CVE-2022-26925",
        "CVE-2014-4113",
        "CVE-2016-7255",
        "CVE-2021-36934",
        # 🔁 Añadidos:
        "CVE-2020-1472",
        "CVE-2023-28252",
        "CVE-2021-34484"
    ],

    # CHK_03 (Firewall activado)
    [
        "CVE-2017-0144",
        "CVE-2021-34527",
        "CVE-2020-16898",
        "CVE-2003-0352",
        "CVE-2003-0533",
        "CVE-2020-0796",
        # 🔁 Añadidos:
        "CVE-2021-44228",
        "CVE-2023-28252",
        "CVE-2012-0002",
        "CVE-2020-1472"
    ],

    # CHK_04 (Antivirus activo)
    [
        "CVE-2020-1472",
        "CVE-2020-16898",
        "CVE-2023-23397",
        "CVE-2012-0158",
        "CVE-2014-6332",
        "CVE-2018-8174",
        # 🔁 Añadidos:
        "CVE-2021-26411",
        "CVE-2014-0160",
        "CVE-2020-0796"
    ],

    # CHK_05 (Bloqueo de pantalla activo)
    [
        "CVE-2022-30190",
        "CVE-2022-26925",
        "CVE-2022-22047",
        "CVE-2023-21768",
        "CVE-2022-41099",
        "CVE-2022-41040",
        # 🔁 Añadidos:
        "CVE-2021-34484",
        "CVE-2017-0144",
        "CVE-2021-26411",
        "CVE-2020-0601"
    ],


    # CHK_06 (Deshabilitar USB no autorizados)
    [
        "CVE-2019-0708",  # BlueKeep
        "CVE-2022-30190",  # Follina
        "CVE-2021-26411",  # IE Memory Corruption
        "CVE-2010-2568",  # LNK vulnerability (Stuxnet)
        "CVE-2015-0096",  # Shell Link Path Overflow
        "CVE-2017-8464"   # Windows Shell RCE
    ],

    # CHK_07 (Registro de eventos activado y con retención adecuada)
    [
        "CVE-2017-0144",  # EternalBlue
        "CVE-2021-26411",  # IE Memory Corruption
        "CVE-2021-44228",  # Log4Shell
        "CVE-2020-0601",  # CurveBall
        "CVE-2021-40444",  # MSHTML RCE
        "CVE-2015-1701"   # Win32k EoP
    ],

    # CHK_08 (No permitir que modifiquen el escritorio)
    [
        "CVE-2020-1472",  # Zerologon
        "CVE-2022-22047",  # Windows CSRSS EoP
        "CVE-2023-28252",  # Windows CLFS EoP
        "CVE-2014-4113",  # Win32k.sys EoP
        "CVE-2016-3309",  # Adobe Flash + OS sandbox bypass
        "CVE-2019-1388"   # Windows Certificate Dialog EoP
    ],

    # CHK_09 (Deshabilitar ciertos sitios web)
    [
        "CVE-2021-34527",  # PrintNightmare
        "CVE-2023-23397",  # Outlook EoP
        "CVE-2021-44228",  # Log4Shell
        "CVE-2022-41128",  # Chromium V8 RCE
        "CVE-2021-34473",  # Microsoft Exchange SSRF
        "CVE-2021-34523"  # Exchange EoP
    ],

    # CHK_10 (Deshabilitar el administrador de tareas)
    [
        "CVE-2020-16898",  # Bad Neighbor
        "CVE-2022-30190",  # Follina - MSDT RCE
        "CVE-2014-0160",  # Heartbleed
        "CVE-2012-0002",  # RDP RCE
        "CVE-2013-3660",  # NDProxy EoP
        "CVE-2019-0708"   # BlueKeep
    ],

    # CHK_11 (No abrir cmd)
    [
        "CVE-2022-26925",  # Windows LSA Spoofing
        "CVE-2022-22047",  # Windows CSRSS EoP
        "CVE-2017-5638",  # Apache Struts RCE
        "CVE-2016-0099",  # Secondary Logon EoP
        "CVE-2017-0143",  # ETERNALBLUE exploit kit subcomponent
        "CVE-2019-1402"   # Windows Shell RCE
    ],

    # CHK_12 (No abrir PowerShell)
    [
        "CVE-2023-23397",  # Outlook EoP
        "CVE-2021-26411",  # IE Memory Corruption
        "CVE-2014-0160",  # Heartbleed
        "CVE-2018-0992",  # PowerShell Editor Services RCE
        "CVE-2020-1325",  # PowerShell Remote Jobs
        "CVE-2021-34484"  # User Profile Service EoP
    ],

    # CHK_13 (No permitir que modifiquen la barra de tareas)
    [
        "CVE-2023-28252",  # Windows CLFS EoP
        "CVE-2017-5638",  # Apache Struts RCE
        "CVE-2021-45046",  # Variante de Log4Shell
        "CVE-2014-4113",  # Win32k.sys EoP
        "CVE-2021-1675",  # PrintNightmare (variante inicial)
        "CVE-2019-1069"   # Task Scheduler EoP
    ],

    # CHK_14 (No permitir que modifiquen los accesos directos)
    [
        "CVE-2021-44228",  # Log4Shell
        "CVE-2014-0160",  # Heartbleed
        "CVE-2021-45046",  # Variante Log4Shell
        "CVE-2010-2568",  # LNK Shortcut
        "CVE-2015-0096",  # Shell Link
        "CVE-2020-1472"   # Zerologon
    ],

    # CHK_15 (Evitar que los usuarios accedan al registro)
    [
        "CVE-2017-0144",  # EternalBlue
        "CVE-2023-28252",  # Windows CLFS EoP
        "CVE-2021-45046",  # Variante de Log4Shell
        "CVE-2020-1350",  # SIGRed
        "CVE-2021-34484",  # User Profile Service EoP
        "CVE-2019-1040"   # NTLM Tampering
    ]
]


# --------------------------------------------------------------------------------
# Crear las aristas (edges) conectando CVEs consecutivos en cada check
# --------------------------------------------------------------------------------

edges = []
for check in checks:
    edges.append([node_to_index[check[0]], node_to_index[check[1]]])
    edges.append([node_to_index[check[1]], node_to_index[check[2]]])
edge_index = torch.tensor(edges, dtype=torch.long).t()

# --------------------------------------------------------------------------------
# Leer características desde cve_features.csv
# --------------------------------------------------------------------------------


df = pd.read_csv(csv_file_path)
severity_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
features = []
labels = []
for cve_id in nodes:
    row = df[df["cve_id"] == cve_id].iloc[0]
    count_checks = sum([1 for chk in checks if cve_id in chk])
    year = int(cve_id.split("-")[1]) / 2025.0  # Normalización básica
    features.append([row["cvss_score"], row["has_exploit"], count_checks / 5.0, year])
    labels.append(severity_map[row["severity"]])

x = torch.tensor(features, dtype=torch.float)
y = torch.tensor(labels, dtype=torch.long)
data = Data(x=x, edge_index=edge_index, y=y)
mean = data.x.mean(dim=0)
std = data.x.std(dim=0)
std[std == 0] = 1
data.x = (data.x - mean) / std
features_originales = data.x.clone()

print("\n📌 Estructura del grafo final:")
print(f"- Nodos (CVEs): {data.num_nodes}")
print(f"- Aristas (edges): {data.num_edges}")
print(f"- Features shape: {data.x.shape}")
print(f"- Clases por nodo: {data.y.tolist()}")
print(data)
print("\n✅ Grafo listo para entrenamiento.")

# --------------------------------------------------------------------------------
# Impresión básica para verificar
# --------------------------------------------------------------------------------

print("📌 Estructura del grafo final:")
print(f"- Nodos (CVEs): {data.num_nodes}")
print(f"- Aristas (edges): {data.num_edges}")
print(f"- Features shape: {data.x.shape}")
print(f"- Clases por nodo: {data.y.tolist()}")
print(data)
print("\n✅ Grafo listo para entrenamiento.")

# ╔══════════════════════════════════════════════════════════════════╗
# ║               🔧 ENTRENAMIENTO DEL MODELO GCN                    ║
# ║ Este bloque entrena un modelo de red neuronal GCN para predecir  ║
# ║ la severidad de cada CVE usando su contexto en el grafo          ║
# ╚══════════════════════════════════════════════════════════════════╝


# 🧠 Modelo GCN actualizado
class GCNProbabilidad(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim=128):
        super().__init__()
        self.conv1 = GCNConv(input_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        self.conv3 = GCNConv(hidden_dim, hidden_dim)
        self.conv4 = GCNConv(hidden_dim, hidden_dim)
        self.conv5 = GCNConv(hidden_dim, hidden_dim)
        self.dropout = torch.nn.Dropout(0.3)
        self.linear1 = torch.nn.Linear(hidden_dim, 64)
        self.linear2 = torch.nn.Linear(64, 1)

    def forward(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
        x = F.relu(self.conv2(x, edge_index))
        x = F.relu(self.conv3(x, edge_index))
        x = F.relu(self.conv4(x, edge_index))
        x = F.relu(self.conv5(x, edge_index))
        x = self.dropout(x)
        x = F.relu(self.linear1(x))
        return torch.sigmoid(self.linear2(x))

# --------------------------------------------------------------------------------
# Verificar si ya existe un modelo entrenado
# --------------------------------------------------------------------------------


device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = GCNProbabilidad(data.x.shape[1],hidden_dim=128).to(device)

if os.path.exists(model_file_path):
    print("Cargando modelo entrenado...")
    model.load_state_dict(torch.load(model_file_path), strict=False)
    model.eval()
else:
    print("Entrenando modelo desde cero...")

    features_originales = data.x.clone()

    # 📊 Simular 20 escenarios de fallos en 1-3 checks
    x_list = []
    y_list = []

    check_weights = {
        0: 4.5,  # CHK_01: Contraseñas seguras
        1: 4.8,  # CHK_02: Usuarios sin privilegios
        2: 4.6,  # CHK_03: Firewall activado
        3: 4.7,  # CHK_04: Antivirus activo
        4: 4.3,  # CHK_05: Bloqueo de pantalla
        5: 4.9,  # CHK_06: Deshabilitar USB
        6: 4.5,  # CHK_07: Registro de eventos
        7: 4.2,  # CHK_08: No modificar escritorio
        8: 4.6,  # CHK_09: Deshabilitar sitios web
        9: 4.1,  # CHK_10: Deshabilitar administrador tareas
        10: 5.0, # CHK_11: No abrir cmd
        11: 4.7, # CHK_12: No abrir PowerShell
        12: 4.8, # CHK_13: No modificar barra tareas
        13: 4.5, # CHK_14: No modificar accesos directos
        14: 5.1  # CHK_15: No acceder al registro
    }

    datasets_info = [
        [0, 4, 12],
        [1],
        [3, 5],
        [2, 6, 14],
        [8, 9],
        [10, 11],
        [7, 13],
        [1, 3],
        [0, 2, 13],
        [5, 6],
        [4],
        [0, 5, 9],
        [1, 10],
        [3, 14],
        [8],
        [6],
        [2, 4],
        [7],
        [11],
        [12, 13, 14],
        [0, 1, 2], [3, 4, 5], [6, 7, 8], [9, 10, 11], [12, 13, 14], [0, 2, 4], [1, 3, 5], [6, 9, 12], [7, 10, 13], [8, 11, 14],
        [0, 5, 9], [1, 4, 7], [2, 6, 12], [3, 8, 10], [4, 7, 13], [5, 11, 14], [6, 8, 9], [1, 3, 4], [2, 6, 10], [0, 5, 13],
        [1, 2, 7], [3, 4, 9], [0, 6, 11], [2, 5, 8], [3, 7, 14], [4, 10, 13], [6, 9, 11], [0, 2, 5], [7, 8, 12], [9, 10, 14],
        [1, 3, 6], [2, 4, 7], [8, 9, 13], [5, 11, 14], [6, 8, 10], [3, 5, 12], [4, 9, 13], [7, 8, 11], [1, 2, 6], [0, 4, 10],
        [1, 5, 12], [3, 7, 9], [2, 8, 14], [4, 6, 13], [5, 9, 10], [3, 6, 12], [7, 8, 11], [1, 2, 5], [0, 3, 9], [4, 7, 12],
        [6, 10, 13], [0, 2, 12], [1, 4, 8], [3, 5, 9], [7, 10, 14], [2, 6, 13], [8, 9, 11], [1, 3, 12], [5, 7, 13], [0, 6, 14],
        [4, 8, 11], [2, 5, 9], [7, 10, 12], [3, 6, 14], [1, 4, 7], [0, 2, 6], [8, 9, 13], [5, 7, 12], [3, 8, 10], [4, 6, 13],
        [1, 9, 12], [2, 3, 7], [5, 8, 10], [6, 7, 14], [0, 4, 11], [1, 2, 10], [3, 5, 12], [4, 7, 13], [8, 9, 14], [1, 6, 10],
        [2, 5, 13], [4, 8, 12], [3, 9, 10], [7, 8, 11], [0, 5, 14], [1, 2, 12], [3, 6, 11], [4, 7, 10], [5, 8, 13], [2, 6, 9],
        [1, 3, 10], [0, 4, 12], [7, 9, 13], [2, 3, 5], [1, 6, 14], [8, 10, 12], [4, 6, 9], [3, 5, 7], [0, 1, 12], [9, 11, 14],
        [2, 5, 10], [1, 3, 8], [4, 6, 13], [7, 9, 12], [0, 2, 5], [3, 7, 10], [4, 8, 11], [1, 2, 6], [5, 9, 14], [3, 4, 13],
        [0],            # Fallan CHK_01
        [3, 6],         # Fallan CHK_04 y CHK_07
        [1, 8, 10],     # Fallan CHK_02, CHK_09 y CHK_11
        [5, 12],        # Fallan CHK_06 y CHK_13
        [2],            # Fallan CHK_03
        [4, 7, 13],     # Fallan CHK_05, CHK_08 y CHK_14
        [9],            # Fallan CHK_10
        [11, 14],       # Fallan CHK_12 y CHK_15
        [0, 2, 5],      # Fallan CHK_01, CHK_03 y CHK_06
        [1, 4],         # Fallan CHK_02 y CHK_05
        [0, 1, 5], [2, 4], [3, 6], [7, 8, 9], [10, 11], [0, 3], [1, 5], [6, 12], [7, 13], [8, 14],
        [9, 10], [2, 12], [1, 6], [4, 13], [2, 10], [5, 9], [11, 14], [0, 4], [6, 7], [8, 13],
        [0, 2, 3], [1, 9], [4, 6, 7], [12, 14], [2, 6], [5, 13], [3, 9], [8, 11], [0, 4, 8], [5, 12],
        [7, 10], [3, 14], [1, 8], [4, 11], [6, 10], [0, 2, 5], [9, 12], [3, 13], [7, 14], [1, 4],
        [0, 7], [2, 8], [6, 11], [3, 10], [5, 9], [12, 14], [1, 3, 6], [7, 12], [2, 5, 13], [4, 10],
        [6, 8], [9, 14], [11, 13], [1, 4], [0, 3], [2, 7], [5, 10], [8, 12], [9, 11], [6, 13],
            [0, 2, 3], [1, 4], [5], [6, 7, 8], [9], [10, 11],
        [12, 13], [14, 0], [1, 2], [3, 4, 5], [6], [7, 8],
        [9, 10, 11], [12], [13, 14], [0, 1, 2], [3, 6], [7],
        [8, 9, 10], [11], [12, 13], [14, 1], [2, 3], [4, 5, 6],
        [7, 8], [9, 10], [11, 12], [13], [14], [0, 3, 6],
        [1, 4], [2, 5], [7, 10], [8, 11], [9, 12], [13, 0],
        [1, 5], [2, 6], [3, 7, 13], [4, 8]
    ]

    for fallos in datasets_info:
        x_mod = features_originales.clone()
        y_mod = torch.zeros(x_mod.size(0))
        cnt = defaultdict(int)
        for chk in fallos:
            for cve in checks[chk]: cnt[cve]+=1
        for cve, count in cnt.items():
            i=node_to_index[cve]
            x_mod[i,0]=10; x_mod[i,1]=1; x_mod[i,2]=count/5.0
            # ----- MODIFICACIÓN MÁS AGRESIVA -----
            if count==1:
                prob=0.70 # Podemos subir un poco más si queremos afectar también este caso
            elif count==2:
                prob=0.95 # Aumentado significativamente
            else: # count >= 3
                prob=min(0.99 + np.random.uniform(0.005, 0.01), 0.7) # Muy cerca de 1.0 y menos aleatorio
            # -------------------------------------
            y_mod[i]=prob
        x_list.append(x_mod); y_list.append(y_mod)


    # 🚀 Entrenamiento
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = GCNProbabilidad(input_dim=data.x.shape[1], hidden_dim=128).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001, weight_decay=1e-4)  # Reducción de lr

    # 🔁 Entrenamiento
    print("\n🚀 Entrenando modelo de probabilidad GCN con datasets sintéticos...")

    for fallos in [[0, 1, 2], [3, 4, 5], [6, 7, 8]]:
        x = features_originales.clone()
        y = torch.zeros(x.size(0))
        cve_count = defaultdict(int)
        for chk in fallos:
            for cve_id in checks[chk]:
                cve_count[cve_id] += 1
        for cve_id, count in cve_count.items():
            idx = node_to_index[cve_id]
            x[idx][0] = 10.0
            x[idx][1] = 1.0
            if count == 1:
                prob = 0.75
            elif count == 2:
                prob = 0.90
            else:
                prob = min(0.95 + np.random.uniform(0.03, 0.05), 1.0)
            y[idx] = prob
        x_list.append(x)
        y_list.append(y)

    for epoch in range(4000):
        model.train()
        optimizer.zero_grad()
        loss_total = 0
        for x_batch, y_batch in zip(x_list, y_list):
            out = model(x_batch.to(device), data.edge_index)
            loss = F.binary_cross_entropy(out.view(-1), y_batch.to(device).view(-1))
            loss.backward()
            loss_total += loss.item()
        optimizer.step()
        if epoch % 100 == 0:
            print(f"Epoch {epoch} | MSE Loss: {loss_total:.4f}")

    # ✅ Evaluación con el último escenario
    model.eval()
    x_eval = x_list[0].to(device)
    y_eval = y_list[0].to(device)
    out_eval = model(x_eval, data.edge_index.to(device)).detach()
    mse = F.mse_loss(out_eval, y_eval.view(-1, 1)).item()



    # 🔍 Mostrar resultados
    print("\n🚀 Entrenando GCN probabilístico...")
    for epoch in range(6000):
        model.train(); optimizer.zero_grad()
        total_loss=0
        for x_b,y_b in zip(x_list,y_list):
            out=model(x_b.to(device), data.edge_index.to(device)).view(-1)
            loss=F.binary_cross_entropy(out, y_b.to(device))
            loss.backward(); total_loss+=loss.item()
        optimizer.step()
        if epoch%100==0: print(f"Epoch {epoch} | Loss={total_loss:.4f}")

    # Guardar checkpoint
torch.save(model.state_dict(), model_file_path)

# -----------------------------------------------------------------------------
# 🛠 SIMULACIÓN DE FALLO DE MÚLTIPLES CHECKS: 
# Esta simulación simula un fallo en varios checks aumentando las características
# relacionadas con la severidad y el exploit, y muestra cómo cambia la probabilidad.
# -----------------------------------------------------------------------------

# 1. Definir qué checks quieres simular como fallados (usa una lista de índices)
checks_fallados_idx = [1]  # Cambia la lista para simular otros checks

# 2. Obtener los índices de los CVEs de esos checks
cves_afectados_idx = []
for check_idx in checks_fallados_idx:
    cves_afectados = checks[check_idx]
    cves_afectados_idx.extend([node_to_index[cve] for cve in cves_afectados])

# 3. Copiar las features originales
x_modificado = data.x.clone()

# 4. Simular el efecto de riesgo: aumentar cvss y activar exploit
for idx in cves_afectados_idx:
    x_modificado[idx][0] = torch.tensor(10.0)  # Aumentar cvss_score (esto es un ejemplo, valor máximo)
    x_modificado[idx][1] = torch.tensor(1.0)   # Activar exploit (esto es un ejemplo, riesgo más alto)

# 5. Pasar el nuevo grafo al modelo sin entrenarlo de nuevo
model.eval()

# Asegurarnos de que los datos y el modelo estén en el mismo dispositivo (CPU o GPU)
x_modificado = x_modificado.to(device)
data.edge_index = data.edge_index.to(device)

# Predicción antes de la simulación
pred_original = model(data.x.to(device), data.edge_index.to(device))

# Predicción después de la simulación
out_simulado = model(x_modificado, data.edge_index.to(device))
pred_simulada = out_simulado.view(-1).detach().cpu()  # Extraer las probabilidades predichas
pred_simulada = torch.clamp(pred_simulada, min=0.30)
# -----------------------------------------------------------------------------
# Mostrar resultados comparados (compara las probabilidades predichas antes y después de simular el fallo)
# -----------------------------------------------------------------------------

print(f"\n🔍 Resultados al simular que fallaron los checks {', '.join([f'CHK_{i+1}' for i in checks_fallados_idx])}")
for idx in cves_afectados_idx:
    original_probabilidad = pred_original[idx].item()  # Probabilidad antes de la simulación
    nueva_probabilidad = pred_simulada[idx].item()    # Probabilidad después de la simulación
    cve = nodes[idx]
    
    # Mostrar las probabilidades antes y después del fallo
    print(f"🛠 {cve}: probabilidad_original={original_probabilidad:.2f} → probabilidad_nueva={nueva_probabilidad:.2f}")
