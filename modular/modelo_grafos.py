import torch
from torch_geometric.data import Data
import pandas as pd
import torch.nn.functional as F
from torch_geometric.nn import GCNConv
import random

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
        "CVE-2017-0144",  # EternalBlue
        "CVE-2019-0708",  # BlueKeep
        "CVE-2020-1472",  # Zerologon
        "CVE-2020-0796",  # SMBGhost
        "CVE-2022-21907",  # HTTP.sys RCE
        "CVE-2022-30190"  # Follina (MSDT RCE)
    ],

    # CHK_02 (Usuarios sin privilegios innecesarios)
    [
        "CVE-2019-0708",  # BlueKeep
        "CVE-2021-34527",  # PrintNightmare
        "CVE-2022-26925",  # Windows LSA Spoofing
        "CVE-2014-4113",  # Win32k.sys EoP
        "CVE-2016-7255",  # Kernel EoP
        "CVE-2021-36934"  # HiveNightmare
    ],

    # CHK_03 (Firewall activado)
    [
        "CVE-2017-0144",  # EternalBlue
        "CVE-2021-34527",  # PrintNightmare
        "CVE-2020-16898",  # Bad Neighbor (TCP/IP RCE)
        "CVE-2003-0352",  # DCOM RPC RCE
        "CVE-2003-0533",  # LSASS RCE (Sasser)
        "CVE-2020-0796"   # SMBGhost
    ],

    # CHK_04 (Antivirus activo)
    [
        "CVE-2020-1472",  # Zerologon
        "CVE-2020-16898",  # Bad Neighbor
        "CVE-2023-23397",  # Outlook EoP
        "CVE-2012-0158",  # MSCOMCTL ActiveX
        "CVE-2014-6332",  # OLE VBScript EoP
        "CVE-2018-8174"   # Double Kill (VBScript RCE)
    ],

    # CHK_05 (Bloqueo de pantalla activo)
    [
        "CVE-2022-30190",  # Follina (MSDT RCE)
        "CVE-2022-26925",  # Windows LSA Spoofing
        "CVE-2022-22047",  # Windows CSRSS EoP
        "CVE-2023-21768",  # Win32k EoP
        "CVE-2022-41099",  # SmartScreen Security Feature Bypass
        "CVE-2022-41040"  # ProxyNotShell (Exchange)
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

# --------------------------------------------------------------------------------
# Cargar características desde cve_features.csv
# --------------------------------------------------------------------------------
df = pd.read_csv("cve_features.csv")
severity_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
features = []
labels = []
for cve_id in nodes:
    row = df[df["cve_id"] == cve_id].iloc[0]
    features.append([row["cvss_score"], row["has_exploit"]])
    labels.append(severity_map[row["severity"]])

x = torch.tensor(features, dtype=torch.float)
y = torch.tensor(labels, dtype=torch.long)

# Crear el objeto Data de PyTorch Geometric
data = Data(x=x, edge_index=edge_index, y=y)

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


# Definir el modelo GCN
class GCN(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim, output_dim):
        super(GCN, self).__init__()
        self.conv1 = GCNConv(input_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, output_dim)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.conv2(x, edge_index)
        return x


print("\n: 🔧 Iniciando entrenamiento...")

# Crear máscaras de entrenamiento y prueba
num_nodes = data.num_nodes
train_mask = torch.zeros(num_nodes, dtype=torch.bool)
test_mask = torch.zeros(num_nodes, dtype=torch.bool)

# Seleccionar 40 nodos para entrenamiento, 11 para prueba (manteniendo proporciones)
indices = list(range(num_nodes))
random.seed(42)
random.shuffle(indices)
train_indices = indices[:40]
test_indices = indices[40:]

train_mask[train_indices] = True
test_mask[test_indices] = True

data.train_mask = train_mask
data.test_mask = test_mask

# Inicializar modelo, optimizador y parámetros
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = GCN(input_dim=data.x.shape[1], hidden_dim=16, output_dim=4).to(device)
data = data.to(device)
optimizer = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)

# Entrenamiento
print("\n🚀 Entrenando modelo GCN...")
for epoch in range(201):
    model.train()
    optimizer.zero_grad()
    out = model(data.x, data.edge_index)
    loss = F.cross_entropy(out[data.train_mask], data.y[data.train_mask])
    loss.backward()
    optimizer.step()

    if epoch % 50 == 0:
        print(f"Epoch {epoch} | Loss: {loss.item():.4f}")

# Evaluación
model.eval()
out = model(data.x, data.edge_index)
pred = out.argmax(dim=1)

correct = int((pred[data.test_mask] == data.y[data.test_mask]).sum())
total = int(data.test_mask.sum())
acc = correct / total

print("\n✅ Evaluación final:")
print(f"- Precisión en test: {acc*100:.2f}%")
print(f"- Clases verdaderas : {data.y[data.test_mask].tolist()}")
print(f"- Predicciones      : {pred[data.test_mask].tolist()}")


# ╔══════════════════════════════════════════════════════════════════╗
# ║                 ⚠️ SIMULACIÓN DE FALLO DE UN CHECK              ║
# ║ Modifica las características de los CVEs relacionados a un      ║
# ║ check y muestra cómo cambia su severidad predicha               ║
# ╚══════════════════════════════════════════════════════════════════╝

# 1. Definir qué check quieres simular como fallado (usa su índice)
check_fallado_idx = 0  # CHK_01 → cambia a 1, 2, etc. si quieres simular otro

# 2. Obtener los índices de los CVEs de ese check
cves_afectados = checks[check_fallado_idx]
cves_afectados_idx = [node_to_index[cve] for cve in cves_afectados]

# 3. Copiar las features originales (sin alterar el grafo real)
x_modificado = data.x.clone()

# 4. Simular el efecto de riesgo: aumentar cvss y activar exploit
for idx in cves_afectados_idx:
    x_modificado[idx][0] = torch.tensor(8.0)  # cvss_score máximo
    x_modificado[idx][1] = torch.tensor(1.0)   # activar has_exploit

# 5. Pasar el nuevo grafo al modelo sin entrenarlo de nuevo
model.eval()
out_simulado = model(x_modificado, data.edge_index)
pred_simulada = out_simulado.argmax(dim=1)

# 6. Mostrar resultados comparados
print("\n🔍 Resultados al simular que falló CHK_{:02d}".format(check_fallado_idx + 1))
for idx in cves_afectados_idx:
    original = data.y[idx].item()
    pred_anterior = pred[idx].item()
    nueva = pred_simulada[idx].item()
    cve = nodes[idx]
    print(f"🛠 {cve}: clase_real={original} | antes={pred_anterior} → ahora={nueva}")


# ╔══════════════════════════════════════════════════════════════════╗
# ║              ⚙️ FUNCIONES DE MANEJO CVE                          ║
# ╚══════════════════════════════════════════════════════════════════╝


def actualizar_cve_features(
    checks_afectados,
    intensidad=1.5,
    modo="aumentar",
    ruta_original="cve_features_original.csv",
    ruta_modificada="cve_features.csv",
):
    """
    Crea una copia del archivo original y modifica el riesgo de los CVEs afectados por los checks.

    Parámetros:
    - checks_afectados (list[int]): Índices de los checks fallados o corregidos (0 a N).
    - intensidad (float): Cuánto modificar el cvss_score (por defecto +1.5).
    - modo (str): "aumentar" o "reducir" para subir/bajar el score.
    - ruta_original (str): Ruta al archivo base que nunca se modifica.
    - ruta_modificada (str): Ruta donde se guarda la copia modificada.
    """
    if checks is None:
        raise ValueError("❌ Debes proporcionar la estructura 'checks' con los CVEs asignados por check.")

    # Leer desde el archivo original
    df = pd.read_csv(ruta_original)

    # Modificar CVEs afectados por los checks
    for chk_idx in checks_afectados:
        if 0 <= chk_idx < len(checks):
            for cve in checks[chk_idx]:
                match = df[df["cve_id"] == cve]
                if not match.empty:
                    i = match.index[0]
                    if modo == "aumentar":
                        df.at[i, "cvss_score"] = min(df.at[i, "cvss_score"] + intensidad, 10.0)
                        df.at[i, "has_exploit"] = 1.0
                    elif modo == "reducir":
                        df.at[i, "cvss_score"] = max(df.at[i, "cvss_score"] - intensidad, 0.0)

    # Guardar archivo modificado
    df.to_csv(ruta_modificada, index=False)
    print(f"✅ Archivo {ruta_modificada} actualizado (modo: {modo}) con checks {checks_afectados}.")


def generar_tensor_y_predecir_desde_csv(model, edge_index, csv_path="cve_features.csv", device="cpu"):
    """
    Lee el archivo cve_features.csv, genera el tensor x y devuelve las nuevas predicciones.

    Parámetros:
    - csv_path: ruta al archivo CSV con los features de los CVEs
    - model: modelo GCN ya entrenado
    - edge_index: conexiones del grafo
    - device: "cpu" o "cuda"

    Retorna:
    - pred: tensor con clases de severidad actualizadas (0=LOW, ..., 3=CRITICAL)
    - x: tensor de features actualizado
    """
    df = pd.read_csv(csv_path)
    x = torch.tensor(df[["cvss_score", "has_exploit"]].values, dtype=torch.float)

    model.eval()
    with torch.no_grad():
        out = model(x.to(device), edge_index.to(device))
        pred = out.argmax(dim=1)

    return pred, x


# ╔══════════════════════════════════════════════════════════════════╗
# ║              ⚙️ TESTING                                          ║
# ╚══════════════════════════════════════════════════════════════════╝

print("Testeando actualizar cve")
checks_fallados_test = [0]
actualizar_cve_features(checks_fallados_test)

pred_actualizadas, x_actualizadas = generar_tensor_y_predecir_desde_csv(
    model=model,
    edge_index=data.edge_index,  # o edge_index si lo tienes suelto
    device=device
)

# Mostrar las nuevas severidades predichas por índice
print("\n🔢 Nuevas severidades predichas por el modelo:")
for idx, clase in enumerate(pred_actualizadas):
    print(f"{idx:02d} - {nodes[idx]}: Severidad = {clase.item()}")

# Si quieres comparar contra data.y (severidad base):
print("\n📊 Comparación con severidades originales:")
for idx in range(len(nodes)):
    antes = data.y[idx].item()
    despues = pred_actualizadas[idx].item()
    flecha = "↑" if despues > antes else ("↓" if despues < antes else "→")
    print(f"{nodes[idx]}: antes={antes} {flecha} ahora={despues}")


print("PRED ACTUALIZADAS")
print(pred_actualizadas)
print("X_ACTUALIZADAS")
print(x_actualizadas)