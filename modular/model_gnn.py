import torch
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import GCNConv
from sklearn.preprocessing import LabelEncoder
from copy import deepcopy
import random

GRAVEDAD_NUMERICA = {
    "Baja": 0,
    "Media": 1,
    "Alta": 2,
    "Crítica": 3
}

# ==================== MODELO GNN CORREGIDO ====================
class RiskPredictionGNN(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim, output_dim=4):
        super().__init__()
        self.conv1 = GCNConv(input_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        # Capa para impacto con mayor capacidad
        self.impact_proj = torch.nn.Sequential(
            torch.nn.Linear(1, hidden_dim),
            torch.nn.ReLU(),
            torch.nn.Linear(hidden_dim, hidden_dim)
        )
        self.classifier = torch.nn.Linear(hidden_dim * 2, output_dim)
    
    def forward(self, data):
        x, edge_index = data.x, data.edge_index
        
        # Features normales
        x_conv = self.conv1(x, edge_index)
        x_conv = F.relu(x_conv)
        x_conv = self.conv2(x_conv, edge_index)
        x_conv = F.relu(x_conv)
        
        # Procesar impacto de checks (última feature)
        impact = x[:, -1].view(-1, 1)
        x_impact = self.impact_proj(impact)
        
        # Combinar
        x_combined = torch.cat([x_conv, x_impact], dim=1)
        return F.log_softmax(self.classifier(x_combined), dim=1)

# ==================== SISTEMA PRINCIPAL MEJORADO ====================
class CVESecuritySystem:
    def __init__(self, nodes, checks, device='cpu'):
        self.device = device
        self.nodes = nodes
        self.checks = checks
        self.num_checks = len(checks)
        self._initialize_encoders()
        self._generate_risk_labels()
        self._create_graph_structure()
        self._initialize_model()
        self.original_data = deepcopy(self.data)

    def _initialize_encoders(self):
        self.tipo_encoder = LabelEncoder()
        self.componente_encoder = LabelEncoder()
        self.gravedad_encoder = LabelEncoder()

        tipos = [info["Tipo"] for info in self.nodes.values()]
        componentes = [info["Componente"] for info in self.nodes.values()]
        gravedades = [info["Gravedad"] for info in self.nodes.values()]

        self.tipo_encoder.fit(tipos)
        self.componente_encoder.fit(componentes)
        self.gravedad_encoder.fit(gravedades)

    def _generate_risk_labels(self):
        self.risk_labels = torch.tensor([
            GRAVEDAD_NUMERICA[info["Gravedad"]]
            for info in self.nodes.values()
        ], dtype=torch.long, device=self.device)

    def _create_graph_structure(self):
        self.node_to_index = {cve: idx for idx, cve in enumerate(self.nodes)}
        self.node_features = torch.zeros((len(self.nodes), 4), dtype=torch.float)
        
        for cve, info in self.nodes.items():
            idx = self.node_to_index[cve]
            self.node_features[idx, 0] = self.tipo_encoder.transform([info["Tipo"]])[0] / len(self.tipo_encoder.classes_)
            self.node_features[idx, 1] = self.componente_encoder.transform([info["Componente"]])[0] / len(self.componente_encoder.classes_)
            self.node_features[idx, 2] = GRAVEDAD_NUMERICA[info["Gravedad"]] / 3.0
            self.node_features[idx, 3] = 0  # Impacto inicial

        # Aristas DIRIGIDAS (solo A->B)
        edges = []
        for check in self.checks:
            for i in range(len(check)-1):
                edges.append([self.node_to_index[check[i]], self.node_to_index[check[i+1]]])
        
        self.edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()

        # Matriz de impacto con pesos más altos
        self.check_cve_matrix = torch.zeros((self.num_checks, len(self.nodes)), dtype=torch.float)
        for check_idx, check_cves in enumerate(self.checks):
            for cve in check_cves:
                cve_idx = self.node_to_index[cve]
                peso = 5.0 if self.nodes[cve]["Gravedad"] == "Crítica" else 2.0
                self.check_cve_matrix[check_idx][cve_idx] = peso

        self.data = Data(
            x=self.node_features,
            edge_index=self.edge_index,
            y=self.risk_labels
        )

    def _initialize_model(self):
        self.model = RiskPredictionGNN(
            input_dim=self.node_features.shape[1],
            hidden_dim=32,
            output_dim=4
        ).to(self.device)
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=0.005, weight_decay=5e-4)

    def train(self, epochs=200):
        self.model.train()
        for epoch in range(epochs):
            # Simular bloques de checks fallados (más realista)
            failed = torch.zeros(self.num_checks, device=self.device)
            block_start = random.randint(0, self.num_checks - 3)
            failed[block_start:block_start+3] = 1  # Fallar 3 checks seguidos
            
            impact = torch.matmul(failed, self.check_cve_matrix)
            self.data.x[:, -1] = impact
            
            self.optimizer.zero_grad()
            out = self.model(self.data)
            loss = F.nll_loss(out, self.data.y)
            loss.backward()
            self.optimizer.step()
            
            if epoch % 20 == 0:
                pred = out.argmax(dim=1)
                acc = (pred == self.data.y).sum().item() / len(self.nodes)
                print(f'Epoch {epoch:>3} | Loss: {loss.item():.4f} | Accuracy: {acc:.2f}')

    def predict_risk_with_probabilities(self, failed_check_indices=None):
        current_data = deepcopy(self.original_data)
        
        if failed_check_indices is not None:
            failed = torch.zeros(self.num_checks, device=self.device)
            failed[failed_check_indices] = 1.0
            impact = torch.matmul(failed, self.check_cve_matrix)
            current_data.x[:, -1] = impact
        
        self.model.eval()
        with torch.no_grad():
            out = self.model(current_data)
            prob = F.softmax(out, dim=1)
            
            # Forzar que no disminuya la gravedad original
            for i in range(len(prob)):
                original_grav = self.risk_labels[i].item()
                if prob[i].argmax() < original_grav:
                    prob[i] = torch.zeros_like(prob[i])
                    prob[i][original_grav] = 1.0
                else:
                    prob[i] = prob[i] / prob[i].sum()  # Renormalizar
            
            # Convertir a formato legible
            results = []
            for i, p in enumerate(prob.cpu().numpy()):
                results.append({
                    "CVE": list(self.nodes.keys())[i],
                    "Prediccion": ["Baja", "Media", "Alta", "Crítica"][p.argmax()],
                    "Probabilidades": {
                        "Baja": f"{p[0]*100:.1f}%",
                        "Media": f"{p[1]*100:.1f}%",
                        "Alta": f"{p[2]*100:.1f}%",
                        "Crítica": f"{p[3]*100:.1f}%"
                    }
                })
            return results

    def compare_predictions(self, failed_check_indices):
        print("\n=== COMPARACIÓN PREDICCIONES ===")
        print(f"Checks fallados: {failed_check_indices}\n")
        
        original = self.predict_risk_with_probabilities()
        updated = self.predict_risk_with_probabilities(failed_check_indices)
        
        # Filtrar solo CVEs afectados por los checks fallados
        affected_cves = set()
        for check_idx in failed_check_indices:
            affected_cves.update(self.checks[check_idx])
        
        print("{:<15} {:<10} {:<15} {:<10} {:<15}".format(
            "CVE", "Original", "Actualizado", "Δ Prob Crítica", "Checks Relacionados"))
        print("-"*70)
        
        for orig, upd in zip(original, updated):
            cve = orig['CVE']
            if cve in affected_cves:
                delta = float(upd['Probabilidades']['Crítica'][:-1]) - float(orig['Probabilidades']['Crítica'][:-1])
                related_checks = [i for i, cves in enumerate(self.checks) if cve in cves]
                print("{:<15} {:<10} {:<10} {:<15.1f}% {}".format(
                    cve,
                    orig['Prediccion'],
                    upd['Prediccion'],
                    delta,
                    related_checks
                ))

# ==================== EJECUCIÓN ====================
if __name__ == "__main__":
    # Datos de ejemplo
    nodes = {
        # Críticas
        "CVE-2020-0796": {
            "Tipo": "RCE",
            "Componente": "SMBv3 (Windows)",
            "Gravedad": "Crítica"
        },
        "CVE-2022-21907": {
            "Tipo": "RCE",
            "Componente": "HTTP.sys (Windows)",
            "Gravedad": "Crítica"
        },
        "CVE-2012-0002": {
            "Tipo": "RCE",
            "Componente": "RDP (Windows)",
            "Gravedad": "Crítica"
        },
        "CVE-2014-6332": {
            "Tipo": "RCE",
            "Componente": "OLE (Windows)",
            "Gravedad": "Crítica"
        },
        "CVE-2017-0143": {
            "Tipo": "RCE",
            "Componente": "SMBv1 subcomponente (Windows)",
            "Gravedad": "Crítica"
        },
        "CVE-2021-40444": {
            "Tipo": "RCE",
            "Componente": "MSHTML (Windows)",
            "Gravedad": "Crítica"
        },
        "CVE-2017-8464": {
            "Tipo": "RCE",
            "Componente": "Windows Shell",
            "Gravedad": "Crítica"
        },
        "CVE-2003-0533": {
            "Tipo": "RCE",
            "Componente": "LSASS (Windows)",
            "Gravedad": "Crítica"
        },
        "CVE-2022-41128": {
            "Tipo": "RCE",
            "Componente": "Chromium V8 (Windows)",
            "Gravedad": "Crítica"
        },

        # Altas
        "CVE-2014-4113": {
            "Tipo": "Elevación de Privilegios",
            "Componente": "Win32k (Windows)",
            "Gravedad": "Alta"
        },
        "CVE-2016-7255": {
            "Tipo": "Elevación de Privilegios",
            "Componente": "Kernel (Windows)",
            "Gravedad": "Alta"
        },
        "CVE-2023-21768": {
            "Tipo": "Elevación de Privilegios",
            "Componente": "Win32k (Windows)",
            "Gravedad": "Alta"
        },
        "CVE-2022-41099": {
            "Tipo": "Security Feature Bypass",
            "Componente": "SmartScreen (Windows)",
            "Gravedad": "Alta"
        },
        "CVE-2020-0601": {
            "Tipo": "Spoofing",
            "Componente": "Criptografía (Windows)",
            "Gravedad": "Alta"
        },
        "CVE-2022-41040": {
            "Tipo": "SSRF/Escalación",
            "Componente": "Exchange (Windows)",
            "Gravedad": "Alta"
        },
        "CVE-2016-3309": {
            "Tipo": "Sandbox Bypass",
            "Componente": "Adobe Flash + OS (Windows)",
            "Gravedad": "Alta"
        },
        "CVE-2021-34473": {
            "Tipo": "SSRF",
            "Componente": "Microsoft Exchange (Windows)",
            "Gravedad": "Alta"
        },
        "CVE-2021-34523": {
            "Tipo": "Elevación de Privilegios",
            "Componente": "Exchange (Windows)",
            "Gravedad": "Alta"
        },

        # Medias
        "CVE-2010-2568": {
            "Tipo": "RCE",
            "Componente": "LNK (Windows)",
            "Gravedad": "Media"
        },
        "CVE-2015-0096": {
            "Tipo": "RCE",
            "Componente": "Shell Link (Windows)",
            "Gravedad": "Media"
        },
        "CVE-2018-8174": {
            "Tipo": "RCE",
            "Componente": "VBScript (Windows)",
            "Gravedad": "Media"
        },
        "CVE-2003-0352": {
            "Tipo": "RCE",
            "Componente": "DCOM RPC (Windows)",
            "Gravedad": "Media"
        },
        "CVE-2019-1402": {
            "Tipo": "RCE",
            "Componente": "Windows Shell",
            "Gravedad": "Media"
        },
        "CVE-2019-1069": {
            "Tipo": "Elevación de Privilegios",
            "Componente": "Task Scheduler (Windows)",
            "Gravedad": "Media"
        },
        "CVE-2020-1325": {
            "Tipo": "Elevación de Privilegios",
            "Componente": "PowerShell Remote Jobs (Windows)",
            "Gravedad": "Media"
        },
        "CVE-2021-1675": {
            "Tipo": "RCE/EoP",
            "Componente": "Print Spooler (Windows)",
            "Gravedad": "Media"
        },
        "CVE-2020-1350": {
            "Tipo": "RCE",
            "Componente": "DNS (Windows) - SIGRed",
            "Gravedad": "Media"
        },

        # Bajas
        "CVE-2021-36934": {
            "Tipo": "Elevación de Privilegios",
            "Componente": "Hive (Windows)",
            "Gravedad": "Baja"
        },
        "CVE-2015-1701": {
            "Tipo": "Elevación de Privilegios",
            "Componente": "Win32k (Windows)",
            "Gravedad": "Baja"
        },
        "CVE-2019-1388": {
            "Tipo": "Elevación de Privilegios",
            "Componente": "Cert Dialog (Windows)",
            "Gravedad": "Baja"
        },
        "CVE-2022-22047": {
            "Tipo": "Elevación de Privilegios",
            "Componente": "CSRSS (Windows)",
            "Gravedad": "Baja"
        },
        "CVE-2013-3660": {
            "Tipo": "Elevación de Privilegios",
            "Componente": "NDProxy (Windows)",
            "Gravedad": "Baja"
        },
        "CVE-2016-0099": {
            "Tipo": "Elevación de Privilegios",
            "Componente": "Secondary Logon (Windows)",
            "Gravedad": "Baja"
        },
        "CVE-2021-34484": {
            "Tipo": "Elevación de Privilegios",
            "Componente": "User Profile Service (Windows)",
            "Gravedad": "Baja"
        },
        "CVE-2018-0992": {
            "Tipo": "RCE",
            "Componente": "PowerShell Editor Services (Windows)",
            "Gravedad": "Baja"
        },
        "CVE-2019-1040": {
            "Tipo": "Tampering",
            "Componente": "NTLM (Windows)",
            "Gravedad": "Baja"
        },
        "CVE-2017-0144": {
            "Tipo": "RCE",
            "Componente": "SMBv1 (Windows)",
            "Gravedad": "Crítica"  # Ajusta según sea necesario
        },
        "CVE-2019-0708": {
            "Tipo": "RCE",  # Remote Code Execution
            "Componente": "Remote Desktop Protocol (RDP)",
            "Gravedad": "Crítica"
        },
        "CVE-2020-1472": {
            "Tipo": "Elevación de Privilegios",  # También se considera fallo de autenticación
            "Componente": "Netlogon (Windows Domain Controller)",
            "Gravedad": "Crítica"
        },
        "CVE-2022-30190": {
            "Tipo": "RCE",  # Remote Code Execution
            "Componente": "Microsoft Support Diagnostic Tool (MSDT)",
            "Gravedad": "Crítica"
        },
        # Críticas
        "CVE-2021-34527": {  # PrintNightmare
            "Tipo": "RCE",
            "Componente": "Print Spooler (Windows)",
            "Gravedad": "Crítica"
        },
        "CVE-2022-26925": {  # Windows LSA Spoofing
            "Tipo": "Elevación de Privilegios",
            "Componente": "Local Security Authority (Windows)",
            "Gravedad": "Alta"
        },
        "CVE-2020-16898": {  # Bad Neighbor
            "Tipo": "RCE",
            "Componente": "TCP/IP Stack (Windows)",
            "Gravedad": "Crítica"
        },
        "CVE-2023-23397": {  # Outlook EoP
            "Tipo": "Elevación de Privilegios",
            "Componente": "Microsoft Outlook",
            "Gravedad": "Crítica"
        },
        
        # Altas/Medias
        "CVE-2012-0158": {  # MSCOMCTL ActiveX
            "Tipo": "RCE",
            "Componente": "MSCOMCTL.OCX",
            "Gravedad": "Crítica"
        },
        "CVE-2021-26411": {  # IE Memory Corruption
            "Tipo": "RCE",
            "Componente": "Internet Explorer",
            "Gravedad": "Crítica"
        },
        "CVE-2021-44228": {  # Log4Shell
            "Tipo": "RCE",
            "Componente": "Apache Log4j",
            "Gravedad": "Crítica"
        },
        "CVE-2023-28252": {  # Windows CLFS EoP
            "Tipo": "Elevación de Privilegios",
            "Componente": "Common Log File System (Windows)",
            "Gravedad": "Alta"
        },
        
        # Otras
        "CVE-2017-5638": {  # Apache Struts
            "Tipo": "RCE",
            "Componente": "Apache Struts",
            "Gravedad": "Crítica"
        },
        "CVE-2021-45046": {  # Log4Shell variante
            "Tipo": "RCE",
            "Componente": "Apache Log4j",
            "Gravedad": "Crítica"
        },
        "CVE-2014-0160": {  # Heartbleed
            "Tipo": "Information Disclosure",
            "Componente": "OpenSSL",
            "Gravedad": "Alta"
        }
    }
    
    checks = [
        # CHK_01 (Contraseñas seguras)
        [
            "CVE-2017-0144",  # EternalBlue
            "CVE-2019-0708",  # BlueKeep
            "CVE-2020-1472",  # Zerologon
            "CVE-2020-0796",  # SMBGhost
            "CVE-2022-21907", # HTTP.sys RCE
            "CVE-2022-30190", # Follina - MSDT RCE
        ],
        # CHK_02 (Usuarios sin privilegios innecesarios)
        [
            "CVE-2019-0708",  # BlueKeep
            "CVE-2021-34527", # PrintNightmare
            "CVE-2022-26925", # Windows LSA Spoofing
            "CVE-2014-4113",  # Win32k.sys EoP
            "CVE-2016-7255",  # Kernel EoP
            "CVE-2021-36934", # HiveNightmare
        ],
        # CHK_03 (Firewall activado)
        [
            "CVE-2017-0144",  # EternalBlue
            "CVE-2021-34527", # PrintNightmare
            "CVE-2020-16898", # Bad Neighbor
            "CVE-2003-0352",  # DCOM RPC RCE
            "CVE-2003-0533",  # LSASS RCE (Sasser)
            "CVE-2020-0796",  # SMBGhost
        ],
        # CHK_04 (Antivirus activo)
        [
            "CVE-2020-1472",  # Zerologon
            "CVE-2020-16898", # Bad Neighbor
            "CVE-2023-23397", # Outlook EoP
            "CVE-2012-0158",  # MSCOMCTL ActiveX
            "CVE-2014-6332",  # OLE VBScript EoP
            "CVE-2018-8174",  # Double Kill
        ],
        # CHK_05 (Bloqueo de pantalla activo)
        [
            "CVE-2022-30190", # Follina - MSDT RCE
            "CVE-2022-26925", # Windows LSA Spoofing
            "CVE-2022-22047", # Windows CSRSS EoP
            "CVE-2023-21768", # Win32k EoP
            "CVE-2022-41099", # SmartScreen Bypass
            "CVE-2022-41040", # ProxyNotShell (Exchange)
        ],
        # CHK_06 (Deshabilitar USB no autorizados)
        [
            "CVE-2019-0708",  # BlueKeep
            "CVE-2022-30190", # Follina - MSDT RCE
            "CVE-2021-26411", # IE Memory Corruption
            "CVE-2010-2568",  # LNK vulnerability (Stuxnet)
            "CVE-2015-0096",  # Shell Link Path Overflow
            "CVE-2017-8464",  # Windows Shell RCE
        ],
        # CHK_07 (Registro de eventos activado y con retención adecuada)
        [
            "CVE-2017-0144",  # EternalBlue
            "CVE-2021-26411", # IE Memory Corruption
            "CVE-2021-44228", # Log4Shell
            "CVE-2020-0601",  # CurveBall
            "CVE-2021-40444", # MSHTML RCE
            "CVE-2015-1701",  # Win32k EoP
        ],
        # CHK_08 (No permitir que modifiquen el escritorio)
        [
            "CVE-2020-1472",  # Zerologon
            "CVE-2022-22047", # Windows CSRSS EoP
            "CVE-2023-28252", # Windows CLFS EoP
            "CVE-2014-4113",  # Win32k.sys EoP
            "CVE-2016-3309",  # Adobe Flash + OS sandbox bypass
            "CVE-2019-1388",  # Cert Dialog EoP
        ],
        # CHK_09 (Deshabilitar ciertos sitios web)
        [
            "CVE-2021-34527", # PrintNightmare
            "CVE-2023-23397", # Outlook Elevation of Privilege
            "CVE-2021-44228", # Log4Shell
            "CVE-2022-41128", # Chromium V8 RCE
            "CVE-2021-34473", # Exchange SSRF
            "CVE-2021-34523", # Exchange EoP
        ],
        # CHK_10 (Deshabilitar el administrador de tareas)
        [
            "CVE-2020-16898", # Bad Neighbor
            "CVE-2022-30190", # Follina - MSDT RCE
            "CVE-2014-0160",  # Heartbleed
            "CVE-2012-0002",  # RDP RCE
            "CVE-2013-3660",  # NDProxy EoP
            "CVE-2019-0708",  # BlueKeep
        ],
        # CHK_11 (No abrir cmd)
        [
            "CVE-2022-26925", # Windows LSA Spoofing
            "CVE-2022-22047", # Windows CSRSS EoP
            "CVE-2017-5638",  # Apache Struts RCE
            "CVE-2016-0099",  # Secondary Logon EoP
            "CVE-2017-0143",  # EternalBlue exploit subcomponent
            "CVE-2019-1402",  # Windows Shell RCE
        ],
        # CHK_12 (No abrir PowerShell)
        [
            "CVE-2023-23397", # Outlook Elevation of Privilege
            "CVE-2021-26411", # IE Memory Corruption
            "CVE-2014-0160",  # Heartbleed
            "CVE-2018-0992",  # PowerShell Editor Services RCE
            "CVE-2020-1325",  # PowerShell Remote Jobs
            "CVE-2021-34484", # User Profile Service EoP
        ],
        # CHK_13 (No permitir que modifiquen la barra de tareas)
        [
            "CVE-2023-28252", # Windows CLFS EoP
            "CVE-2017-5638",  # Apache Struts RCE
            "CVE-2021-45046", # Variante de Log4Shell
            "CVE-2014-4113",  # Win32k.sys EoP
            "CVE-2021-1675",  # PrintNightmare variante inicial
            "CVE-2019-1069",  # Task Scheduler EoP
        ],
        # CHK_14 (No permitir que modifiquen los accesos directos)
        [
            "CVE-2021-44228", # Log4Shell
            "CVE-2014-0160",  # Heartbleed
            "CVE-2021-45046", # Variante Log4Shell
            "CVE-2010-2568",  # LNK Shortcut
            "CVE-2015-0096",  # Shell Link
            "CVE-2020-1472",  # Zerologon
        ],
        # CHK_15 (Evitar que los usuarios accedan al registro)
        [
            "CVE-2017-0144",  # EternalBlue
            "CVE-2023-28252", # Windows CLFS EoP
            "CVE-2021-45046", # Variante Log4Shell
            "CVE-2020-1350",  # SIGRed
            "CVE-2021-34484", # User Profile Service EoP
            "CVE-2019-1040",  # NTLM Tampering
        ]
    ]
    
    # 1. Inicialización
    security_system = CVESecuritySystem(nodes, checks)
    
    # 2. Entrenamiento
    print("Entrenando modelo...")
    security_system.train(epochs=200)
    
    # 3. Comparar predicciones
    security_system.compare_predictions([0, 1])  # Ejemplo: checks 0 y 1 fallados