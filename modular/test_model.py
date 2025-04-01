import torch
from model_gnn import CVESecuritySystem  # Cambia esta línea

def test_model():
    print("=== PRUEBA DEL MODELO ===")
    
    # Datos mínimos para prueba
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
    
    # Cargar sistema (usando el método de clase)
    system = CVESecuritySystem.load_full_model(
        "modular/cve_full_model.pt",
        nodes,
        checks
    )
    
    # Resto de tu código de prueba...
    test_cases = [
        ([0], "Solo check 0 fallado"),
        ([1], "Solo check 1 fallado"),
        ([0, 1], "Ambos checks fallados")
    ]
    
    for checks_fallidos, desc in test_cases:
        system.update_failed_checks(checks_fallidos)
        pred = system.predict_risk()
        
        print(f"\nCaso: {desc}")
        for cve, riesgo in zip(nodes.keys(), pred):
            print(f"{cve}: {['Bajo', 'Medio', 'Alto', 'Crítico'][riesgo]}")

if __name__ == "__main__":
    test_model()