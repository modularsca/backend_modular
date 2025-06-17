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

    # info de cves
    cves_info = [
    {
        "cve_name": "CVE-2017-0144",
        "description": "EternalBlue, parte del exploit kit MS17-010, es una vulnerabilidad de ejecución remota de código en el protocolo Server Message Block (SMBv1) de Windows.",
        "impact_if_unpatched": "Permite a atacantes ejecutar código arbitrario en sistemas vulnerables, facilitando la propagación de malware como WannaCry y NotPetya, el robo de datos y el control total del sistema."
    },
    {
        "cve_name": "CVE-2019-0708",
        "description": "BlueKeep es una vulnerabilidad de ejecución remota de código en los Servicios de Escritorio Remoto (RDP) de Windows.",
        "impact_if_unpatched": "Permite a atacantes no autenticados ejecutar código arbitrario en el servidor RDP, lo que podría llevar al control total del sistema y la propagación de gusanos."
    },
    {
        "cve_name": "CVE-2020-1472",
        "description": "Zerologon es una vulnerabilidad de elevación de privilegios en el protocolo Netlogon de Windows Server.",
        "impact_if_unpatched": "Permite a un atacante no autenticado obtener privilegios de administrador de dominio, comprometiendo toda la infraestructura de Active Directory."
    },
    {
        "cve_name": "CVE-2020-0796",
        "description": "SMBGhost es una vulnerabilidad de ejecución remota de código en el protocolo Server Message Block (SMBv3) de Windows.",
        "impact_if_unpatched": "Permite a un atacante ejecutar código arbitrario en el servidor SMB, llevando al control total del sistema."
    },
    {
        "cve_name": "CVE-2022-21907",
        "description": "HTTP.sys RCE es una vulnerabilidad de ejecución remota de código en el controlador HTTP de Windows (HTTP.sys).",
        "impact_if_unpatched": "Permite a un atacante remoto ejecutar código arbitrario en el sistema afectado, lo que puede resultar en una denegación de servicio o el control completo del servidor web."
    },
    {
        "cve_name": "CVE-2022-30190",
        "description": "Follina (MSDT RCE) es una vulnerabilidad de ejecución remota de código en la herramienta de diagnóstico de soporte de Microsoft (MSDT) que se activa a través de archivos de Microsoft Office.",
        "impact_if_unpatched": "Permite a un atacante ejecutar código arbitrario simplemente haciendo que la víctima abra un documento malicioso, lo que podría conducir a la instalación de programas, visualización, cambio o eliminación de datos, o la creación de nuevas cuentas con todos los derechos de usuario."
    },
    {
        "cve_name": "CVE-2021-34527",
        "description": "PrintNightmare es una vulnerabilidad de ejecución remota de código y elevación de privilegios en el servicio Windows Print Spooler.",
        "impact_if_unpatched": "Permite a un atacante ejecutar código arbitrario con privilegios SYSTEM o añadir drivers de impresora maliciosos, comprometiendo el sistema y la red."
    },
    {
        "cve_name": "CVE-2022-26925",
        "description": "Windows LSA Spoofing es una vulnerabilidad de suplantación en el Subsistema de Autoridad de Seguridad Local (LSA) de Windows.",
        "impact_if_unpatched": "Permite a un atacante engañar al LSA para que utilice un controlador de dominio comprometido para la autenticación, lo que podría conducir a la ejecución remota de código."
    },
    {
        "cve_name": "CVE-2014-4113",
        "description": "Win32k.sys EoP es una vulnerabilidad de elevación de privilegios en el controlador del subsistema Win32k de Windows.",
        "impact_if_unpatched": "Permite a un atacante local elevar sus privilegios de usuario estándar a privilegios de SYSTEM, obteniendo control total sobre el sistema."
    },
    {
        "cve_name": "CVE-2016-7255",
        "description": "Kernel EoP es una vulnerabilidad de elevación de privilegios en el kernel de Windows.",
        "impact_if_unpatched": "Permite a un atacante local elevar sus privilegios a SYSTEM, lo que le da control total sobre el sistema operativo."
    },
    {
        "cve_name": "CVE-2021-36934",
        "description": "HiveNightmare (o SeriousSAM) es una vulnerabilidad que permite el acceso a los archivos SAM, SYSTEM y SECURITY de Windows, que contienen hashes de contraseñas y claves de cifrado.",
        "impact_if_unpatched": "Permite a atacantes locales leer y copiar los archivos del registro del sistema, lo que podría llevar al robo de credenciales y la elevación de privilegios."
    },
    {
        "cve_name": "CVE-2020-16898",
        "description": "Bad Neighbor (TCP/IP RCE) es una vulnerabilidad de ejecución remota de código en la pila TCP/IP de Windows.",
        "impact_if_unpatched": "Permite a un atacante remoto ejecutar código arbitrario en el sistema afectado con privilegios elevados, lo que podría resultar en un compromiso completo del sistema."
    },
    {
        "cve_name": "CVE-2003-0352",
        "description": "DCOM RPC RCE es una vulnerabilidad de ejecución remota de código en el servicio DCOM RPC de Windows.",
        "impact_if_unpatched": "Permite a un atacante no autenticado ejecutar código arbitrario en el sistema vulnerable, lo que puede llevar al control total del sistema."
    },
    {
        "cve_name": "CVE-2003-0533",
        "description": "LSASS RCE (Sasser) es una vulnerabilidad de ejecución remota de código en el proceso LSASS (Local Security Authority Subsystem Service) de Windows.",
        "impact_if_unpatched": "Permitió al gusano Sasser propagarse rápidamente, causando denegación de servicio y ejecución de código arbitrario en sistemas vulnerables, llevando al reinicio de los equipos."
    },
    {
        "cve_name": "CVE-2023-23397",
        "description": "Outlook Elevation of Privilege es una vulnerabilidad en Microsoft Outlook que permite la elevación de privilegios a través de archivos de sonido especialmente manipulados.",
        "impact_if_unpatched": "Permite a un atacante remoto acceder a la información de hash NTLM de un usuario sin interacción, lo que podría llevar a la suplantación de identidad o a ataques de retransmisión NTLM."
    },
    {
        "cve_name": "CVE-2012-0158",
        "description": "MSCOMCTL ActiveX es una vulnerabilidad de ejecución remota de código en un control ActiveX de Microsoft Office (MSCOMCTL.OCX).",
        "impact_if_unpatched": "Permite a un atacante ejecutar código arbitrario cuando un usuario abre un documento de Office especialmente diseñado, lo que podría llevar al control total del sistema."
    },
    {
        "cve_name": "CVE-2014-6332",
        "description": "OLE VBScript EoP es una vulnerabilidad de elevación de privilegios y ejecución remota de código en OLE Automation y VBScript en Internet Explorer.",
        "impact_if_unpatched": "Permite a un atacante ejecutar código arbitrario en el contexto del usuario actual cuando este visita una página web maliciosa, lo que podría llevar al control del sistema."
    },
    {
        "cve_name": "CVE-2018-8174",
        "description": "Double Kill (VBScript RCE) es una vulnerabilidad de ejecución remota de código en el motor VBScript de Internet Explorer.",
        "impact_if_unpatched": "Permite a un atacante ejecutar código arbitrario en el sistema de la víctima cuando esta visita una página web maliciosa, lo que podría llevar al control total del sistema."
    },
    {
        "cve_name": "CVE-2022-22047",
        "description": "Windows CSRSS EoP es una vulnerabilidad de elevación de privilegios en el Subsistema Cliente/Servidor de Windows (CSRSS).",
        "impact_if_unpatched": "Permite a un atacante local elevar sus privilegios a SYSTEM, obteniendo control total sobre el sistema."
    },
    {
        "cve_name": "CVE-2023-21768",
        "description": "Win32k EoP es una vulnerabilidad de elevación de privilegios en el controlador del subsistema Win32k de Windows.",
        "impact_if_unpatched": "Permite a un atacante local elevar sus privilegios a SYSTEM, obteniendo control total sobre el sistema."
    },
    {
        "cve_name": "CVE-2022-41099",
        "description": "SmartScreen Security Feature Bypass es una vulnerabilidad que permite eludir la característica de seguridad SmartScreen de Windows.",
        "impact_if_unpatched": "Permite a un atacante evadir las advertencias de seguridad de SmartScreen, facilitando la entrega de malware o la ejecución de código no confiable sin el conocimiento del usuario."
    },
    {
        "cve_name": "CVE-2022-41040",
        "description": "ProxyNotShell (Exchange) es una vulnerabilidad de ejecución remota de código en Microsoft Exchange Server, combinada con otra vulnerabilidad (CVE-2022-41082).",
        "impact_if_unpatched": "Permite a un atacante remoto ejecutar código arbitrario en el servidor Exchange, lo que puede resultar en la toma de control del servidor de correo electrónico."
    },
    {
        "cve_name": "CVE-2021-26411",
        "description": "IE Memory Corruption (RCE) es una vulnerabilidad de corrupción de memoria en Internet Explorer que puede llevar a la ejecución remota de código.",
        "impact_if_unpatched": "Permite a un atacante ejecutar código arbitrario en el contexto del usuario actual cuando este visita una página web maliciosa, lo que podría llevar al control total del sistema."
    },
    {
        "cve_name": "CVE-2010-2568",
        "description": "LNK vulnerability (Stuxnet) es una vulnerabilidad de ejecución remota de código a través de archivos de acceso directo (.lnk) maliciosos.",
        "impact_if_unpatched": "Permite a un atacante ejecutar código arbitrario cuando se visualiza un archivo .lnk malicioso, incluso en un disco extraíble, como se vio en el ataque de Stuxnet a instalaciones nucleares."
    },
    {
        "cve_name": "CVE-2015-0096",
        "description": "Shell Link Path Overflow es una vulnerabilidad de desbordamiento de búfer en el componente Windows Shell que procesa archivos .lnk.",
        "impact_if_unpatched": "Permite a un atacante remoto ejecutar código arbitrario en el sistema cuando un usuario abre una carpeta que contiene un archivo .lnk malicioso."
    },
    {
        "cve_name": "CVE-2017-8464",
        "description": "Windows Shell RCE via .lnk es una vulnerabilidad de ejecución remota de código en el shell de Windows a través de archivos .lnk maliciosos.",
        "impact_if_unpatched": "Permite a un atacante remoto ejecutar código arbitrario en el sistema cuando un usuario abre una carpeta que contiene un archivo .lnk malicioso."
    },
    {
        "cve_name": "CVE-2021-44228",
        "description": "Log4Shell (Apache Log4j) es una vulnerabilidad de ejecución remota de código en la biblioteca de registro Apache Log4j.",
        "impact_if_unpatched": "Permite a un atacante remoto ejecutar código arbitrario en el servidor, lo que puede resultar en un control completo del sistema afectado."
    },
    {
        "cve_name": "CVE-2020-0601",
        "description": "CurveBall (CryptoAPI spoofing) es una vulnerabilidad de suplantación en CryptoAPI de Windows que afecta a la validación de certificados ECC.",
        "impact_if_unpatched": "Permite a un atacante falsificar firmas de código y certificados SSL, lo que podría usarse para distribuir malware aparentemente legítimo o realizar ataques de hombre en el medio."
    },
    {
        "cve_name": "CVE-2021-40444",
        "description": "MSHTML RCE es una vulnerabilidad de ejecución remota de código en el motor de renderizado MSHTML de Internet Explorer y otros componentes de Windows.",
        "impact_if_unpatched": "Permite a un atacante ejecutar código arbitrario simplemente haciendo que la víctima abra un documento de Office malicioso o visite una página web diseñada con fines maliciosos."
    },
    {
        "cve_name": "CVE-2015-1701",
        "description": "Win32k EoP es una vulnerabilidad de elevación de privilegios en el controlador del subsistema Win32k de Windows.",
        "impact_if_unpatched": "Permite a un atacante local elevar sus privilegios de usuario estándar a privilegios de SYSTEM, obteniendo control total sobre el sistema."
    },
    {
        "cve_name": "CVE-2023-28252",
        "description": "Windows CLFS EoP es una vulnerabilidad de elevación de privilegios en el sistema de archivos de registro común (CLFS) de Windows.",
        "impact_if_unpatched": "Permite a un atacante local ejecutar código arbitrario con privilegios de SYSTEM, lo que lleva al control total del sistema."
    },
    {
        "cve_name": "CVE-2016-3309",
        "description": "Adobe Flash + Win32k sandbox bypass es una vulnerabilidad que combina un fallo en Adobe Flash con una vulnerabilidad en Win32k para eludir las protecciones de la 'sandbox'.",
        "impact_if_unpatched": "Permite a un atacante ejecutar código arbitrario fuera del entorno seguro de Flash Player, lo que podría llevar al control total del sistema."
    },
    {
        "cve_name": "CVE-2019-1388",
        "description": "Windows Certificate Dialog EoP es una vulnerabilidad de elevación de privilegios en el cuadro de diálogo de certificados de Windows.",
        "impact_if_unpatched": "Permite a un atacante local obtener privilegios de SYSTEM aprovechando la forma en que se manejan las operaciones relacionadas con los certificados."
    },
    {
        "cve_name": "CVE-2022-41128",
        "description": "Chromium V8 RCE es una vulnerabilidad de ejecución remota de código en el motor JavaScript V8 de Chromium.",
        "impact_if_unpatched": "Permite a un atacante ejecutar código arbitrario cuando un usuario visita una página web maliciosa, lo que podría llevar al control total del navegador y, potencialmente, del sistema."
    },
    {
        "cve_name": "CVE-2021-34473",
        "description": "Microsoft Exchange SSRF es una vulnerabilidad de falsificación de solicitudes del lado del servidor (SSRF) en Microsoft Exchange Server.",
        "impact_if_unpatched": "Permite a un atacante no autenticado enviar solicitudes arbitrarias desde el servidor Exchange, lo que podría llevar al acceso a recursos internos o a la ejecución remota de código."
    },
    {
        "cve_name": "CVE-2021-34523",
        "description": "Exchange Elevation of Privilege es una vulnerabilidad de elevación de privilegios en Microsoft Exchange Server.",
        "impact_if_unpatched": "Permite a un atacante obtener privilegios elevados en el servidor Exchange, lo que podría llevar al control total del servidor de correo electrónico."
    },
    {
        "cve_name": "CVE-2014-0160",
        "description": "Heartbleed (OpenSSL) es una vulnerabilidad de divulgación de información en la biblioteca de criptografía OpenSSL.",
        "impact_if_unpatched": "Permite a un atacante leer grandes cantidades de memoria de servidores y clientes, lo que puede exponer información sensible como claves privadas SSL, nombres de usuario y contraseñas."
    },
    {
        "cve_name": "CVE-2012-0002",
        "description": "RDP RCE es una vulnerabilidad de ejecución remota de código en el protocolo de Escritorio Remoto (RDP) de Windows.",
        "impact_if_unpatched": "Permite a un atacante no autenticado ejecutar código arbitrario en el servidor RDP, lo que podría llevar al control total del sistema."
    },
    {
        "cve_name": "CVE-2013-3660",
        "description": "NDProxy Elevation of Privilege es una vulnerabilidad de elevación de privilegios en el controlador NDProxy de Windows.",
        "impact_if_unpatched": "Permite a un atacante local elevar sus privilegios a SYSTEM, obteniendo control total sobre el sistema."
    },
    {
        "cve_name": "CVE-2017-5638",
        "description": "Apache Struts RCE es una vulnerabilidad de ejecución remota de código en el marco de trabajo web Apache Struts.",
        "impact_if_unpatched": "Permite a un atacante ejecutar código arbitrario en el servidor, lo que puede resultar en un control completo del sistema afectado."
    },
    {
        "cve_name": "CVE-2016-0099",
        "description": "Secondary Logon EoP es una vulnerabilidad de elevación de privilegios en el servicio de inicio de sesión secundario (runas) de Windows.",
        "impact_if_unpatched": "Permite a un atacante local obtener privilegios de SYSTEM al explotar un error en la forma en que el servicio maneja los tokens de seguridad."
    },
    {
        "cve_name": "CVE-2017-0143",
        "description": "ETERNA_BLUE exploit kit subcomponent (MS17-010) es un subcomponente del kit de explotación EternalBlue, parte del boletín MS17-010.",
        "impact_if_unpatched": "Permite la explotación de la vulnerabilidad CVE-2017-0144, llevando a la ejecución remota de código en sistemas vulnerables."
    },
    {
        "cve_name": "CVE-2019-1402",
        "description": "Windows Shell RCE es una vulnerabilidad de ejecución remota de código en el shell de Windows.",
        "impact_if_unpatched": "Permite a un atacante ejecutar código arbitrario en el sistema al procesar ciertos tipos de archivos o al interactuar con el shell de forma maliciosa."
    },
    {
        "cve_name": "CVE-2018-0992",
        "description": "PowerShell Editor Services RCE es una vulnerabilidad de ejecución remota de código en los servicios del editor de PowerShell.",
        "impact_if_unpatched": "Permite a un atacante ejecutar código arbitrario en el sistema cuando un usuario interactúa con un entorno PowerShell especialmente diseñado."
    },
    {
        "cve_name": "CVE-2020-1325",
        "description": "PowerShell Remote Jobs es una vulnerabilidad que permite la ejecución de código arbitrario a través de trabajos remotos de PowerShell.",
        "impact_if_unpatched": "Permite a un atacante remoto ejecutar código arbitrario en el sistema, lo que podría llevar al control total del sistema."
    },
    {
        "cve_name": "CVE-2021-34484",
        "description": "User Profile Service EoP es una vulnerabilidad de elevación de privilegios en el servicio de perfil de usuario de Windows.",
        "impact_if_unpatched": "Permite a un atacante local elevar sus privilegios a SYSTEM, obteniendo control total sobre el sistema."
    },
    {
        "cve_name": "CVE-2021-45046",
        "description": "Variante de Log4Shell es una segunda vulnerabilidad relacionada con Log4j que aborda una corrección incompleta de CVE-2021-44228.",
        "impact_if_unpatched": "Permite a un atacante remoto ejecutar código arbitrario en el servidor, incluso después de aplicar la primera corrección para Log4Shell, lo que puede resultar en un control completo del sistema afectado."
    },
    {
        "cve_name": "CVE-2021-1675",
        "description": "PrintNightmare (variante inicial) es la vulnerabilidad inicial de elevación de privilegios en el servicio Windows Print Spooler.",
        "impact_if_unpatched": "Permite a un atacante local ejecutar código arbitrario con privilegios SYSTEM o añadir drivers de impresora maliciosos, comprometiendo el sistema y la red."
    },
    {
        "cve_name": "CVE-2019-1069",
        "description": "Task Scheduler EoP es una vulnerabilidad de elevación de privilegios en el Programador de Tareas de Windows.",
        "impact_if_unpatched": "Permite a un atacante local obtener privilegios de SYSTEM al explotar un error en la forma en que se manejan las tareas programadas."
    },
    {
        "cve_name": "CVE-2020-1350",
        "description": "SIGRed (Windows DNS Server RCE) es una vulnerabilidad de ejecución remota de código en el servidor DNS de Windows.",
        "impact_if_unpatched": "Permite a un atacante no autenticado ejecutar código arbitrario en el servidor DNS, lo que podría llevar al control total de la infraestructura DNS y, por extensión, de la red."
    },
    {
        "cve_name": "CVE-2019-1040",
        "description": "NTLM Tampering es una vulnerabilidad que permite la manipulación del protocolo NTLM de autenticación de Windows.",
        "impact_if_unpatched": "Permite a un atacante remoto eludir las protecciones de MIC (Message Integrity Check) y SMB Signing, lo que podría llevar a ataques de retransmisión NTLM y ejecución remota de código."
    }
    ]

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
        # Find the corresponding CVE info
        # Busca la información del CVE en la lista cves_info
        info = None
        for cve_data_item in cves_info:
            if cve_data_item["cve_name"] == cve:
                info = cve_data_item
                break # Una vez encontrado, salimos del bucle interno

        if info:
            # Añade un diccionario con toda la información requerida
            results.append({
                "cve_name": cve,
                "probability_percentage": pct,
                "description": info["description"],
                "impact_if_unpatched": info["impact_if_unpatched"]
            })
        else:
            # Maneja los casos donde la información del CVE no se encuentra
            results.append({
                "cve_name": cve,
                "probability_percentage": pct,
                "description": "Description not available",
                "impact_if_unpatched": "Impact not available"
            })
    return results


if __name__ == "__main__":
    test = get_failed_cves_probabilities([0, 1, 2])
    print(test)