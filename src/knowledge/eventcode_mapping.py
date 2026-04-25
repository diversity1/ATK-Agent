EVENTCODE_ONTOLOGY = {
    "1": {
        "telemetry": ["Process Creation"],
        "data_components": ["Process Creation", "Process Command"],
        "platforms": ["Windows"],
        "hints": ["sysmon", "process creation", "process command"],
    },
    "3": {
        "telemetry": ["Network Connection"],
        "data_components": ["Network Connection Creation", "Network Traffic Flow"],
        "platforms": ["Windows"],
        "hints": ["sysmon", "network connection", "network traffic"],
    },
    "7": {
        "telemetry": ["Image Load"],
        "data_components": ["Module Load"],
        "platforms": ["Windows"],
        "hints": ["sysmon", "module load", "dll", "image load"],
    },
    "8": {
        "telemetry": ["Create Remote Thread"],
        "data_components": ["Process Access", "OS API Execution"],
        "platforms": ["Windows"],
        "hints": ["sysmon", "create remote thread", "process injection"],
    },
    "10": {
        "telemetry": ["Process Access"],
        "data_components": ["Process Access"],
        "platforms": ["Windows"],
        "hints": ["sysmon", "process access"],
    },
    "11": {
        "telemetry": ["File Creation"],
        "data_components": ["File Creation"],
        "platforms": ["Windows"],
        "hints": ["sysmon", "file creation"],
    },
    "12": {
        "telemetry": ["Registry Modification"],
        "data_components": ["Windows Registry Key Creation"],
        "platforms": ["Windows"],
        "hints": ["sysmon", "registry key creation", "registry"],
    },
    "13": {
        "telemetry": ["Registry Modification"],
        "data_components": ["Windows Registry Key Modification"],
        "platforms": ["Windows"],
        "hints": ["sysmon", "registry key modification", "registry"],
    },
    "14": {
        "telemetry": ["Registry Modification"],
        "data_components": ["Windows Registry Key Modification"],
        "platforms": ["Windows"],
        "hints": ["sysmon", "registry key modification", "registry"],
    },
    "22": {
        "telemetry": ["DNS Query"],
        "data_components": ["DNS Query"],
        "platforms": ["Windows"],
        "hints": ["sysmon", "dns", "domain name"],
    },
    "4103": {
        "telemetry": ["Script Execution"],
        "data_components": ["Command Execution", "Script Execution"],
        "platforms": ["Windows"],
        "hints": ["powershell", "script execution", "module logging"],
    },
    "4104": {
        "telemetry": ["Script Execution"],
        "data_components": ["Command Execution", "Script Execution"],
        "platforms": ["Windows"],
        "hints": ["powershell", "script block", "script execution"],
    },
    "4624": {
        "telemetry": ["Logon Session"],
        "data_components": ["Logon Session Creation", "User Account Authentication"],
        "platforms": ["Windows"],
        "hints": ["windows security", "logon session", "authentication"],
    },
    "4625": {
        "telemetry": ["Logon Session"],
        "data_components": ["Logon Session Creation", "User Account Authentication"],
        "platforms": ["Windows"],
        "hints": ["windows security", "failed logon", "authentication"],
    },
    "4688": {
        "telemetry": ["Process Creation"],
        "data_components": ["Process Creation", "Process Command"],
        "platforms": ["Windows"],
        "hints": ["windows security", "process creation", "process command"],
    },
    "4698": {
        "telemetry": ["Scheduled Task"],
        "data_components": ["Scheduled Job Creation"],
        "platforms": ["Windows"],
        "hints": ["scheduled task", "task creation"],
    },
    "7045": {
        "telemetry": ["Service Creation"],
        "data_components": ["Service Creation"],
        "platforms": ["Windows"],
        "hints": ["service creation", "windows service"],
    },
}


def lookup_eventcode(event_code: str) -> dict:
    return EVENTCODE_ONTOLOGY.get(str(event_code).strip(), {})

