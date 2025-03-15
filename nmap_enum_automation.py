import subprocess
import json
import xmltodict

ACTIONS = {
    80: "gobuster dir -u http://{target} -w /usr/share/wordists/dirb/common.txt",
    443: "gobuster dir -u https://{target} -w /usr/share/wordists/dirb/common.txt",
    21: "ftp {target}",
    22: "hydra -L users.txt -P pasaswords.txt ssh://{target}",

}

def run_nmap_scan(target, args):
    print(f"Running nmap Scan on {target} ......")
    nmap_command = f"nmap {target} {args} -oX nmap_result.xml"
    subprocess.run(nmap_command, shell=True)

def convert_xml_to_json():
    with open("nmap_result.xml", "r") as xml_file:
        xml_content = xml_file.read()
        json_data = json.dumps(xmltodict.parse(xml_content), indent=4)
        return json_data
    
def extract_port_details(port):
    # Port Number
    port_number = port["portid"]
    
    # Protocol
    protocol = port["protocol"]
    
    # State Info
    state = port["state"]["state"]
    state_reason = port["state"].get("reason", "unknown")
    state_ttl = port["state"].get("reason_ttl", "unknown")
    
    # Service Info
    service_name = port["service"].get("name", "unknown")
    service_product = port["service"].get("product", "unknown")
    service_version = port["service"].get("version", "unknown")
    service_extrainfo = port["service"].get("extrainfo", "unknown")
    service_ostype = port["service"].get("ostype", "unknown")
    
    # Script Output (if available)
    script_output = port.get("script", {}).get("ssh-hostkey", {}).get("output", "none")
    
    # CPE Info
    cpe_info = port.get("cpe", "none")

    # Return all extracted details in a dictionary
    return {
        "port_number": port_number,
        "protocol": protocol,
        "state": state,
        "state_reason": state_reason,
        "state_ttl": state_ttl,
        "service_name": service_name,
        "service_product": service_product,
        "service_version": service_version,
        "service_extrainfo": service_extrainfo,
        "service_ostype": service_ostype,
        "script_output": script_output,
        "cpe_info": cpe_info
    }

def parse_nmap_output():
    nmap_json_output = convert_xml_to_json()
    if len(nmap_json_output.get("ports", [])) == 0:
        print("No open ports")
        return None
    open_ports = []
    for port in nmap_json_output["ports"]:
        port_details = extract_port_details(port)
        open_ports.append(port_details)
    return open_ports

def execute_automations(target, open_ports):
    for port in open_ports:
        if port.get("port_number") in ACTIONS:
            