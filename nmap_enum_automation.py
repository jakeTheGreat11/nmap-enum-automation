import subprocess

def run_nmap_scan(target, args):
    print(f"Running nmap Scan on {target} ......")
    nmap_command = f"nmap {target} {args} -oX nmap_result.xml"
    subprocess.run(nmap_command, shell=True)
    