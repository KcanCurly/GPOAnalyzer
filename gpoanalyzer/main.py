from ldap3 import NTLM, Server, Connection, ALL
from impacket.dcerpc.v5 import dtypes
from impacket.structure import Structure
import base64
import argparse



def parse_args():
    parser = argparse.ArgumentParser(description="Read GPO permissions from Active Directory.")
    parser.add_argument("--domain", required=True, help="Domain name (e.g. yourdomain.local)")
    parser.add_argument("--user", required=True, help="Username (without domain)")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--dc-ip", required=True, help="Domain Controller IP address")
    return parser.parse_args()

def main():
    args = parse_args()

    domain = args.domain
    user = args.user
    password = args.password
    dc_ip = args.dc_ip

    # Connect to the domain controller
    server = Server(dc_ip, get_info=ALL)
    conn = Connection(server, user=f"{domain}\\{user}", password=password, authentication=NTLM, auto_bind=True)

    # Search for all Group Policy Objects
    # We first build the base DN for the search
    domain_parts = domain.split('.')
    base_dn = ','.join([f"DC={part}" for part in domain_parts])
    base_dn = "CN=Policies,CN=System," + base_dn
    conn.search(base_dn,
            '(objectClass=groupPolicyContainer)',
            attributes=["displayName", "nTSecurityDescriptor"])

    for entry in conn.entries:
        display_name = entry.displayName.value
        sd_raw = entry["nTSecurityDescriptor"].raw_values[0]  # Raw binary SD

        try:
            # Parse security descriptor using impacket
            sec_desc = dtypes.SECURITY_DESCRIPTOR(data=sd_raw)
            print(f"\n📁 GPO: {display_name}")
            print("🔐 Permissions:")
            sec_desc['Dacl'].dump()
        except Exception as e:
            print(f"Error parsing security descriptor for {display_name}: {e}")