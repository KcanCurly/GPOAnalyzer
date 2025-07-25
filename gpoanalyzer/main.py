import binascii
from pprint import pprint
import ldap3
from impacket.dcerpc.v5 import dtypes
from impacket.structure import Structure
import base64
import argparse

from gpoanalyzer.DescribeNTSecurityDescriptor import HumanDescriber, LDAPSearcher, NTSecurityDescriptor

def get_base_dn_anonymous(ldap_server):
    server = ldap3.Server(ldap_server, get_info=ldap3.ALL)
    conn = ldap3.Connection(server, auto_bind=True, authentication="ANONYMOUS")

    conn.search(
        search_base="",
        search_scope=ldap3.BASE,
        search_filter="(objectClass=*)",
        attributes=["namingContexts"]
    )

    naming_contexts = conn.entries[0]["namingContexts"]
    for context in naming_contexts:
        if str(context).startswith("DC="):
            base_dn = str(context)
            # Extract NetBIOS-style domain (e.g., DC=curlylab,DC=local -> curlylab)
            domain_name = ".".join(part.split("=")[1] for part in base_dn.split(","))
            return base_dn, domain_name

    raise Exception("Base DN not found")

def get_base_dn(ldap_server, user, password, domain):
    base_dn, domain_name = get_base_dn_anonymous(ldap_server)
    server = ldap3.Server(ldap_server, get_info=ldap3.ALL)
    conn = ldap3.Connection(server, user=f"{domain_name}\\{user}", password=password, auto_bind=True, authentication="NTLM")

    # Query the RootDSE entry for naming contexts
    conn.search(
        search_base="",
        search_scope=ldap3.BASE,
        search_filter="(objectClass=*)",
        attributes=["namingContexts"]
    )

    naming_contexts = conn.entries[0]["namingContexts"]

    # Pick the first DN that looks like a domain (starts with "DC=")
    for context in naming_contexts:
        if str(context).startswith("DC="):
            return str(context)

    raise Exception("No valid base DN found")

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

    server = ldap3.Server(dc_ip, get_info=ldap3.ALL)
    conn = ldap3.Connection(server, user=f"{domain}\\{user}", password=password, auto_bind=True, authentication="NTLM")

    base_dn = get_base_dn(dc_ip, user, password, domain)
    print(f"[+] Base DN: {base_dn}")

    # Query for all GPOs
    conn.search(
        search_base=base_dn,
        search_filter='(objectClass=groupPolicyContainer)',
        attributes=['displayName', 'cn', 'gPCFileSysPath', 'gPCFunctionalityVersion', "nTSecurityDescriptor"]
    )

    for entry in conn.entries:
        print(f"GPO: {entry.displayName}")
        print(f"CN: {entry.cn}")
        print(f"Path: {entry.gPCFileSysPath}")
        print(f"Functionality Version: {entry.gPCFunctionalityVersion}")
        # print(f"Security: {entry.nTSecurityDescriptor}")
        raw_ntsd_value = entry.nTSecurityDescriptor.value
        if type(raw_ntsd_value) == list:
            raw_ntsd_value = raw_ntsd_value[0]
        ls = LDAPSearcher(
            ldap_server=server,
            ldap_session=conn
        )
        print(type(raw_ntsd_value))
        ntsd = NTSecurityDescriptor(
            value=raw_ntsd_value,
            verbose=False,
            ldap_searcher=ls
        )
        print("\n" + "==[Summary]".ljust(80,'=') + "\n")
        HumanDescriber(ntsd=ntsd).summary()
        print("------")
