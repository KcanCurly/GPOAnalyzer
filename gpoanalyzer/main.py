import ldap3
import argparse
from ldap3 import ALL, NTLM, Connection, Server, SUBTREE, Tls
from ldap3.core.exceptions import LDAPBindError
import ssl
import socket
import traceback
import registrypol
from smb import SMBConnection as pysmbconn

def create_ldap_server(server, use_ssl):
    if use_ssl:
        tls = Tls(validate=ssl.CERT_NONE)
        return Server(server, use_ssl=True, tls=tls, get_info=ALL)
    return Server(server, get_info=ALL)

def get_connection(server, domain, user, password):
    conn = None
    try:
        try:
            server = create_ldap_server(server, True)
            conn = Connection(
                server,
                user=f"{domain}\\{user}",
                password=password,
                authentication=NTLM,
                channel_binding="TLS_CHANNEL_BINDING",
                auto_bind=True,
                auto_range=True,
            )
            print("Connecting using ntlm - channel binding")
        except (ssl.SSLError, socket.error, LDAPBindError) as e:
            print("1", e)
            server = create_ldap_server(server, False)
            conn = Connection(
                server,
                user=f"{domain}\\{user}",
                password=password,
                authentication=NTLM,
                auto_bind=True,
                auto_range=True,
            )
            print("Connecting using ntlm")
    except Exception as e:
        print("2", e)
        traceback.print_exc() 
        return None
    return conn

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
    parser.add_argument("--username", required=True, help="Username (without domain)")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--host", required=True, help="Domain Controller IP address")
    return parser.parse_args()

def main():
    args = parse_args()

    base_dn, domain = get_base_dn_anonymous(args.host)

    conn = get_connection(args.host, domain, args.username, args.password)
    if not conn:
        print("LDAP connection failed")
        return

    # Query for all GPOs
    conn.search(
        search_base=base_dn,
        search_filter='(objectClass=groupPolicyContainer)',
        attributes=['displayName', 'cn', 'gPCFileSysPath', 'gPCFunctionalityVersion', "nTSecurityDescriptor"]
    )

    smb_conn = pysmbconn.SMBConnection(args.username, args.password, '', '', is_direct_tcp=True)
    smb_conn.connect(args.host, 445)

    for entry in conn.entries:
        print(f"GPO: {entry.displayName}")
        print(f"CN: {entry.cn}")
        print(f"Path: {entry.gPCFileSysPath}")
        print(f"Functionality Version: {entry.gPCFunctionalityVersion}")
        _, filename = entry.gPCFileSysPath.rsplit("/", 1)
        _, sharename, path = entry.gPCFileSysPath.split("/", 2)
        with open(filename, "w") as f:
            smb_conn.retrieveFile(sharename, path, f)

