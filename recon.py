import dns.resolver

# ---- Colors --------------------
RESET = "\033[0m"
BOLD = "\033[1m"
GREY = "\033[90m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"

#------ Banner --------------------
def banner():
    print(f"""
{GREEN}{BOLD}╔══════════════════════════════════════╗
║       DNS Recon & Takeover Scanner   ║
║       CTF / Authorized Use Only      ║
╚══════════════════════════════════════╝{RESET}
""")

# ------- Helper Functions --------------------
def ok(msg): print(f"   {GREEN}[+]{RESET} {msg}")
def info(msg): print(f"   {GREEN}[*]{RESET} {msg}")
def warn(msg): print(f"   {GREEN}[!]{RESET} {msg}")
def err(msg): print(f"   {GREEN}[-]{RESET} {msg}")
def head(msg): print(f"\n{BOLD}{'─'*50}\n   {msg}\n{'─'*50}{RESET}")

#------- Dns Queury function --------------------
def query_a_record(domain):
    head("[A] Records")

    # the recursive resolver instance
    resolver = dns.resolver.Resolver() 
    resolver.timeout = 5 # single query timeout before retrying
    resolver.lifetime = 5 # tota time before giving up

    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
    results = {}

    for rtype in record_types:
        try: 
            answers = resolver.resolve(domain, rtype)
            results[rtype] = []

            for record in answers: 
                value = record.to_text()
                results[rtype].append(value)
                ok(f"{BOLD}{rtype:<6} record: {value}")
            
        # NXDOMAIN: Non EXistent Domain
        except dns.resolver.NXDOMAIN:
            err(f"{domain} does not exist.")
            return {}
        # No Answer: Domain Exists but no A recrd, might have MX and TXT record, (eg mail, no website)
        except dns.resolver.NoAnswer:
            warn(f"No A records found for {domain}.")
        # Timeout, network error, malformed response, etc
        except dns.exception.DNSException as e:        
            err(f"DNS query failed: {e}")




# ---- Main Function --------------------
def main():
    banner()
    query_a_record("google.com")  # Replace with target domain
    

#------------------------------------------------------
if __name__ == "__main__":
    main()
