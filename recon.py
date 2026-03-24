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

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    try: 
        answers = resolver.resolve(domain, 'A')
        for record in answers: ok(record.to_text())
    except dns.resolver.NXDOMAIN:
        err(f"{domain} does not exist.")
    except dns.resolver.NoAnswer:
        warn(f"No A records found for {domain}.")
    except dns.exception.DNSException as e:        
        err(f"DNS query failed: {e}")


# ---- Main Function --------------------
def main():
    banner()
    query_a_record("google.com")  # Replace with target domain
    

#------------------------------------------------------
if __name__ == "__main__":
    main()
