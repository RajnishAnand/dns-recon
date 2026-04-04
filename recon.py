import dns.resolver
import argparse
import requests


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


# passive recon
def crtsh_subdomains(domain):
    head("Certificate Transparency (crt.sh)")
    info(f"Querying crt.sh for *.{domain}")

    found = set() # no duplicate subdomains
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(
            url,
            timeout=15,
            headers={"User-Agent": "recon.py/1.0"}
        )
        response.raise_for_status()
        data = response.json()

        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    found.add(name)

        ok(f"Found {len(found)} unique subdomains in CT logs")
        for sub in sorted(found):
            print(f"    {GREY}{sub}{RESET}")
    
    except requests.exceptions.Timeout:
        warn("crt.sh request timed out.")
    except requests.exceptions.ConnectionError:
        warn("Could not reach crt.sh")
    except requests.exceptions.HTTPError as e:
        warn(f"crt.sh returned an error: {e}")
    except ValueError:
        warn("crt.sh response was not valid JSON")

    return found;


#------- Dns Query function --------------------
def enumerate_dns_records(domain):
    head("[A] Records")

    # the recursive resolver instance
    resolver = dns.resolver.Resolver() 
    resolver.timeout = 5 # single query timeout before retrying
    resolver.lifetime = 5 # total time before giving up

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

        # NXDOMAIN: Non Existent Domain
        except dns.resolver.NXDOMAIN:
            err(f"{domain} does not exist.")
            return {}
        # No Answer: Domain Exists but no A record, might have MX and TXT record, (eg mail, no website)
        except dns.resolver.NoAnswer:
            warn(f"No A records found for {domain}.")
        # Timeout, network error, malformed response, etc
        except dns.exception.DNSException as e:        
            err(f"DNS query failed: {e}")


# ---------------  Argument Parser function -------------------
def parser_args():
    parser = argparse.ArgumentParser(
        description="DNS Recon & Takeover Scanner",
        epilog="Example: python recon.py -d example.com --json"
    )
    parser.add_argument(
        "-d", "--domain",
        help="Target domain",
        required=True
    )
    parser.add_argument(
        "--wordlist",
        default=None,
        help="Path to subdomain wordlist file"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Save results to a JSON file"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Number of brute-force threads (default: 50)"
    )
    parser.add_argument(
        "--no-axfr",
        action="store_true",
        help="Skip AXFR zone transfer attempt"
    )
    return parser.parse_args()


# ---- Main Function --------------------
def main():
    banner()
    args = parser_args()
    info(f"Target: {BOLD}{args.domain}{RESET}")

    records = enumerate_dns_records(args.domain)
    ct_subdomains = crtsh_subdomains(args.domain)


#------------------------------------------------------
if __name__ == "__main__":
    main()
