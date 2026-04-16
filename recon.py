import dns.resolver
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import dns.resolver
import dns.zone
import dns.exception
import dns.rdatatype
import json
import time




TAKEOVER_FINGERPRINTS = [
    ("github.io",         "There isn't a GitHub Pages site here",          "GitHub Pages"),
    ("herokuapp.com",     "No such app",                                    "Heroku"),
    ("s3.amazonaws.com",  "NoSuchBucket",                                   "AWS S3"),
    ("netlify.app",       "Not Found - Request ID",                         "Netlify"),
    ("netlify.com",       "Not Found - Request ID",                         "Netlify"),
    ("azurewebsites.net", "404 Web Site not found",                         "Azure"),
    ("cloudapp.net",      "404 Web Site not found",                         "Azure"),
    ("fastly.net",        "Fastly error: unknown domain",                   "Fastly"),
    ("ghost.io",          "The thing you were looking for is no longer here","Ghost"),
    ("myshopify.com",     "Sorry, this shop is currently unavailable",      "Shopify"),
    ("surge.sh",          "project not found",                              "Surge"),
    ("webflow.io",        "The page you are looking for doesn't exist",     "Webflow"),
    ("readthedocs.io",    "Unknown project code",                           "ReadTheDocs"),
    ("zendesk.com",       "Help Center Closed",                             "Zendesk"),
    ("freshdesk.com",     "There is no helpdesk here",                      "Freshdesk"),
]

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


# --------------- wordlist loader -------------
def load_wordlist(path):
    if path:
        try:
            with open(path) as f:
                words = [line.strip() for line in f if line.strip()]
            info(f"Loaded {len(words)} words from {path}")
            return words
        except FileNotFoundError:
            warn(f"Wordlist {path} not found - using built-in list")

    return[
        "www", "mail", "remote", "blog", "webmail", "server",
        "ns1", "ns2", "smtp", "secure", "vpn", "shop", "ftp",
        "test", "portal", "admin", "dev", "api", "staging", "beta",
        "mobile", "static", "cdn", "app", "old", "new", "git",
        "gitlab", "jenkins", "wiki", "docs", "help", "status",
        "dashboard", "login", "sso", "auth", "cloud", "media",
        "img", "assets", "backup", "mysql", "prod", "sandbox",
    ]


# ----- brute-force subdomain finder ----------
def brute_force_subdomains(domain, wordlist, threads=50):
    head(f"Wordlist Brute-force ({len(wordlist)} words, {threads} threads)")

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    results = []
    
    def resolve_one(word):
        fqdn = f"{word}.{domain}"
        cname_target = None

        try:
            try:
                cname_ans = resolver.resolve(fqdn, "CNAME")
                cname_target = cname_ans[0].to_text().rstrip(".")
            except Exception:
                pass

            a_ans = resolver.resolve(fqdn, "A")
            ips = [r.to_text() for r in a_ans]
            return {"name": fqdn, "ips": ips, "cname": cname_target}

        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            if cname_target:
                return {"name": fqdn, "ips": [], "cname": cname_target }
            return None
        except dns.exception.DNSException:
            return None

    found = 0
    completed = 0
    total = len(wordlist)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = { executor.submit(resolve_one, word): word for word in wordlist }

        for future in as_completed(futures):
            completed += 1
            result = future.result()

            if result: 
                found += 1
                results.append(result)
                cname_str = f" → {YELLOW}{result['cname']}{RESET}" if result['cname'] else ""
                ip_str = ", ".join(result['ips']) if result['ips'] else "(no A)"
                ok(f"{result['name']:<45} {ip_str}{cname_str}")

            print(f"    {GREY}[{completed}/{total}] scanned, {found} found...{RESET}", end="\r")

    print()
    info(f"Brute-force complete: {found} subdomains resolved")
    return results



#----------------- passive recon/crt.scan----------
def crtsh_subdomains(domain):
    head("Certificate Transparency (crt.sh)")
    info(f"Querying crt.sh for *.{domain}")

    found = set() # no duplicate subdomains
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(
            url,
            timeout=60,
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
    return results


# --------- AXFR ------
def attempt_axfr(domain, nameservers):
    head("AXFR Zone Transfer Attempt")

    result = {
        "attempted": [],
        "success": False,
        "records": []
    }

    if not nameservers:
        warn("NO nameservers found — skipping AXFR")
        return result

    for ns in nameservers:
        ns = ns.rstrip(".")
        info(f"Trying AXFR from {ns}")
        result["attempted"].append(ns)

        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))

            ok(f"AXFR SUCESS from {ns} — zone transfer allowed!")
            result["success"] = True

            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        record = (
                                f"{name}.{domain}",
                                f"{dns.rdatatype.to_text(rdataset.rdtype)}",
                                f"{rdata.to_text()}"
                        )
                        result["records"].append(record)
                        print(f"    {GREEN}     {record}{RESET}")

            return result

        except dns.exception.FormError:
            warn(f"     {ns}  refused AXFR (REFUSED — expected)")
        except ConnectionRefusedError:
            warn(f"     {ns}  refused connection")
        except socket.gaierror:
            warn(f"     Could not resolve nameservers: {ns}")
        except Exception as e:
            warn(f"     {ns} AXFR failed: {type(e).__name__}: {e}")

    info("All AXFR attempts refused — nameservers are correctly configured")
    info("Note: a successful AXFR would mean the target is misconfigured") 
    return result

def cname_resolves(cname):
    try:
        socket.gethostbyname(cname)
        return True
    except socket.gaierror:
        return False

def check_takeover(subdomain, cname):
    for cname_pat, body_pat, service in TAKEOVER_FINGERPRINTS:
        if cname_pat not in cname:
            continue

        # CNAME matches a known platform - now check if it resolves
        if not cname_resolves(cname):
            return f"{service} (CNAME does not resolve — dangling)"

        # it resolves — probe HTTP for the error fingerprint 
        try:
            r = requests.get(
                f"https://{subdomain}",
                timeout=5,
                allow_redirects=True,
                headers={"User-Agent": "recon.py/1.0"}
            )
            if body_pat.lower() in r.text.lower():
                return f"{service} (error page fingerprint matched)"
        except requests.exceptions.RequestException:
            return f"{service} (CNAME matches, HTTP unreachable)"

    return None

def detect_takeovers(subdomains):
    head("Subdomain Takeover Detection")

    candidates = []
    cname_subs = [s for s in subdomains if s.get("cname")]

    if not cname_subs:
        info("No CNAME records found among discovered subdomains")
        return candidates

    info(f"checking {len(cname_subs)} CNAME record(s)...")

    for sub in cname_subs: 
        result = check_takeover(sub["name"], sub["cname"])
        if result:
            sub["takeover"] = result
            candidates.append(sub)

            print(f"\n {RED}{BOLD}[TAKEOVER CANDIDATE]{RESET}")
            print(f"    {RED}  Subdomain : {sub['name']}{RESET}")
            print(f"    {RED}  CNAME     : {sub['cname']}{RESET}")
            print(f"    {RED}  Service   : {result}{RESET}")
        else:
            info(f"{sub['name']} → {sub['cname']} (no fingerprint match)")

    if not candidates:
        ok("No takeover candidates found")

    return candidates




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

# summary printer
def print_summary(domain, records, brute_results, axfr_results, takeover_candidates):
    head("Summary")

    total_subs = len(brute_results)
    resolved = len([s for s in brute_results if s.get("ips")])
    takeovers = len(takeover_candidates)

    print(f"   {BOLD}Target:{RESET}             {domain}")
    print(f"   {BOLD}A records:{RESET}          {len(records.get('A', []))}")
    print(f"   {BOLD}MX records:{RESET}         {len(records.get('MX', []))}")
    print(f"   {BOLD}NS records:{RESET}         {len(records.get('NS', []))}")
    print(f"   {BOLD}Subdomains found{RESET}    {total_subs} ({resolved} resolved)")
    print(f"   {BOLD}AXFR success{RESET}        {axfr_results.get('success', False)}")

    if takeovers:
        print(f"\n  {RED}{BOLD}⚠  TAKEOVER CANDIDATES: {takeovers}{RESET}")
        for s in takeover_candidates:
            print(f"  {RED}   • {s['name']} → {s['cname']}{RESET}")
            print(f"  {RED}     {s['takeover']}{RESET}")
    else:
        print(f"\n  {GREEN}  No takeover candidates found{RESET}")
    print()


def write_json(domain, records, brute_results, axfr_results, takeover_candidates, path):
    report = {
        "target":    domain,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "dns_records": records,
        "subdomains": brute_results,
        "axfr": axfr_results,
        "takeover_candidates": takeover_candidates,
    }

    with open(path, "w") as f:
        json.dump(report, f, indent=2)

    ok(f"JSON report written to {path}")


# ---- Main Function --------------------
def main():
    banner()
    args = parser_args()
    domain = args.domain.strip().lower()
    info(f"Target: {BOLD}{args.domain}{RESET}")

    # 1. DNS records 
    records = enumerate_dns_records(args.domain)

    # 2. Certificate transparency
    ct_subdomains = crtsh_subdomains(args.domain)

    # 3. Wordlist brute-force
    wordlist = load_wordlist(args.wordlist)
    brute_results = brute_force_subdomains(args.domain, wordlist, args.threads)

    # 4. Merge CT-only subdomains into results
    brute_names = {s["name"] for s in brute_results}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    for fqdn in sorted(ct_subdomains):
        if fqdn in brute_names or fqdn == domain:
            continue
        cname_target = None
        try:
            try:
                ca = resolver.resolve(fqdn, "CNAME")
                cname_target = ca[0].to_text().rstrip(".")
            except Exception:
                pass

            a_ans = resolver.resolve(fqdn, "A")
            ips = [r.to_text() for r in a_ans]
            brute_results.append({"name": fqdn, "ips": ips, "cname": cname_target, "source": "crt.sh"})
            ok(f"{fqdn<<45} {', ',join(ips)}    {GREY}(crt.sh){RESET}")
        except Exception:
            brute_results.append({"name": fqdn, "ips": [], "cname": None, "source": "crtsh"})
            warn(f"{fqdn:<45} (unresolvable — historical CT entry)")


    # 5. AXFR
    axfr_result = {"attempted": [], "success": False, "records": []}
    if not args.no_axfr:
        ns_list = records.get("NS", [])
        axfr_result = attempt_axfr(args.domain, ns_list)

    # 6. Takeover detection
    takeover_candidates = detect_takeovers(brute_results)

    # 7. Summary
    print_summary(args.domain, records, brute_results, axfr_result, takeover_candidates)

    # 8. JSON output
    if args.json:
        out_path = f"{domain.replace('.', '_')}_recon.json"
        write_json(domain, records, brute_results, axfr_result, takeover_candidates, out_path)



#------------------------------------------------------
if __name__ == "__main__":
    main()
