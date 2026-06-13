#!/usr/bin/env python3
"""
MailScope
=========
A deep scope into your domain's email security. Checks:
  - SPF      (Sender Policy Framework)
  - DKIM     (DomainKeys Identified Mail)
  - DMARC    (Domain-based Message Authentication, Reporting & Conformance)
  - MTA-STS  (Mail Transfer Agent Strict Transport Security)
  - MX       (Mail Exchange records)
  - DNSSEC   (DNS Security Extensions)

All checks use public DNS queries (and HTTPS for MTA-STS only) — no external APIs.

Usage:
    python mailscope.py
    python mailscope.py example.com
    python mailscope.py example.com google      # with DKIM selector

Dependencies:
    pip install dnspython requests
"""

import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    import dns.resolver
    import dns.rdatatype
    import dns.flags
except ImportError:
    print("[ERROR] Library 'dnspython' not found. Install with: pip install dnspython")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[ERROR] Library 'requests' not found. Install with: pip install requests")
    sys.exit(1)


COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "k1", "k2", "k3",
    "s1", "s2",
    "amazonses", "ses",
    "smtp", "mail", "dkim", "email",
    "zoho", "zendesk1", "zendesk2",
    "mandrill", "mxvault", "everlytickey1", "everlytickey2",
]

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

FALLBACK_DNS = ["8.8.8.8", "1.1.1.1"]

SCORE_BAR_WIDTH = 10

# Maps each check status to a base score (0–10). Individual checks may adjust further.
STATUS_SCORES = {
    "OK": 10,
    "OK (can improve)": 8,
    "OK (testing)": 6,
    "WEAK": 3,
    "INCOMPLETE": 5,
    "NOT FOUND": 3,
    "CRITICAL": 0,
    "FAIL": 0,
}

SCORECARD_GROUPS = {
    "Authentication (SPF·DKIM·DMARC)": ["SPF", "DKIM", "DMARC"],
    "Transport (MTA-STS)": ["MTA-STS"],
    "Infrastructure (MX)": ["MX"],
    "DNS Integrity (DNSSEC)": ["DNSSEC"],
}


def ok(msg):
    print(f"  {GREEN}[OK]{RESET} {msg}")


def fail(msg):
    print(f"  {RED}[FAIL]{RESET} {msg}")


def warn(msg):
    print(f"  {YELLOW}[WARNING]{RESET} {msg}")


def info(msg):
    print(f"  {CYAN}[INFO]{RESET} {msg}")


def header(title):
    print(f"\n{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}")


def make_result(status, score=None, notes=None):
    """Build a standardized check result with status and score."""
    if score is None:
        score = STATUS_SCORES.get(status, 0)
    result = {"status": status, "score": max(0, min(10, score))}
    if notes:
        result["notes"] = notes
    return result


def score_bar(score, width=SCORE_BAR_WIDTH):
    filled = round(score / 10 * width)
    filled = max(0, min(width, filled))
    return "█" * filled + "░" * (width - filled)


def score_color(score):
    if score >= 8:
        return GREEN
    if score >= 5:
        return YELLOW
    return RED


def group_score(check_names, results):
    scores = [results[name]["score"] for name in check_names]
    return round(sum(scores) / len(scores), 1)


def dns_query(name, rdtype):
    """Query DNS with system resolver fallback. Returns (answers, None) or (None, error)."""
    attempts = [None] + FALLBACK_DNS
    for server in attempts:
        resolver = dns.resolver.Resolver()
        if server:
            resolver.nameservers = [server]
        resolver.timeout = 5
        resolver.lifetime = 10
        try:
            answers = resolver.resolve(name, rdtype)
            return answers, None
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return None, "NO_RECORD"
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as e:
            source = server if server else "system resolver"
            print(f"  {YELLOW}[WARNING]{RESET} Failed to query '{name}' ({rdtype}) via {source} "
                  f"({type(e).__name__}). Trying another DNS server...")
        except Exception as e:
            source = server if server else "system resolver"
            print(f"  {YELLOW}[WARNING]{RESET} Unexpected error querying '{name}' ({rdtype}) "
                  f"via {source}: {e}")

    print(f"  {RED}[FAIL]{RESET} Could not query '{name}' ({rdtype}) on any DNS server. "
          f"Check your connection/firewall.")
    return None, "QUERY_FAILED"


def get_txt_records(name):
    """Fetch TXT records for a DNS name. Returns a list of strings."""
    answers, err = dns_query(name, "TXT")
    if err or answers is None:
        return []

    records = []
    for rdata in answers:
        txt = "".join(
            part.decode() if isinstance(part, bytes) else part
            for part in rdata.strings
        )
        records.append(txt)
    return records


def check_spf(domain):
    header("1. SPF (Sender Policy Framework)")
    records = [r for r in get_txt_records(domain) if r.lower().startswith("v=spf1")]

    if not records:
        fail("No SPF record found.")
        info("Create a TXT record on the root domain starting with 'v=spf1'.")
        return make_result("FAIL")

    if len(records) > 1:
        fail(f"Found {len(records)} SPF records. There must be ONLY ONE.")
        for r in records:
            info(f"Record: {r}")
        return make_result("FAIL")

    record = records[0]
    ok(f"SPF record found: {record}")

    if re.search(r"-all\b", record):
        ok("Policy: '-all' (hard fail) — most secure configuration.")
        status = "OK"
    elif re.search(r"~all\b", record):
        warn("Policy: '~all' (soft fail) — acceptable, but '-all' is more secure.")
        status = "OK (can improve)"
    elif re.search(r"\?all\b", record):
        warn("Policy: '?all' (neutral) — provides virtually no protection.")
        status = "WEAK"
    elif re.search(r"\+all\b", record):
        fail("Policy: '+all' — ALLOWS ANY SERVER to send email for this domain!")
        status = "CRITICAL"
    else:
        warn("Record does not end with an 'all' mechanism. Define an explicit policy.")
        status = "INCOMPLETE"

    score = STATUS_SCORES[status]
    lookups = len(re.findall(r"\b(include:|a\b|mx\b|ptr\b|exists:|redirect=)", record))
    if lookups > 10:
        fail(f"Record uses {lookups} DNS lookup mechanisms (limit: 10). SPF may fail with 'permerror'.")
        score = max(0, score - 2)
    else:
        info(f"DNS lookup mechanisms: {lookups}/10.")

    return make_result(status, score)


def check_dkim(domain, custom_selector=None):
    header("2. DKIM (DomainKeys Identified Mail)")

    selectors = list(COMMON_DKIM_SELECTORS)
    if custom_selector:
        selectors.insert(0, custom_selector)

    found = {}
    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"
        records = get_txt_records(name)
        for r in records:
            if "v=dkim1" in r.lower() or "p=" in r.lower():
                found[selector] = r
                break

    if not found:
        fail("No DKIM record found among common selectors tested.")
        info("DKIM lives at '<selector>._domainkey.<domain>'. The selector is set")
        info("by your email provider (e.g. 'google', 'selector1'). If you know the")
        info("selector, pass it as the second argument: python mailscope.py domain selector")
        return make_result("NOT FOUND")

    best_score = 0
    has_revoked = False

    for selector, record in found.items():
        ok(f"Selector '{selector}' found.")
        match = re.search(r"p=([A-Za-z0-9+/=]*)", record)
        if match and match.group(1):
            key = match.group(1)
            key_bits = len(key) * 6
            if key_bits >= 2000:
                info("Public key present (~2048 bits or larger). Great.")
                best_score = max(best_score, 10)
            elif key_bits >= 1000:
                warn("Key appears to be ~1024 bits. Consider migrating to 2048 bits.")
                best_score = max(best_score, 8)
            else:
                warn("Public key is very short or non-RSA format (may be Ed25519).")
                best_score = max(best_score, 9)
        else:
            fail(f"Selector '{selector}' exists, but the public key is EMPTY (DKIM revoked).")
            has_revoked = True
            best_score = max(best_score, 2)

    if has_revoked and best_score <= 2:
        return make_result("FAIL", best_score)

    return make_result("OK", best_score)


def check_dmarc(domain):
    header("3. DMARC")
    name = f"_dmarc.{domain}"
    records = [r for r in get_txt_records(name) if r.lower().startswith("v=dmarc1")]

    if not records:
        fail("No DMARC record found.")
        info(f"Create a TXT record at '{name}' starting with 'v=DMARC1'.")
        return make_result("FAIL")

    record = records[0]
    ok(f"DMARC record found: {record}")

    policy_match = re.search(r"p=(\w+)", record)
    policy = policy_match.group(1).lower() if policy_match else None

    if policy == "reject":
        ok("Policy: 'p=reject' — maximum protection against spoofing.")
        status = "OK"
    elif policy == "quarantine":
        warn("Policy: 'p=quarantine' — good, but 'p=reject' is the ideal end state.")
        status = "OK (can improve)"
    elif policy == "none":
        warn("Policy: 'p=none' — monitoring only, does NOT block spoofing.")
        status = "WEAK"
    else:
        fail("Missing or invalid 'p=' tag. The DMARC record is malformed.")
        status = "FAIL"

    score = STATUS_SCORES[status]
    has_rua = "rua=" in record

    if status == "OK":
        score = 10 if has_rua else 9
    elif status == "OK (can improve)" and has_rua:
        score = 9

    if has_rua:
        info("Aggregate reports (rua=) configured — you receive usage reports.")
    else:
        warn("No 'rua=' — you will not receive reports. Configuring it is recommended.")

    pct_match = re.search(r"pct=(\d+)", record)
    if pct_match and int(pct_match.group(1)) < 100:
        warn(f"Policy applies to only {pct_match.group(1)}% of email (pct=).")
        score = max(0, score - 1)

    sp_match = re.search(r"sp=(\w+)", record)
    if sp_match:
        info(f"Subdomain policy: sp={sp_match.group(1)}.")

    return make_result(status, score)


def check_mta_sts(domain):
    header("4. MTA-STS")
    fail_score = make_result("FAIL", 0)

    name = f"_mta-sts.{domain}"
    records = [r for r in get_txt_records(name) if r.lower().startswith("v=stsv1")]

    if not records:
        fail(f"TXT record '{name}' not found.")
        info("MTA-STS requires a TXT 'v=STSv1; id=...' and a policy file over HTTPS.")
        return fail_score

    ok(f"DNS record found: {records[0]}")

    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    info(f"Fetching policy at: {url}")
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            fail(f"Policy file returned HTTP {resp.status_code}.")
            return make_result("FAIL", 2)

        policy_text = resp.text.strip()
        ok("Policy file found:")
        for line in policy_text.splitlines():
            print(f"      {line.strip()}")

        mode_match = re.search(r"mode:\s*(\w+)", policy_text)
        mode = mode_match.group(1).lower() if mode_match else None
        if mode == "enforce":
            ok("Mode: 'enforce' — TLS mandatory on delivery. Ideal configuration.")
            return make_result("OK", 10)
        if mode == "testing":
            warn("Mode: 'testing' — monitoring only, does not block insecure connections.")
            return make_result("OK (testing)", 6)
        if mode == "none":
            warn("Mode: 'none' — policy disabled.")
            return make_result("WEAK", 2)
        fail("Missing or invalid 'mode' field in the policy.")
        return make_result("FAIL", 2)

    except requests.exceptions.SSLError:
        fail("SSL certificate error fetching the policy (certificate must be valid).")
        return make_result("FAIL", 2)
    except requests.exceptions.RequestException as e:
        fail(f"Could not access the policy file: {e}")
        return fail_score


def hostname_resolves(hostname):
    """Return True if hostname has at least one A or AAAA record."""
    hostname = hostname.rstrip(".")
    for rdtype in ("A", "AAAA"):
        answers, err = dns_query(hostname, rdtype)
        if answers is not None and err != "QUERY_FAILED":
            return True
    return False


def check_mx(domain):
    header("5. MX (Mail Exchange)")
    answers, err = dns_query(domain, "MX")

    if err == "QUERY_FAILED":
        return make_result("FAIL")

    if err == "NO_RECORD" or answers is None:
        fail("No MX records found.")
        info("If this domain receives email, add MX records pointing to your mail servers.")
        return make_result("FAIL")

    mx_list = []
    for rdata in answers:
        priority = rdata.preference
        host = str(rdata.exchange).rstrip(".")
        mx_list.append((priority, host))

    mx_list.sort(key=lambda x: (x[0], x[1]))
    ok(f"Found {len(mx_list)} MX record(s):")
    for priority, host in mx_list:
        print(f"      {priority:>5}  {host}")

    lowest_priority = mx_list[0][0]
    primary = [h for p, h in mx_list if p == lowest_priority]
    if len(primary) == 1:
        info(f"Primary MX: {primary[0]} (priority {lowest_priority}).")
    else:
        info(f"{len(primary)} MX hosts share priority {lowest_priority} (load balancing).")

    single_mx = len(mx_list) == 1
    if single_mx:
        warn("Only one MX record — no redundancy if the mail server goes down.")

    unresolved = [host for _, host in mx_list if not hostname_resolves(host)]
    if unresolved:
        for host in unresolved:
            fail(f"MX host '{host}' does not resolve to A/AAAA — email delivery may fail.")
        return make_result("FAIL", 0)

    if single_mx:
        return make_result("OK (can improve)", 7)
    if len(primary) > 1:
        return make_result("OK", 9)
    return make_result("OK", 10)


def check_dnssec(domain):
    header("6. DNSSEC (DNS Security Extensions)")
    answers, err = dns_query(domain, "DNSKEY")

    if err == "QUERY_FAILED":
        return make_result("FAIL")

    if err == "NO_RECORD" or answers is None:
        fail("No DNSKEY records found — DNSSEC does not appear to be enabled.")
        info("DNSSEC signs DNS responses so clients can detect tampering (cache poisoning, "
             "record spoofing). Enable it at your DNS registrar/provider.")
        return make_result("FAIL", 0)

    key_count = len(list(answers))
    ok(f"Found {key_count} DNSKEY record(s) — zone signing keys are published.")

    algorithms = set()
    for rdata in answers:
        algorithms.add(rdata.algorithm)

    algo_names = {
        8: "RSA/SHA-256",
        13: "ECDSA P-256",
        14: "ECDSA P-384",
        15: "Ed25519",
        16: "Ed448",
    }
    for algo in sorted(algorithms):
        name = algo_names.get(algo, f"algorithm {algo}")
        info(f"Signing algorithm: {name}.")

    validated = False
    for server in FALLBACK_DNS:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server]
        resolver.timeout = 5
        resolver.lifetime = 10
        for rdtype in ("A", "AAAA", "MX"):
            try:
                response = resolver.resolve(domain, rdtype)
                if response.response.flags & dns.flags.AD:
                    validated = True
                    source = "Google Public DNS" if server == "8.8.8.8" else "Cloudflare DNS"
                    ok(f"DNS responses validated (AD flag set via {source}). Chain of trust OK.")
                    break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                    dns.exception.Timeout):
                continue
            except Exception:
                continue
        if validated:
            break

    if not validated:
        warn("DNSKEY records exist, but validating resolvers did not confirm the chain (AD flag).")
        warn("DNSSEC may be partially configured — check DS records at the parent zone.")
        return make_result("OK (can improve)", 7)

    return make_result("OK", 10)


def print_summary(domain, results):
    header(f"SUMMARY — {domain}")
    for check, data in results.items():
        status = data["status"]
        score = data["score"]
        if status.startswith("OK"):
            color = GREEN
        elif status in ("WEAK", "INCOMPLETE", "NOT FOUND"):
            color = YELLOW
        else:
            color = RED
        score_c = score_color(score)
        print(f"  {check:<10} {color}{status:<18}{RESET} {score_c}{score:>2}/10{RESET}")
    print()


def print_scorecard(results):
    header("SCORECARD")

    print(f"  {BOLD}{'Check':<10} {'Bar':<{SCORE_BAR_WIDTH + 2}} {'Score':>5}{RESET}")
    print(f"  {'-' * 32}")
    for check, data in results.items():
        score = data["score"]
        bar = score_bar(score)
        color = score_color(score)
        print(f"  {check:<10} {color}{bar}{RESET}  {color}{score:>4.0f}/10{RESET}")

    print()
    print(f"  {BOLD}{'Layer':<32} {'Bar':<{SCORE_BAR_WIDTH + 2}} {'Score':>5}{RESET}")
    print(f"  {'-' * 52}")
    for group, checks in SCORECARD_GROUPS.items():
        gs = group_score(checks, results)
        bar = score_bar(gs)
        color = score_color(gs)
        print(f"  {group:<32} {color}{bar}{RESET}  {color}{gs:>4.0f}/10{RESET}")

    overall = group_score(list(results.keys()), results)
    print()
    overall_color = score_color(overall)
    print(f"  {BOLD}{'Overall':<32} {overall_color}{score_bar(overall)}{RESET}  "
          f"{overall_color}{overall:>4.0f}/10{RESET}")
    print()


def main():
    print(f"{BOLD}{CYAN}")
    print("  ┌─────────────────────────────────────────┐")
    print("  │   MAILSCOPE — Email Security Scanner    │")
    print("  │   SPF · DKIM · DMARC · MTA-STS · MX     │")
    print("  │   DNSSEC                                │")
    print("  └─────────────────────────────────────────┘")
    print(RESET)

    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("Enter the domain (e.g. example.com): ").strip()

    domain = re.sub(r"^https?://", "", domain)
    domain = re.sub(r"^www\.", "", domain)
    domain = domain.split("/")[0].strip().lower()

    if not domain or "." not in domain:
        print(f"{RED}Invalid domain.{RESET}")
        sys.exit(1)

    custom_selector = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"\nAnalyzing: {BOLD}{domain}{RESET}")

    results = {
        "SPF": check_spf(domain),
        "DKIM": check_dkim(domain, custom_selector),
        "DMARC": check_dmarc(domain),
        "MTA-STS": check_mta_sts(domain),
        "MX": check_mx(domain),
        "DNSSEC": check_dnssec(domain),
    }

    print_summary(domain, results)
    print_scorecard(results)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user.")
