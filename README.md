# 🔭 MailScope

> A deep scope into your domain's email security.

A Python script that analyzes the email security of any domain by checking **SPF**, **DKIM**, **DMARC**, **MTA-STS**, **MX records**, and **DNSSEC**.

All checks use **public DNS queries** (and HTTPS for MTA-STS only) — **no external APIs** required.

[🇧🇷 Versão em português](README.pt.md)

---

## 🚀 How to run

### 1. Prerequisites

- Python 3.8 or higher
- Install the dependencies:

```bash
pip install -r requirements.txt
```

(or manually: `pip install dnspython requests`)

### 2. Run

**Interactive mode** (the script asks for the domain):

```bash
python mailscope.py
```

**Direct mode** (domain as an argument):

```bash
python mailscope.py example.com
```

**Providing the DKIM selector** (second argument, optional):

```bash
python mailscope.py example.com google
```

> 💡 Type only the domain, without `https://` or `www` — the script cleans that up automatically.

---

## 🔍 What each check does

### 1. SPF (Sender Policy Framework)

**What it is:** a TXT record in DNS that lists which servers are authorized to send email on behalf of the domain. Without it, anyone can send emails "pretending" to be your domain.

**How the script checks it:** looks for TXT records on the root domain starting with `v=spf1`.

**Possible results:**

| Result | Meaning |
|---|---|
| `[OK]` with `-all` | Hard fail — unauthorized servers are rejected. **Ideal configuration.** |
| `[WARNING]` with `~all` | Soft fail — suspicious emails are flagged but not rejected. Acceptable. |
| `[WARNING]` with `?all` | Neutral — provides virtually no protection. |
| `[FAIL]` with `+all` | **Critical** — authorizes any server in the world to send email as your domain. |
| `[FAIL]` no record | No SPF exists. Create a TXT record in your DNS. |
| `[FAIL]` duplicate records | More than one SPF record causes a validation error (`permerror`). |

The script also counts the **DNS lookups** (`include:`, `mx`, `a`, etc.). RFC 7208 limits them to 10 — beyond that, SPF breaks.

**Risks mitigated when OK (`-all`):** sender spoofing; unauthorized sending; spam/phishing abusing your brand.

---

### 2. DKIM (DomainKeys Identified Mail)

**What it is:** a cryptographic signature added to outgoing emails. The receiving server validates the signature using the public key published in DNS, ensuring the message was not altered and really came from the domain.

**How the script checks it:** DKIM lives at `<selector>._domainkey.<domain>`. Since the selector varies by provider, the script automatically tests the most common ones in the market:

- `google` (Google Workspace)
- `selector1`, `selector2` (Microsoft 365)
- `k1`, `k2` (Mailchimp)
- `s1`, `s2` (SendGrid)
- `amazonses` (Amazon SES)
- among others

**Possible results:**

| Result | Meaning |
|---|---|
| `[OK]` selector found | DKIM is published. The script also evaluates the key size. |
| `[INFO]` ~2048-bit key | Currently recommended size. |
| `[WARNING]` ~1024-bit key | Works, but is considered weak. Migrate to 2048. |
| `[FAIL]` empty key (`p=`) | The selector exists but the key has been revoked. |
| `[NOT FOUND]` | No common selector responded. **This does not mean DKIM doesn't exist** — provide your provider's selector manually. |

**Risks mitigated when OK:** message tampering in transit; repudiation of legitimate email; DMARC alignment failures.

---

### 3. DMARC

**What it is:** a policy that tells receiving servers **what to do** when an email fails SPF or DKIM (deliver, quarantine, or reject). It also enables reports about who is sending email using your domain.

**How the script checks it:** looks up the TXT record at `_dmarc.<domain>` starting with `v=DMARC1`.

**Possible results:**

| Result | Meaning |
|---|---|
| `[OK]` `p=reject` | Fraudulent emails are rejected. **Maximum protection.** |
| `[WARNING]` `p=quarantine` | Suspicious emails go to spam. Good intermediate stage. |
| `[WARNING]` `p=none` | Monitoring only — **does not block spoofing**. Use only in the initial phase. |
| `[FAIL]` no record | Without DMARC, SPF and DKIM lose much of their effectiveness. |
| `[WARNING]` no `rua=` | You won't receive aggregate reports. Configuring it is recommended. |
| `[WARNING]` `pct=` < 100 | The policy only applies to a portion of the emails. |

**Risks mitigated when OK (`p=reject`):** delivery of fraudulent email; unblocked spoofing; no visibility into domain abuse.

---

### 4. MTA-STS

**What it is:** a mechanism that forces mail servers to use **TLS (encryption)** when delivering messages to your domain, preventing interception attacks (downgrade/man-in-the-middle).

**How the script checks it** (two steps):

1. **DNS:** TXT record at `_mta-sts.<domain>` with `v=STSv1; id=...`
2. **HTTPS:** policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt`

**Possible results:**

| Result | Meaning |
|---|---|
| `[OK]` `mode: enforce` | TLS is mandatory on delivery. **Ideal configuration.** |
| `[WARNING]` `mode: testing` | Monitoring only, does not block insecure connections. |
| `[WARNING]` `mode: none` | The policy exists but is disabled. |
| `[FAIL]` no DNS record | MTA-STS is not configured (the case for most domains). |
| `[FAIL]` HTTP ≠ 200 or SSL error | The DNS record exists, but the policy file is unreachable or the certificate is invalid. |

**Risks mitigated when OK (`mode: enforce`):** email interception in transit (MITM); TLS downgrade to unencrypted connections; plaintext message exposure on the network.

---

### 5. MX (Mail Exchange)

**What it is:** DNS records that specify **which servers receive email** for the domain, with numeric priority (lower = preferred).

**How the script checks it:** queries MX records via DNS (no API). Lists priority and hostname, verifies each host resolves to A/AAAA, and warns about missing redundancy.

**Possible results:**

| Result | Meaning |
|---|---|
| `[OK]` MX found and resolving | Inbound mail servers configured and reachable. |
| `[WARNING]` only 1 MX | No redundancy — server outage stops inbound mail. |
| `[FAIL]` no MX | Domain does not receive email (or record missing). |
| `[FAIL]` MX host does not resolve | Email delivery will likely fail. |

**Risks mitigated when OK:** silent mail loss from missing/broken MX; delivery failures from invalid hostnames; clear visibility into inbound infrastructure.

---

### 6. DNSSEC (DNS Security Extensions)

**What it is:** a DNS extension that **cryptographically signs** records so clients can detect forged or altered responses.

**How the script checks it:** queries DNSKEY records and, on validating resolvers (Google 8.8.8.8, Cloudflare 1.1.1.1), checks the AD (Authenticated Data) flag on the chain of trust. **DNS only — no API.**

**Possible results:**

| Result | Meaning |
|---|---|
| `[OK]` DNSKEY + AD confirmed | DNSSEC active and chain of trust validated. |
| `[WARNING]` DNSKEY without AD | Keys published but chain incomplete (check DS at registrar). |
| `[FAIL]` no DNSKEY | DNSSEC not enabled — DNS records can be spoofed. |

**Risks mitigated when OK:** DNS cache poisoning; spoofed SPF/DKIM/DMARC records; MX hijacking to malicious servers; poisoned DNS responses.

---

## 🛡️ Mitigated risks by category (when fully OK)

When each check returns **OK** at the ideal configuration, these are the main risks that are mitigated:

| Category | Ideal status | Mitigated risks |
|----------|--------------|-----------------|
| **SPF** | `-all` (hard fail) | Sender spoofing; unauthorized sending; spam/phishing using your brand |
| **DKIM** | Active selector, 2048-bit key | Content tampering in transit; repudiation of legitimate messages; DMARC alignment failure |
| **DMARC** | `p=reject` + `rua=` | Delivery of fraudulent email; undetected spoofing; no visibility into domain abuse |
| **MTA-STS** | `mode: enforce` | MITM interception; TLS downgrade; plaintext email on the wire |
| **MX** | Multiple resolving MX records | Total mail loss from missing MX; silent failure from bad hostnames; single point of failure (with redundancy) |
| **DNSSEC** | DNSKEY + validated chain | DNS poisoning; forged SPF/DKIM/DMARC; MX hijack to attacker server |

> **Note:** OK on SPF/DKIM/DMARC does not replace MTA-STS (transport layer) or DNSSEC (DNS integrity). Full protection requires all layers relevant to your scenario.

### Score mapping (0–10)

| Check | 10/10 | 8–9 | 6–7 | 3–5 | 0–2 |
|-------|-------|-----|-----|-----|-----|
| **SPF** | `-all` | `~all` | — | `?all`, incomplete | missing, `+all`, duplicate |
| **DKIM** | 2048+ bit key | 1024 bit key | — | not found | revoked key |
| **DMARC** | `p=reject` + `rua=` | `p=reject` no `rua`, or `quarantine` | — | `p=none` | missing / malformed |
| **MTA-STS** | `mode: enforce` | — | `mode: testing` | — | missing / invalid |
| **MX** | multiple MX | load balanced | 1 working MX | — | missing / bad host |
| **DNSSEC** | DNSKEY + AD validated | partial DNSKEY | — | — | disabled |

---

## 📊 Summary and scorecard

When finished, the script displays a consolidated panel with **0–10 scores** and a **SCORECARD** with visual bars per check and per layer (Authentication, Transport, Infrastructure, DNS Integrity):

```
============================================================
  SUMMARY — example.com
============================================================
  SPF        OK                 10/10
  DKIM       OK                  8/10
  DMARC      OK                  9/10
  MTA-STS    FAIL                0/10
  MX         OK (can improve)     7/10
  DNSSEC     FAIL                0/10

============================================================
  SCORECARD
============================================================
  Authentication (SPF·DKIM·DMARC)  █████████░   9/10
  Transport (MTA-STS)              ░░░░░░░░░░   0/10
  Infrastructure (MX)              ███████░░░   7/10
  DNS Integrity (DNSSEC)           ░░░░░░░░░░   0/10

  Overall                          ██████░░░░   6/10
```

- 🟢 **Green (OK):** correctly configured
- 🟡 **Yellow (WEAK / can improve):** exists, but the configuration can be hardened
- 🔴 **Red (FAIL / CRITICAL):** absent or dangerously misconfigured

---

## 🧠 How the code works (overview)

| Function | Responsibility |
|---|---|
| `get_txt_records(name)` | Queries TXT records with fallback to Google (8.8.8.8) and Cloudflare (1.1.1.1). |
| `dns_query(name, rdtype)` | Generic DNS query (MX, DNSKEY, A, AAAA…) with the same fallback. **No external API.** |
| `check_spf(domain)` | Filters `v=spf1` TXT, validates duplicates, final qualifier, and DNS lookups. |
| `check_dkim(domain, selector)` | Tests common selectors at `<selector>._domainkey.<domain>` and evaluates the public key. |
| `check_dmarc(domain)` | Queries `_dmarc.<domain>`, extracts `p=`, `rua=`, `pct=`, and `sp=`. |
| `check_mta_sts(domain)` | Queries `_mta-sts` TXT and fetches the policy file over HTTPS. |
| `check_mx(domain)` | Lists MX records, priorities, host resolution, and redundancy. |
| `check_dnssec(domain)` | Checks DNSKEY and AD flag on validating resolvers. |
| `print_summary()` | Color-coded status panel with scores per check. |
| `print_scorecard()` | Visual score bars grouped by security layer plus overall score. |
| `main()` | Reads the domain, sanitizes input, and runs all six checks. |

---

## ⚠️ Notes

- The script performs **public queries only** (DNS and HTTPS for MTA-STS) — **no third-party APIs** and no email is sent.
- MX and DNSSEC are checked exclusively via the DNS protocol (`dnspython`).
- For DKIM, if your provider uses an uncommon selector, find it in the header of an email sent from the domain (`DKIM-Signature` field, `s=` tag) and provide it to the script.
- Online tools like MXToolbox can be used to compare the results.

---

## 📁 Additional documentation

| File | Description |
|------|-------------|
| [README.pt.md](README.pt.md) | Portuguese documentation (complementary) |
| [docs/GITHUB.md](docs/GITHUB.md) | Guide to create and publish the repository on GitHub |
| [docs/REPOSITORY.md](docs/REPOSITORY.md) | GitHub repository description (English) and topics |
| [docs/guia-medium-pt.docx](docs/guia-medium-pt.docx) | Portuguese article/guide (Medium) |
| [docs/guide-medium-en.docx](docs/guide-medium-en.docx) | English article/guide (Medium) |

To regenerate the `.docx` files after editing content:

```bash
pip install python-docx
python scripts/generate_docs.py
```
