# MailGuard - Email Security Analyzer

A free, open-source web tool that analyzes your domain's email authentication security posture by checking DNS records for SPF, DKIM, and DMARC configurations.

**Live Url**:(https://helloyusuf-mailguard.streamlit.app) (free)


## 📋 Features

✅ **Instant DNS Analysis** - Analyze SPF, DKIM, and DMARC records in seconds  
✅ **Security Scoring** - Get a 0-100 score based on email authentication standards (RFC 7208, 6376, 7489)  
✅ **Issue Detection** - Identify 20+ common configuration issues and security gaps  
✅ **Actionable Recommendations** - Receive clear, prioritized guidance to improve your security  
✅ **Non-Technical Friendly** - Simple interface designed for users of all technical levels  
✅ **Privacy-First** - Stateless analysis, no data storage, no tracking  
✅ **Completely Free** - Open-source, free to use and deploy  


## 🔍 Understanding Email Authentication

### What is SPF (Sender Policy Framework)?

SPF is a DNS record that authorizes which mail servers can send emails for your domain.

- **SPF Record Format**: `v=spf1 include:provider.com -all`
- **Policy Types**:
  - `+all` = Accept all (unsafe, ❌ not recommended)
  - `~all` = Softfail, allow fallback (⚠️ warning)
  - `-all` = Hardfail, reject unauthorized (✅ recommended)
- **Best Practices**:
  - Use hardfail `-all` policy
  - Limit DNS lookups to 10 maximum
  - Monitor only (p=none) before enforcing

### What is DKIM (DomainKeys Identified Mail)?

DKIM adds a digital signature to your emails, proving they came from your domain.

- **DKIM Record Format**: `v=DKIM1; k=rsa; p=[public-key]`
- **Key Size**: 2048 bits minimum recommended (1024 is weak)
- **Algorithm**: SHA256 (SHA1 is deprecated)
- **Common Selectors**: default, k1, selector1, google, protonmail, sendgrid
- **Best Practices**:
  - Use 2048+ bit RSA keys
  - Use SHA256 algorithm
  - Monitor multiple selectors

### What is DMARC (Domain-based Message Authentication)?

DMARC ties SPF and DKIM together and tells email providers what to do with failed messages.

- **DMARC Record Format**: `v=DMARC1; p=quarantine; rua=mailto:reports@example.com`
- **Policy Levels**:
  - `p=none` = Monitor only (⚠️ no enforcement)
  - `p=quarantine` = Quarantine failed emails (⚠️ medium enforcement)
  - `p=reject` = Reject failed emails (✅ strong enforcement)
- **Alignment Modes**:
  - `dkim=relaxed` or `dkim=strict` (how DKIM is checked)
  - `spf=relaxed` or `spf=strict` (how SPF is checked)
- **Best Practices**:
  - Start with `p=none` to monitor
  - Progress to `p=quarantine` then `p=reject`
  - Configure reporting (rua for aggregate, ruf for forensics)
  - Set alignment to `strict` for both SPF and DKIM

---

## 📊 Scoring Methodology

Your security score is calculated as a weighted combination of three factors:

### Score Breakdown (0-100)

**SPF Component (35% of score, 0-35 points)**
- Valid SPF record exists: +25 points
- Strong policy (`-all` hardfail): +5 points
- Valid syntax and configuration: +5 points
- Penalties:
  - Multiple SPF records detected: -10 points
  - Softfail only (`~all`): -5 points
  - Exceeds 10 DNS lookup limit: -10 points
  - Missing or invalid SPF: 0 points

**DKIM Component (30% of score, 0-30 points)**
- DKIM record(s) found: +15 points
- Key size ≥2048 bits: +10 points
- Uses SHA256 algorithm: +5 points
- Penalties:
  - Key size <2048 bits: -8 points
  - SHA1 algorithm (deprecated): -5 points
  - Invalid syntax: -15 points
  - No DKIM found: 0 points

**DMARC Component (35% of score, 0-35 points)**
- DMARC record exists: +15 points
- Strong policy (reject or quarantine): +15 points
- Reporting configured (rua/ruf): +5 points
- Penalties:
  - Policy set to `p=none` (monitoring only): -10 points
  - No reporting addresses configured: -5 points
  - Invalid syntax: -15 points
  - No DMARC record: 0 points

### Score Interpretation

| Score | Status | Recommendation |
|-------|--------|-----------------|
| 90-100 | 🟢 Excellent | Your domain email security is well-configured. Continue monitoring. |
| 75-89 | 🟢 Good | Your configuration is solid. Consider adding missing features. |
| 50-74 | 🟡 Fair | Your setup has issues. Follow the recommendations below. |
| 0-49 | 🔴 Poor | Critical security gaps detected. Take immediate action. |

---

## 🛠️ Common Issues & Fixes

### Issue: Multiple SPF Records

**Problem**: RFC 5321 requires only ONE SPF record per domain  
**Solution**: Consolidate multiple SPF records into a single record using `include:` mechanisms

```
# ❌ Multiple records (WRONG)
v=spf1 include:provider1.com -all
v=spf1 include:provider2.com -all

# ✅ Single record (CORRECT)
v=spf1 include:provider1.com include:provider2.com -all
```

### Issue: SPF Lookup Limit Exceeded

**Problem**: SPF record triggers more than 10 DNS lookups  
**Solution**: Consolidate `include:` mechanisms or remove unused services

```
# Before: 11 lookups (FAILS)
v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com -all

# After: 2 lookups (PASSES)
v=spf1 include:consolidated.com -all
```

### Issue: Weak DKIM Keys

**Problem**: DKIM key is <2048 bits (e.g., 1024-bit key)  
**Solution**: Generate a new 2048-bit key and update DNS

```bash
# Generate new 2048-bit DKIM key
openssl genrsa 2048 > dkim_key.pem
openssl rsa -in dkim_key.pem -pubout | grep -v "BEGIN\|END"
```

### Issue: DMARC Policy Too Weak

**Problem**: DMARC is set to `p=none` (monitoring only)  
**Solution**: Progress through policies: none → quarantine → reject

```
# Stage 1: Monitor only
v=DMARC1; p=none; rua=mailto:reports@example.com

# Stage 2: Quarantine failing emails
v=DMARC1; p=quarantine; rua=mailto:reports@example.com; ruf=mailto:forensics@example.com

# Stage 3: Reject failing emails (final)
v=DMARC1; p=reject; rua=mailto:reports@example.com; ruf=mailto:forensics@example.com; fo=1
```

### Issue: DMARC Missing Reporting

**Problem**: DMARC configured but no reporting addresses  
**Solution**: Add `rua` (aggregate reports) and `ruf` (forensic reports)

```
# ❌ No reporting
v=DMARC1; p=quarantine

# ✅ With reporting
v=DMARC1; p=quarantine; rua=mailto:reports@example.com; ruf=mailto:forensics@example.com
```

---

## 🏗️ Technical Details

### Technology Stack

**Backend:**
- Python 3.8+
- Streamlit (web framework)
- dnspython (DNS resolution)

### How It Works

1. **User enters domain** → `example.com`
2. **Domain validation** → Check format (RFC 1123 compliant)
3. **DNS lookups** → Query authoritative nameservers:
   - SPF: Look up TXT record at `example.com`
   - DKIM: Check 12 common selectors (default, k1, selector1/2, google, protonmail, etc.)
   - DMARC: Look up TXT record at `_dmarc.example.com`
4. **Parse records** → Extract configuration details
5. **Validate syntax** → Check RFC compliance (7208, 6376, 7489)
6. **Calculate score** → Apply weighted scoring algorithm
7. **Generate report** → Display results with recommendations

### Data Privacy

✅ **Stateless** - No user data stored  
✅ **No tracking** - No analytics or cookies  
✅ **No logs** - DNS queries are not retained  
✅ **No external calls** - Only queries public DNS records  
✅ **HTTPS** - All communication is encrypted (Streamlit Cloud)  


## 🔐 Security & Compliance

### Standards Referenced

- **RFC 7208**: SPF (Sender Policy Framework)
- **RFC 6376**: DKIM (DomainKeys Identified Mail)
- **RFC 7489**: DMARC (Domain-based Message Authentication)
- **RFC 1035**: DNS Protocol
- **RFC 1123**: Host Requirements

### Security Notes

- Tool performs **read-only** DNS queries only
- No modifications to your DNS records
- No authentication required
- Rate limited to prevent abuse (Streamlit Cloud default)
- No sensitive data handled

---

## ⚖️ Disclaimers & Limitations

### Important Limitations

1. **Analysis is informational only** - This tool provides guidance but does not guarantee email deliverability
2. **Not a substitute for security audits** - For critical infrastructure, consult security professionals
3. **DNS propagation delays** - Changes to DNS records can take 24-48 hours to propagate globally
4. **Third-party integrations** - Analysis only covers standard DNS records; some email providers use proprietary methods
5. **Score is not certification** - A high score indicates configuration best practices but is not a security certification

### Liability

THIS TOOL IS PROVIDED "AS-IS" WITHOUT WARRANTY OF ANY KIND. THE AUTHORS ARE NOT LIABLE FOR:
- Incorrect analysis results
- DNS lookup failures
- DNS provider outages
- Data loss or service interruption
- Email delivery failures
- Security breaches or vulnerabilities
- Any indirect, incidental, or consequential damages

Use this tool at your own risk. For production environments, always validate results with DNS tools like `dig`, `nslookup`, or your DNS provider's interface.

## 📚 Additional Resources

### Email Authentication Learning

- [Google's Email Authentication Guide](https://support.google.com/a/answer/10737)
- [Microsoft Email Authentication](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/email-validation-and-authentication)
- [DMARC Deployment Best Practices](https://dmarcian.com/dmarc-deployment-best-practices](https://redsift.com/guides/dmarc-implementation)

### DNS Record Testing Tools

- `dig` command: `dig TXT example.com`
- `nslookup` command: `nslookup -type=TXT example.com`
- Online tools: MXToolbox, DMARCIAN, Google Admin Toolbox

---

## 📄 License

This project is open-source and built using AI.

---

## 👨‍💻 Author

**MailGuard** - Built with care for email security

Connect | Follow: https://www.linkedin.com/in/yusufranapurwala 

---

**Last Updated**: August 17, 2026  
**Version**: 1.0  
**Status**: Production Ready ✅
