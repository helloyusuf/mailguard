# MailGuard - Email Security Analyzer

## 🎯 What is MailGuard?

**MailGuard** is a free, open-source web tool that instantly analyzes your domain's email authentication security posture. Enter any domain name and get a detailed report on your SPF, DKIM, and DMARC configurations—all checked against industry security standards (RFC 7208, 6376, 7489).

Think of it as a health checkup for your domain's email security. It identifies configuration gaps, highlights security risks, and gives you clear, actionable recommendations to improve your protection.

---

## 📧 Who Should Use MailGuard?

✅ **Email Administrators** - Monitor and improve domain email security  
✅ **Domain Owners** - Verify your email setup is secure and compliant  
✅ **Security Professionals** - Quick assessment tool for client audits  
✅ **Business Owners** - Protect your brand from email spoofing and phishing  
✅ **Non-Technical Users** - Simple, clear interface with plain-language guidance  
✅ **IT Teams** - Free alternative to expensive email security audits  

---

## 💡 Why Email Authentication Matters

Email spoofing and phishing attacks are among the top security threats facing businesses today. Attackers can impersonate your domain and send fraudulent emails that appear legitimate to recipients.

**Email authentication protects you by:**
- Verifying emails actually come from your domain (SPF, DKIM)
- Telling email providers how to handle suspicious emails (DMARC)
- Building trust with recipients and email systems
- Reducing your emails going to spam
- Preventing brand damage from impersonation attacks

MailGuard helps you implement these protections quickly and correctly.

---

## 🎁 What You Get

✅ **Instant Analysis** - Analyze SPF, DKIM, and DMARC records in seconds  
✅ **Security Scoring** - 0-100 score showing your email authentication posture  
✅ **Issue Detection** - Identify 20+ common configuration problems  
✅ **Clear Recommendations** - Step-by-step guidance to fix each issue  
✅ **Plain Language** - Explanations designed for non-technical users  
✅ **Privacy-First** - No data storage, no tracking, read-only DNS queries  
✅ **100% Free** - Open-source, completely free to use and deploy  
✅ **No Account Needed** - Analyze any domain instantly  

---

## 🚀 Try It Now

No installation required! You can try MailGuard instantly:

1. **Visit**: [MailGuard online](https://mailguard-app.streamlit.app) *(when deployed)*
2. **Enter**: Your domain name (e.g., google.com, github.com, yourcompany.com)
3. **Click**: "Analyze Domain"
4. **View**: Your security score, findings, and recommendations

---

## 📊 How MailGuard Works

### The Analysis Process

When you enter a domain, MailGuard:

1. **Validates** your domain format
2. **Queries** public DNS records for SPF, DKIM, and DMARC
3. **Parses** the configuration data
4. **Checks** against RFC security standards
5. **Calculates** a weighted security score
6. **Generates** a report with findings and recommendations

All analysis is **read-only**—MailGuard never modifies your DNS records or stores any data.

---

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

## 💼 Common Use Cases

### For Email Administrators
"I need to audit our email security and make sure we're not vulnerable to spoofing attacks."

MailGuard provides a quick security assessment, identifies gaps, and shows exactly what needs to be fixed.

### For Domain Owners
"I want to verify my domain setup is secure and protect my brand reputation."

MailGuard checks if your SPF, DKIM, and DMARC are properly configured and provides plain-language recommendations.

### For Business Leaders
"Why do our emails go to spam? Are we at risk from email spoofing?"

MailGuard reveals configuration issues that affect deliverability and security, with clear explanations of the impact.

### For Security Teams
"We need to quickly assess client domains for email authentication vulnerabilities."

MailGuard provides detailed reports that can be shared with clients, complete with severity ratings and remediation steps.

### For DevOps/IT Teams
"We're moving to a new email provider and need to update our DNS records correctly."

MailGuard validates your new configuration is secure and RFC-compliant before deployment.

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

## 🔐 Compliance & Standards

MailGuard follows industry best practices and complies with email authentication standards:

- **RFC 7208** - SPF (Sender Policy Framework) specification
- **RFC 6376** - DKIM (DomainKeys Identified Mail) specification  
- **RFC 7489** - DMARC (Domain-based Message Authentication) specification
- **RFC 1035** - DNS Protocol specification
- **RFC 1123** - Host Requirements specification

All recommendations are based on these official standards and security best practices.

---

## ⚖️ Important Disclaimers

### Limitations

1. **Informational Only** - This tool provides guidance but does not guarantee email deliverability
2. **Not a Security Audit** - For critical infrastructure, consult professional security experts
3. **DNS Propagation** - Changes to DNS records can take 24-48 hours to propagate globally
4. **Third-Party Integrations** - Some email providers use proprietary authentication methods not covered here
5. **Score is Not Certification** - A high score indicates best practices but is not an official certification

### Liability Notice

THIS TOOL IS PROVIDED "AS-IS" WITHOUT ANY WARRANTY. THE CREATORS ARE NOT LIABLE FOR:
- Incorrect or inaccurate analysis results
- DNS lookup failures or timeouts
- Email delivery problems or failures
- Security breaches or vulnerabilities
- Data loss or service interruptions
- Any indirect or consequential damages

**Use this tool at your own risk.** For production environments, always validate results with DNS tools (`dig`, `nslookup`) or your DNS provider's interface before making changes.

---

## 🏗️ Technical Details

### Technology Stack

**Backend:**
- Python 3.8+
- Streamlit (web framework)
- dnspython (DNS resolution)

**Deployment:**
- Streamlit Cloud (recommended, free)
- GitHub + Netlify (alternative)
- Replit (alternative)
- Self-hosted (Docker supported)

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


---

## 📥 Get Started (Installation & Deployment)

### Option 1: Try Online (Easiest - Recommended)

No installation needed! When deployed:

1. Visit: `https://mailguard-app.streamlit.app`
2. Enter your domain name
3. Click "Analyze"
4. View your security report

### Option 2: Deploy Your Own Copy (Free - 5 minutes)

**Step 1: Create GitHub Repository**
- Go to [GitHub.com](https://github.com) and create a free account
- Click **New Repository**
- Name it `mailguard`
- Upload these 3 files: `app.py`, `requirements.txt`, `README.md`

**Step 2: Deploy on Streamlit Cloud (Free)**
- Go to [streamlit.io/cloud](https://streamlit.io/cloud)
- Click **New app** and sign in with GitHub
- Select your `mailguard` repository
- Select `app.py` as main file
- Click **Deploy**
- Your app is live in 2-3 minutes! ✅

### Option 3: Run Locally (For Developers)

```bash
# Clone repository
git clone https://github.com/yourusername/mailguard.git
cd mailguard

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py

# Open: http://localhost:8501
```

**Requirements:**
- Python 3.8+
- pip package manager

### Option 4: Self-Hosted (Advanced)

```bash
# Using Docker
docker build -t mailguard .
docker run -p 8501:8501 mailguard

# Or any Python-capable server
pip install -r requirements.txt
streamlit run app.py --server.port 8501 --server.address 0.0.0.0
```

---

## 📁 Project Files

- **app.py** (34 KB) - Complete MailGuard application with UI and DNS analysis
- **requirements.txt** (35 bytes) - Python dependencies (Streamlit + dnspython)
- **README.md** (This file) - Documentation and guides

That's all you need to run MailGuard!

---

## 🔒 Data Privacy & Security

✅ **No Data Storage** - Analysis is performed in-memory and not saved  
✅ **No Tracking** - No analytics, cookies, or user tracking  
✅ **No External Calls** - Only queries public DNS records  
✅ **Read-Only** - Never modifies DNS or any data  
✅ **HTTPS Encrypted** - All communication is encrypted  
✅ **No Account Required** - Use anonymously  

---

## 📄 License

This project is open-source and available under the MIT License.

---

## 🤝 Questions or Issues?

- Found a bug? Open an issue on GitHub
- Have a feature request? Create a GitHub issue
- Need help? Check the "How to Use" tab in the app

---

**MailGuard** - Protecting your domain's email security  
**Version**: 1.0 | **Last Updated**: August 17, 2026 | **Status**: Production Ready ✅
