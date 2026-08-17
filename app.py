import streamlit as st
import dns.resolver
import dns.rdatatype
import re
from typing import Dict, Tuple, List

# Page configuration
st.set_page_config(
    page_title="MailGuard - Domain Email Security Analyzer",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS
st.markdown("""
    <style>
    .big-score-excellent { color: #22C55E; font-size: 56px; font-weight: bold; text-align: center; margin: 10px 0; }
    .big-score-good { color: #84CC16; font-size: 56px; font-weight: bold; text-align: center; margin: 10px 0; }
    .big-score-fair { color: #EAB308; font-size: 56px; font-weight: bold; text-align: center; margin: 10px 0; }
    .big-score-poor { color: #EF4444; font-size: 56px; font-weight: bold; text-align: center; margin: 10px 0; }
    .action-critical { padding: 12px; border-radius: 6px; border-left: 4px solid #ef4444; background-color: #fee2e2; margin: 8px 0; }
    .action-warning { padding: 12px; border-radius: 6px; border-left: 4px solid #f59e0b; background-color: #fef3c7; margin: 8px 0; }
    .action-success { padding: 12px; border-radius: 6px; border-left: 4px solid #22c55e; background-color: #f0fdf4; margin: 8px 0; }
    .metric-card { padding: 20px; border-radius: 10px; background-color: #f8fafc; text-align: center; border: 1px solid #e2e8f0; }
    </style>
""", unsafe_allow_html=True)

def validate_domain(domain: str) -> Tuple[bool, str]:
    """Validate and normalize domain format"""
    domain = domain.strip().lower()

    # Remove common prefixes
    domain = re.sub(r'^(https?://|www\.)', '', domain)

    # Remove trailing dot
    if domain.endswith('.'):
        domain = domain[:-1]

    # Validate length
    if not domain or len(domain) < 3 or len(domain) > 253:
        return False, "Domain must be 3-253 characters"

    # Validate format (RFC 1123)
    pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
    if not re.match(pattern, domain):
        return False, "Invalid domain format (use letters, numbers, hyphens, dots)"

    return True, domain

def analyze_spf(domain: str) -> Dict:
    """Analyze SPF record with detailed actions"""
    try:
        answers = dns.resolver.resolve(domain, dns.rdatatype.TXT, lifetime=5)
        spf_records = []
        for rdata in answers:
            record_str = str(rdata).strip('"')
            if 'v=spf1' in record_str:
                spf_records.append(record_str)

        if not spf_records:
            return {
                'found': False, 'records': [], 'status': '🔴 Critical', 'score': 0,
                'message': 'No SPF record found',
                'actions': [
                    ('critical', 'Add SPF Record', f'Create TXT record: v=spf1 include:mail-provider.com -all'),
                    ('info', 'SPF Basics', 'Authorizes which servers can send email from your domain')
                ]
            }

        # Check for multiple SPF records (RFC violation)
        if len(spf_records) > 1:
            return {
                'found': True, 'records': spf_records, 'status': '🔴 Critical', 'score': 5,
                'message': f'RFC Violation: {len(spf_records)} SPF records found (RFC allows only 1)',
                'actions': [
                    ('critical', 'Consolidate SPF Records', f'Merge {len(spf_records)} records into 1 using "include:" mechanisms'),
                ]
            }

        spf_record = spf_records[0]
        score = 25
        actions = []

        # Analyze policy
        if '-all' in spf_record:
            score += 5
        elif '~all' in spf_record:
            score += 2
            actions.append(('warning', 'Upgrade to Hardfail', 'Change ~all to -all for strict sender validation'))
        elif '+all' in spf_record:
            score = 0
            actions.append(('critical', 'Remove +all (Reject Policy)', '+all allows everyone - use -all instead'))
        else:
            score = max(0, score - 5)
            actions.append(('warning', 'Add Policy Terminator', 'End SPF record with -all (hardfail)'))

        # Count DNS lookups
        mechanisms = (spf_record.count('include:') +
                     spf_record.count('a:') +
                     spf_record.count('mx:') +
                     spf_record.count('ptr:'))

        if mechanisms > 10:
            score = max(0, score - 10)
            actions.append(('critical', f'Reduce DNS Lookups ({mechanisms}/10)',
                          'Use fewer "include:" statements - consolidate mail services'))
        elif mechanisms >= 8:
            actions.append(('warning', f'High DNS Lookups ({mechanisms}/10)',
                          'Close to limit - plan before adding more services'))

        if not actions:
            actions.append(('success', 'SPF Properly Configured', 'No changes needed'))

        status = '🟢 Healthy' if score >= 28 else '🟡 Warning'
        return {
            'found': True, 'records': spf_records, 'status': status, 'score': score,
            'message': 'SPF record analyzed',
            'actions': actions
        }

    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return {
            'found': False, 'records': [], 'status': '🔴 Critical', 'score': 0,
            'message': 'Domain not found or unreachable',
            'actions': [('critical', 'Check Domain Name', 'Verify domain is correct and DNS is responding')]
        }
    except dns.exception.Timeout:
        return {
            'found': False, 'records': [], 'status': '🔴 Critical', 'score': 0,
            'message': 'DNS lookup timed out',
            'actions': [('critical', 'DNS Timeout', 'Check your internet connection')]
        }
    except Exception as e:
        return {
            'found': False, 'records': [], 'status': '🔴 Critical', 'score': 0,
            'message': f'Error: {str(e)[:50]}',
            'actions': [('critical', 'DNS Error', 'Check domain and try again')]
        }

def analyze_dkim(domain: str) -> Dict:
    """Analyze DKIM records"""
    selectors = ['default', 'k1', 'selector1', 'selector2', 'google', 'protonmail', 'sendgrid', 'mailgun', 'ses', 'amazonses', 'mail', 'dkim']
    found_records = []

    for selector in selectors:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, dns.rdatatype.TXT, lifetime=5)
            for rdata in answers:
                record = str(rdata).strip('"')
                if 'v=DKIM1' in record:
                    found_records.append({'selector': selector, 'record': record})
        except:
            continue

    if not found_records:
        return {
            'found': False, 'records': [], 'status': '🔴 Critical', 'score': 0,
            'message': 'No DKIM records found',
            'actions': [
                ('critical', 'Add DKIM Keys', 'Generate RSA-2048 key pair and publish public key as TXT record'),
                ('info', 'Check Selectors', 'Try: default, selector1, selector2, google, protonmail, sendgrid')
            ]
        }

    score = 15
    actions = []

    for rec_info in found_records:
        record = rec_info['record']
        selector = rec_info['selector']

        # Check for public key
        if 'p=' not in record:
            actions.append(('critical', f'Selector "{selector}" - Missing Public Key', 'Add p= field with RSA public key'))
        else:
            # Check key strength (rough estimate)
            key_section = record[record.find('p='):record.find('p=')+100] if 'p=' in record else ''
            if len(record) > 350:  # 2048-bit key produces ~340-350 char record
                score = min(score + 10, 30)
            else:
                actions.append(('warning', f'Selector "{selector}" - Weak Key', 'Upgrade to RSA-2048 bit key (current key too small)'))

        # Check algorithm
        if 'h=sha256' in record:
            score = min(score + 5, 30)
        elif 'h=sha1' in record:
            actions.append(('warning', f'Selector "{selector}" - Old Algorithm', 'Replace SHA1 with SHA256 (SHA1 deprecated)'))
        elif 'h=' not in record:
            actions.append(('info', f'Selector "{selector}" - Algorithm not specified', 'Usually defaults to SHA1 - consider adding h=sha256'))

    if not actions:
        actions.append(('success', f'DKIM Properly Configured', f'{len(found_records)} valid DKIM record(s) found'))

    status = '🟢 Healthy' if score >= 28 else '🟡 Warning'
    return {
        'found': True, 'records': found_records, 'status': status, 'score': min(score, 30),
        'message': f'{len(found_records)} DKIM record(s) found',
        'actions': actions
    }

def analyze_dmarc(domain: str) -> Dict:
    """Analyze DMARC record"""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, dns.rdatatype.TXT, lifetime=5)
        dmarc_records = []
        for rdata in answers:
            record = str(rdata).strip('"')
            if 'v=DMARC1' in record:
                dmarc_records.append(record)

        if not dmarc_records:
            return {
                'found': False, 'records': [], 'status': '🔴 Critical', 'score': 0,
                'message': 'No DMARC record found',
                'actions': [
                    ('critical', 'Create DMARC Record', 'Start with: v=DMARC1; p=none; rua=mailto:reports@domain.com'),
                    ('info', 'Phased Approach', 'Step 1: p=none → Step 2: p=quarantine → Step 3: p=reject')
                ]
            }

        dmarc_record = dmarc_records[0]
        score = 15
        actions = []

        # Check policy
        if 'p=reject' in dmarc_record:
            score += 15
            actions.append(('success', 'Strong Policy: p=reject', 'Maximum enforcement - rejecting failed emails'))
        elif 'p=quarantine' in dmarc_record:
            score += 12
            actions.append(('info', 'Medium Policy: p=quarantine', 'Good balance - consider upgrading to p=reject'))
        elif 'p=none' in dmarc_record:
            score += 5
            actions.append(('warning', 'Monitoring Only: p=none', 'Currently monitoring - upgrade to p=quarantine when confident'))
        else:
            actions.append(('critical', 'No Policy Specified', 'Add p=reject, p=quarantine, or p=none'))

        # Check reporting
        has_rua = 'rua=' in dmarc_record
        has_ruf = 'ruf=' in dmarc_record

        if has_rua:
            actions.append(('success', 'Aggregate Reports Enabled', 'Receiving daily authentication reports'))
        else:
            actions.append(('warning', 'No Aggregate Reports', 'Add rua=mailto:reports@domain.com for insights'))

        if has_ruf:
            actions.append(('info', 'Forensic Reports Enabled', 'Detailed failure notifications configured'))
        else:
            actions.append(('info', 'No Forensic Reports', 'Optional: Add ruf=mailto:forensics@domain.com'))

        # Check alignment
        if 'dkim=strict' in dmarc_record or 'spf=strict' in dmarc_record:
            actions.append(('success', 'Strict Alignment Enabled', 'High security - requiring exact domain match'))
        else:
            actions.append(('info', 'Relaxed Alignment', 'Optional: Use strict mode for higher security'))

        status = '🟢 Healthy' if score >= 28 else '🟡 Warning'
        return {
            'found': True, 'records': dmarc_records, 'status': status, 'score': min(score, 35),
            'message': 'DMARC record analyzed',
            'actions': actions
        }

    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return {
            'found': False, 'records': [], 'status': '🔴 Critical', 'score': 0,
            'message': 'DMARC record not found',
            'actions': [('critical', 'Add DMARC Record', 'Create _dmarc TXT record at domain root')]
        }
    except dns.exception.Timeout:
        return {
            'found': False, 'records': [], 'status': '🔴 Critical', 'score': 0,
            'message': 'DNS lookup timed out',
            'actions': [('critical', 'Timeout Error', 'Check connection and try again')]
        }
    except Exception as e:
        return {
            'found': False, 'records': [], 'status': '🔴 Critical', 'score': 0,
            'message': f'Error: {str(e)[:50]}',
            'actions': [('critical', 'DNS Error', 'Unable to query DMARC record')]
        }

def calculate_overall_score(spf: int, dkim: int, dmarc: int) -> int:
    """Calculate weighted security score (0-100)"""
    return int((spf * 0.35) + (dkim * 0.30) + (dmarc * 0.35))

# ============================================
# MAIN INTERFACE
# ============================================

# Header Navigation
col1, col2 = st.columns([4, 1])
with col1:
    st.title("🔒 MailGuard")
    st.markdown("*Analyze your Domain Email Security*")

# Navigation
st.markdown("---")
nav = st.radio("", ["🔍 Analyzer", "📚 Learn", "ℹ️ About"], horizontal=True, label_visibility="collapsed")

if nav == "🔍 Analyzer":
    st.markdown("### Analyze your Domain Email Security")

    # Input Section
    col1, col2 = st.columns([3, 1])
    with col1:
        domain_input = st.text_input("Enter domain:", placeholder="microsoft.com, google.com, github.com", label_visibility="collapsed")
    with col2:
        st.markdown("")
        analyze_btn = st.button("🔍 Analyze", use_container_width=True)

    # Quick Guide
    st.markdown("""
    **Quick Guide:**
    1. Enter any domain name
    2. We check SPF, DKIM, and DMARC records
    3. You get a security score + action items
    """)

    if analyze_btn and domain_input:
        is_valid, domain = validate_domain(domain_input)
        if not is_valid:
            st.error(f"❌ {domain}")
        else:
            st.markdown("---")

            with st.spinner(f"🔍 Analyzing **{domain}**..."):
                spf = analyze_spf(domain)
                dkim = analyze_dkim(domain)
                dmarc = analyze_dmarc(domain)
                overall = calculate_overall_score(spf['score'], dkim['score'], dmarc['score'])

            # Overall Score Display
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                if overall >= 90:
                    st.markdown(f"<div class='big-score-excellent'>{overall}</div>", unsafe_allow_html=True)
                    st.markdown("#### 🟢 Excellent", help="Your domain has strong email authentication")
                elif overall >= 75:
                    st.markdown(f"<div class='big-score-good'>{overall}</div>", unsafe_allow_html=True)
                    st.markdown("#### 🟢 Good", help="Your configuration is solid")
                elif overall >= 50:
                    st.markdown(f"<div class='big-score-fair'>{overall}</div>", unsafe_allow_html=True)
                    st.markdown("#### 🟡 Fair", help="Some issues to address")
                else:
                    st.markdown(f"<div class='big-score-poor'>{overall}</div>", unsafe_allow_html=True)
                    st.markdown("#### 🔴 Poor", help="Critical issues detected")
                st.markdown("**Overall Score**")

            with col2:
                st.markdown(f"<div class='metric-card'><h2>{spf['score']}</h2><p>SPF (35%)</p></div>", unsafe_allow_html=True)

            with col3:
                st.markdown(f"<div class='metric-card'><h2>{dkim['score']}</h2><p>DKIM (30%)</p></div>", unsafe_allow_html=True)

            with col4:
                st.markdown(f"<div class='metric-card'><h2>{dmarc['score']}</h2><p>DMARC (35%)</p></div>", unsafe_allow_html=True)

            st.markdown("---")

            # Action Items (All results combined)
            st.markdown("### 📋 Recommended Actions")

            all_actions = spf['actions'] + dkim['actions'] + dmarc['actions']
            critical = [a for a in all_actions if a[0] == 'critical']
            warnings = [a for a in all_actions if a[0] == 'warning']
            success = [a for a in all_actions if a[0] == 'success']
            info = [a for a in all_actions if a[0] == 'info']

            if critical:
                st.markdown("#### 🔴 Critical - Act Now")
                for _, title, desc in critical:
                    st.markdown(f"<div class='action-critical'><b>➜ {title}</b><br>{desc}</div>", unsafe_allow_html=True)

            if warnings:
                st.markdown("#### 🟡 Important - Soon")
                for _, title, desc in warnings:
                    st.markdown(f"<div class='action-warning'><b>➜ {title}</b><br>{desc}</div>", unsafe_allow_html=True)

            if success:
                st.markdown("#### 🟢 Good - Maintain")
                for _, title, desc in success:
                    st.markdown(f"<div class='action-success'><b>✓ {title}</b><br>{desc}</div>", unsafe_allow_html=True)

            if info:
                st.markdown("#### ℹ️ Optional Improvements")
                for _, title, desc in info:
                    st.markdown(f"<div class='action-warning' style='border-left-color: #3b82f6;'><b>💡 {title}</b><br>{desc}</div>", unsafe_allow_html=True)

            st.markdown("---")

            # Detailed Records
            st.markdown("### 📊 Detailed Results")

            col1, col2, col3 = st.columns(3)

            with col1:
                st.markdown(f"**SPF** {spf['status']}")
                st.markdown(f"Score: `{spf['score']}/35`")
                if spf['found']:
                    with st.expander("View Record"):
                        for record in spf['records']:
                            st.code(record, language="text")

            with col2:
                st.markdown(f"**DKIM** {dkim['status']}")
                st.markdown(f"Score: `{dkim['score']}/30`")
                if dkim['found']:
                    with st.expander(f"View Records ({len(dkim['records'])} found)"):
                        for rec in dkim['records']:
                            st.markdown(f"**Selector:** `{rec['selector']}`")
                            st.code(rec['record'][:120] + "...", language="text")

            with col3:
                st.markdown(f"**DMARC** {dmarc['status']}")
                st.markdown(f"Score: `{dmarc['score']}/35`")
                if dmarc['found']:
                    with st.expander("View Record"):
                        for record in dmarc['records']:
                            st.code(record, language="text")

# ============================================
# LEARN PAGE
# ============================================

elif nav == "📚 Learn":
    st.title("📚 Email Analyzer Guide")

    tab1, tab2, tab3 = st.tabs(["📧 SPF", "🔑 DKIM", "📋 DMARC"])

    with tab1:
        st.markdown("""
        ## SPF - Sender Policy Framework (RFC 7208)

        ### What is SPF?
        SPF is a DNS record that tells email servers which computers are authorized to send email from your domain.

        ### Why Use SPF?
        - Prevents email spoofing
        - Improves email deliverability
        - Protects your brand reputation

        ### Example SPF Record
        ```
        v=spf1 include:_spf.google.com include:sendgrid.net -all
        ```

        ### SPF Components
        - `v=spf1` - Version identifier
        - `include:` - Includes another domain's SPF rules
        - `ip4:192.0.2.0/24` - Authorizes specific IP
        - `-all` - Hardfail: reject all others (recommended)
        - `~all` - Softfail: accept but mark as suspicious
        - `+all` - Accept all (dangerous - don't use)

        ### Best Practices
        ✅ Always use `-all` (hardfail policy)
        ✅ Keep DNS lookups under 10
        ✅ Consolidate services using "include:"
        ✅ Test before enabling enforcement
        ❌ Avoid `+all` - it defeats the purpose
        """)

    with tab2:
        st.markdown("""
        ## DKIM - DomainKeys Identified Mail (RFC 6376)

        ### What is DKIM?
        DKIM digitally signs emails using a private key. Recipients verify the signature using your public key in DNS.

        ### Why Use DKIM?
        - Proves emails come from your domain
        - Detects email tampering
        - Improves email trust scores

        ### Example DKIM Record
        ```
        v=DKIM1; k=rsa; h=sha256; p=MIGfMA0GCSq...
        ```

        ### DKIM Components
        - `v=DKIM1` - DKIM version
        - `k=rsa` - Key type (RSA encryption)
        - `h=sha256` - Hash algorithm (SHA256 recommended)
        - `p=` - Public key data

        ### Common Selectors
        Try these selector names when looking for your DKIM record:
        - `default`, `k1`, `selector1`, `selector2`
        - `google`, `protonmail`, `sendgrid`, `mailgun`
        - `ses`, `amazonses`, `mail`, `dkim`

        ### Best Practices
        ✅ Use RSA-2048 bit keys (minimum)
        ✅ Use SHA256 algorithm (not SHA1)
        ✅ Store public key in DNS
        ✅ Rotate keys periodically
        ❌ Don't expose private keys
        """)

    with tab3:
        st.markdown("""
        ## DMARC - Domain Message Authentication (RFC 7489)

        ### What is DMARC?
        DMARC ties SPF and DKIM together and tells email servers what to do when authentication fails.

        ### Why Use DMARC?
        - Enforces email authentication
        - Prevents domain abuse
        - Provides visibility into email flows
        - Protects your domain reputation

        ### Example DMARC Record
        ```
        v=DMARC1; p=reject; rua=mailto:reports@domain.com
        ```

        ### Policy Levels (Progressive Enforcement)

        **Stage 1: Monitoring Only**
        ```
        v=DMARC1; p=none; rua=mailto:reports@domain.com
        ```
        - No enforcement, just monitoring
        - Review reports for 30 days

        **Stage 2: Quarantine**
        ```
        v=DMARC1; p=quarantine; rua=mailto:reports@domain.com
        ```
        - Suspicious emails go to spam
        - Good middle ground

        **Stage 3: Reject (Strict)**
        ```
        v=DMARC1; p=reject; rua=mailto:reports@domain.com; ruf=mailto:forensics@domain.com
        ```
        - Failed emails rejected entirely
        - Maximum protection

        ### DMARC Components
        - `p=reject|quarantine|none` - Enforcement policy
        - `rua=mailto:` - Where to send aggregate reports
        - `ruf=mailto:` - Where to send failure reports (optional)
        - `dkim=strict|relaxed` - DKIM alignment mode
        - `spf=strict|relaxed` - SPF alignment mode

        ### Best Practices
        ✅ Start with p=none for 30 days
        ✅ Monitor reports carefully
        ✅ Progress to p=quarantine when confident
        ✅ Move to p=reject when ready
        ✅ Enable reporting (rua and ruf)
        ❌ Don't jump straight to p=reject
        """)

# ============================================
# ABOUT PAGE
# ============================================

elif nav == "ℹ️ About":
    st.title("ℹ️ About MailGuard")

    st.markdown("""
    ## 🎯 Our Mission

    MailGuard helps you to analyze your domain email security so you can protect your organization domain from phishing, spoofing, and impersonation attacks.

    ---

    ## 📊 What We Analyze

    | Standard | Purpose | Impact |
    |----------|---------|--------|
    | **SPF** | Authorizes mail servers | Prevents spoofing |
    | **DKIM** | Signs emails digitally | Proves authenticity |
    | **DMARC** | Enforces authentication | Controls policy |

    ---

    ## 🔒 Your Privacy

    ✅ **No Data Storage** - Analysis is real-time, never saved
    ✅ **No Tracking** - Zero cookies, analytics, or personal data
    ✅ **Read-Only DNS** - We only query public DNS records
    ✅ **HTTPS Encrypted** - All communication is secure
    ✅ **Anonymous Access** - No login or registration needed

    ---

    ## ⚠️ Important Disclaimers

    ### Limitations
    - This tool is **informational** - not a professional security audit
    - A high score doesn't guarantee email deliverability
    - DNS changes take 24-48 hours to fully propagate
    - Always verify results with your DNS provider

    ### Liability Notice
    ⚖️ **This tool is provided "AS-IS" without warranty.** We are NOT liable for:
    - Inaccurate analysis results
    - DNS lookup failures
    - Email delivery problems
    - Security vulnerabilities
    - Any indirect damages

    **Always test thoroughly and consult professionals for critical systems.**

    ---

    ## 📚 Standards & References

    - [RFC 7208](https://tools.ietf.org/html/rfc7208) - Sender Policy Framework (SPF)
    - [RFC 6376](https://tools.ietf.org/html/rfc6376) - DKIM Signatures
    - [RFC 7489](https://tools.ietf.org/html/rfc7489) - DMARC

    ---

    ## 🔗 Get in Touch

    📌 **Connect | Follow:** [Yusuf Bio](https://linktr.ee/yusufbio)

        ---

    **Version:** 1.0 | **Status:** ✅ Production Ready
    **Built with:** Streamlit + Python
    **Last Updated:** August 17, 2026

    Made with ❤️ to help analyze your domain email security.
    """)
