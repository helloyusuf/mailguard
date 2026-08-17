import streamlit as st
import dns.resolver
import dns.exception
from datetime import datetime
import re

# Page Configuration
st.set_page_config(
    page_title="MailGuard - Email Authentication Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5em;
        font-weight: bold;
        color: #1f77b4;
    }
    .section-header {
        font-size: 1.3em;
        font-weight: bold;
        color: #ff7f0e;
        margin-top: 20px;
        margin-bottom: 10px;
    }
    .info-box {
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
    }
    </style>
""", unsafe_allow_html=True)

# ============================================
# HEADER & INTRODUCTION
# ============================================

st.markdown('<div class="main-header">🛡️ MailGuard</div>', unsafe_allow_html=True)
st.markdown("### Email Authentication Security Analyzer")

# Tabs for Organization
tab_home, tab_analyzer, tab_guide, tab_about = st.tabs(
    ["🏠 Home", "🔍 Analyzer", "📖 How to Use", "ℹ️ About"]
)

# ============================================
# TAB 1: HOME / INTRODUCTION
# ============================================

with tab_home:
    st.markdown('<div class="section-header">Welcome to MailGuard</div>', unsafe_allow_html=True)

    st.markdown("""
    ### 🎯 What is MailGuard?

    MailGuard is a **free, professional-grade email authentication analyzer** that helps you:
    - ✅ Verify your domain's email security configuration
    - ✅ Detect critical security gaps
    - ✅ Assess email security health with a numerical score
    - ✅ Prevent email spoofing and phishing attacks
    - ✅ Improve email deliverability
    - ✅ Receive step-by-step fix recommendations

    ---

    ### 📌 Why Email Authentication Matters

    **Email spoofing** is a serious security threat where attackers forge sender addresses to:
    - Phish for sensitive information
    - Distribute malware
    - Damage your brand reputation
    - Bypass email filters

    **Email authentication** (SPF, DKIM, DMARC) prevents this by:
    - Verifying the sender is legitimate (SPF)
    - Digitally signing emails (DKIM)
    - Enforcing authentication policies (DMARC)

    ---

    ### 🚀 Quick Start

    1. Go to the **"Analyzer"** tab
    2. Enter your domain name (e.g., `example.com`)
    3. MailGuard will scan your DNS records
    4. Review your security score and recommendations
    5. Follow step-by-step guides to fix issues
    """)

    # Key Statistics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("SPF Records Checked", "Global Standard", "RFC 7208")
    with col2:
        st.metric("DKIM Validation", "Industry Standard", "RFC 6376")
    with col3:
        st.metric("DMARC Enforcement", "Latest Standard", "RFC 7489")

# ============================================
# TAB 2: ANALYZER
# ============================================

with tab_analyzer:
    st.markdown('<div class="section-header">Domain Email Security Analyzer</div>', unsafe_allow_html=True)

    # Input Section
    col1, col2 = st.columns([3, 1])
    with col1:
        domain = st.text_input(
            "Enter your domain:",
            placeholder="example.com",
            help="Enter domain without http:// or www. (e.g., example.com)"
        )
    with col2:
        analyze_button = st.button("🔍 Analyze", use_container_width=True)

    # Domain Validation Function
    def validate_domain(domain):
        """Validate domain format per RFC 1123"""
        if not domain:
            return False, "Domain cannot be empty"

        domain = domain.strip().lower()

        # Remove http:// or https://
        if domain.startswith('http://'):
            domain = domain[7:]
        elif domain.startswith('https://'):
            domain = domain[8:]

        # Remove www.
        if domain.startswith('www.'):
            domain = domain[4:]

        # Basic validation
        if len(domain) > 255:
            return False, "Domain exceeds 255 characters"

        if domain.endswith('.'):
            domain = domain[:-1]

        # RFC 1123 compliant pattern
        pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'

        if not re.match(pattern, domain):
            return False, "Invalid domain format"

        return True, domain

    # Analysis Logic
    if analyze_button or domain:
        if domain:
            is_valid, result = validate_domain(domain)

            if not is_valid:
                st.error(f"❌ Invalid Domain: {result}")
                st.stop()

            domain = result

            st.write("---")
            st.info(f"📍 Analyzing: **{domain}** | Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            st.write("")

            try:
                # ============================================
                # 1. SPF RECORD ANALYSIS
                # ============================================

                st.markdown('<div class="section-header">📧 SPF (Sender Policy Framework)</div>', unsafe_allow_html=True)

                try:
                    spf_records = dns.resolver.resolve(domain, 'TXT')
                    spf_found = False
                    spf_record = None

                    for record in spf_records:
                        record_str = str(record).strip('"')
                        if 'v=spf1' in record_str:
                            spf_found = True
                            spf_record = record_str
                            break

                    if spf_found:
                        st.success("✅ SPF Record Found")

                        with st.expander("📋 View SPF Record", expanded=True):
                            st.code(spf_record, language="text")
                            st.caption("📌 SPF Record (DNS TXT)")

                        # SPF Analysis
                        spf_score = 0
                        spf_issues = []
                        spf_recommendations = []

                        # Check multiple SPF records
                        spf_count = sum(1 for r in spf_records if 'v=spf1' in str(r))
                        if spf_count > 1:
                            spf_issues.append("⚠️ Multiple SPF records detected (RFC violation)")
                            st.warning("🔴 **Critical Issue**: Multiple SPF records found. Only the first is used, others are ignored.")
                            spf_recommendations.append("Consolidate all SPF mechanisms into a single TXT record")
                        else:
                            spf_score += 25

                        # Check policy strength
                        if '-all' in spf_record:
                            st.success("🟢 **Strong Policy**: Using hardfail (-all)")
                            st.markdown("> Emails from unauthorized servers will be rejected")
                            spf_score += 10
                        elif '~all' in spf_record:
                            st.warning("🟡 **Weak Policy**: Using softfail (~all)")
                            st.markdown("> Emails from unauthorized servers will be accepted but marked suspicious")
                            spf_recommendations.append("Consider upgrading from ~all (softfail) to -all (hardfail)")
                            spf_score += 5
                        elif '+all' in spf_record:
                            st.error("🔴 **Dangerous Policy**: Using +all")
                            st.markdown("> All emails pass SPF check. This defeats the purpose of SPF!")
                            spf_issues.append("Extremely weak policy allowing any sender")
                            spf_score = 0
                        else:
                            st.info("ℹ️ No all mechanism found")
                            spf_recommendations.append("Add an 'all' mechanism to complete your SPF policy")

                        # Check DNS lookup limit
                        lookup_count = spf_record.count('include:') + spf_record.count('a:') + \
                                      spf_record.count('mx:') + spf_record.count('ptr:')

                        if lookup_count > 10:
                            st.error("🔴 **SPF Lookup Limit Exceeded**: " + str(lookup_count) + "/10")
                            st.markdown("> Each DNS lookup counts toward limit. Too many will cause failures.")
                            spf_issues.append(f"SPF includes {lookup_count} DNS lookups (max: 10 per RFC 7208)")
                            spf_recommendations.append("Consolidate includes or use netblocks instead")
                            spf_score = max(0, spf_score - 10)
                        else:
                            st.info(f"✅ SPF DNS Lookups: {lookup_count}/10")

                        # SPF Score
                        st.metric("SPF Score", f"{spf_score}/35")

                        if spf_recommendations:
                            with st.expander("💡 Recommendations for SPF", expanded=False):
                                for i, rec in enumerate(spf_recommendations, 1):
                                    st.write(f"{i}. {rec}")

                    else:
                        st.error("❌ No SPF Record Found")
                        st.markdown("""
                        **What this means:**
                        - Your domain has NO SPF record
                        - Anyone can send emails claiming to be from your domain
                        - Your emails are more likely to be marked as spam
                        - Your domain is vulnerable to spoofing attacks

                        **Action Required:**
                        Add an SPF record to your DNS. Example:
                        """)
                        st.code("v=spf1 include:_spf.google.com -all", language="text")
                        st.metric("SPF Score", "0/35")

                except Exception as e:
                    st.error("❌ No SPF Record Found or DNS Error")
                    st.metric("SPF Score", "0/35")

                st.write("")

                # ============================================
                # 2. DKIM RECORD ANALYSIS
                # ============================================

                st.markdown('<div class="section-header">🔐 DKIM (DomainKeys Identified Mail)</div>', unsafe_allow_html=True)

                dkim_selectors = [
                    'default', 'k1', 'selector1', 'selector2',
                    'google', 'protonmail', 'mailchimp', 'sendgrid',
                    'mailgun', 'mandrill', 'amazonses', 'ses'
                ]

                dkim_found = False
                dkim_score = 0
                dkim_issues = []
                dkim_recommendations = []
                found_selectors = []

                for selector in dkim_selectors:
                    try:
                        dkim_query = f"{selector}._domainkey.{domain}"
                        dkim_records = dns.resolver.resolve(dkim_query, 'TXT')

                        for record in dkim_records:
                            record_str = str(record).strip('"')

                            if 'v=DKIM1' in record_str:
                                dkim_found = True
                                found_selectors.append({
                                    'selector': selector,
                                    'record': record_str
                                })
                    except:
                        pass

                if dkim_found:
                    st.success(f"✅ DKIM Records Found: {len(found_selectors)} selector(s)")

                    for item in found_selectors:
                        with st.expander(f"📋 Selector: {item['selector']}", expanded=True):
                            st.code(item['record'], language="text")
                            st.caption(f"DKIM Record for selector '{item['selector']}'")

                            # Analyze this DKIM record
                            record_str = item['record']

                            # Check key size
                            if '2048' in record_str or '4096' in record_str:
                                st.success("🟢 **Strong Key Size**: 2048+ bits")
                                dkim_score += 15
                            elif '1024' in record_str:
                                st.warning("🟡 **Weak Key Size**: 1024-bit key detected")
                                dkim_issues.append(f"Selector '{item['selector']}' uses 1024-bit key (minimum: 2048-bit)")
                                dkim_recommendations.append(f"Rotate DKIM key for selector '{item['selector']}' to 2048-bit or stronger")
                                dkim_score += 5
                            else:
                                st.info("ℹ️ Key size not explicitly shown (likely 2048+ bits)")
                                dkim_score += 15

                            # Check algorithm
                            if 'sha256' in record_str.lower():
                                st.success("🟢 **Algorithm**: SHA256 (Strong)")
                                dkim_score += 10
                            elif 'sha1' in record_str.lower():
                                st.warning("🟡 **Algorithm**: SHA1 (Deprecated)")
                                dkim_issues.append(f"Selector '{item['selector']}' uses SHA1 (deprecated)")
                                dkim_recommendations.append("Update DKIM key to use SHA256 algorithm")
                                dkim_score += 5
                            else:
                                st.info("ℹ️ Algorithm: Standard")
                                dkim_score += 10

                    st.metric("DKIM Score", f"{min(dkim_score, 30)}/30")

                    if dkim_recommendations:
                        with st.expander("💡 Recommendations for DKIM", expanded=False):
                            for i, rec in enumerate(dkim_recommendations, 1):
                                st.write(f"{i}. {rec}")

                else:
                    st.error("❌ No DKIM Records Found")
                    st.markdown("""
                    **What this means:**
                    - Your domain has NO DKIM records
                    - Emails cannot be digitally signed
                    - Recipients cannot verify emails actually came from you
                    - SPF alone is insufficient protection

                    **Action Required:**
                    Generate DKIM keys and add records to DNS. Contact your email provider for instructions.
                    """)
                    st.metric("DKIM Score", "0/30")

                st.write("")

                # ============================================
                # 3. DMARC RECORD ANALYSIS
                # ============================================

                st.markdown('<div class="section-header">📋 DMARC (Domain-based Message Authentication, Reporting and Conformance)</div>', unsafe_allow_html=True)

                dmarc_score = 0
                dmarc_issues = []
                dmarc_recommendations = []

                try:
                    dmarc_query = f"_dmarc.{domain}"
                    dmarc_records = dns.resolver.resolve(dmarc_query, 'TXT')

                    dmarc_found = False
                    dmarc_record = None

                    for record in dmarc_records:
                        record_str = str(record).strip('"')
                        if 'v=DMARC1' in record_str:
                            dmarc_found = True
                            dmarc_record = record_str
                            break

                    if dmarc_found:
                        st.success("✅ DMARC Record Found")

                        with st.expander("📋 View DMARC Record", expanded=True):
                            st.code(dmarc_record, language="text")
                            st.caption("DMARC Policy Record")

                        # Parse DMARC policy
                        if 'p=reject' in dmarc_record:
                            st.success("🟢 **Policy**: REJECT (Strongest)")
                            st.markdown("> Emails failing DMARC check will be rejected by receivers")
                            dmarc_score += 20
                        elif 'p=quarantine' in dmarc_record:
                            st.info("🟡 **Policy**: QUARANTINE (Medium)")
                            st.markdown("> Emails failing DMARC check will be sent to spam/quarantine")
                            dmarc_score += 15
                            dmarc_recommendations.append("Consider upgrading policy from 'quarantine' to 'reject' after validating alignment")
                        elif 'p=none' in dmarc_record:
                            st.warning("🟡 **Policy**: NONE (Monitoring Only)")
                            st.markdown("> Emails failing DMARC check will still be delivered (policy not enforced)")
                            dmarc_issues.append("DMARC policy is set to 'none' - no enforcement")
                            dmarc_recommendations.append("Upgrade from p=none to p=quarantine or p=reject after testing")
                            dmarc_score += 5
                        else:
                            st.error("🔴 **Policy**: Not set properly")
                            dmarc_score = 0

                        # Check alignment
                        if 'adkim=s' in dmarc_record:
                            st.success("✅ DKIM Alignment: STRICT")
                        elif 'adkim=r' in dmarc_record or 'adkim=' not in dmarc_record:
                            st.info("ℹ️ DKIM Alignment: RELAXED (default)")

                        if 'aspf=s' in dmarc_record:
                            st.success("✅ SPF Alignment: STRICT")
                        elif 'aspf=r' in dmarc_record or 'aspf=' not in dmarc_record:
                            st.info("ℹ️ SPF Alignment: RELAXED (default)")

                        # Check reporting
                        if 'rua=' in dmarc_record:
                            st.success("✅ Aggregate Reports: Enabled")
                            dmarc_score += 8
                        else:
                            st.warning("⚠️ Aggregate Reports: NOT configured")
                            dmarc_recommendations.append("Add 'rua=' parameter to receive daily aggregate reports")
                            dmarc_score += 2

                        if 'ruf=' in dmarc_record:
                            st.success("✅ Forensic Reports: Enabled")
                            dmarc_score += 7
                        else:
                            st.info("ℹ️ Forensic Reports: NOT configured (optional)")
                            dmarc_recommendations.append("Consider adding 'ruf=' for immediate failure notifications")

                        st.metric("DMARC Score", f"{min(dmarc_score, 35)}/35")

                        if dmarc_recommendations:
                            with st.expander("💡 Recommendations for DMARC", expanded=False):
                                for i, rec in enumerate(dmarc_recommendations, 1):
                                    st.write(f"{i}. {rec}")

                    else:
                        st.error("❌ No DMARC Record Found")
                        st.markdown("""
                        **What this means:**
                        - Your domain has NO DMARC policy
                        - No enforcement mechanism for SPF/DKIM
                        - Attackers can spoof your domain even with SPF/DKIM in place
                        - No visibility into authentication failures

                        **Action Required:**
                        Create a DMARC record. Start with monitoring policy:
                        """)
                        st.code("v=DMARC1; p=none; rua=mailto:admin@example.com", language="text")
                        st.metric("DMARC Score", "0/35")

                except:
                    st.error("❌ No DMARC Record Found")
                    st.metric("DMARC Score", "0/35")

                st.write("---")

                # ============================================
                # 4. OVERALL SECURITY SCORE
                # ============================================

                st.markdown('<div class="section-header">📊 Overall Security Score</div>', unsafe_allow_html=True)

                overall_score = min(
                    (spf_score if spf_found else 0) * 0.35 +
                    (dkim_score if dkim_found else 0) * 0.30 +
                    (dmarc_score if dmarc_found else 0) * 0.35,
                    100
                )

                col1, col2, col3 = st.columns([1, 2, 1])
                with col2:
                    st.metric("Security Score", f"{int(overall_score)}/100")

                # Score Interpretation
                if overall_score >= 90:
                    status = "🟢 EXCELLENT"
                    status_color = "green"
                    description = "Your email security configuration is excellent. Your domain is well-protected against spoofing and phishing attacks."
                elif overall_score >= 75:
                    status = "🟢 GOOD"
                    status_color = "green"
                    description = "Your email security is good, but there are some improvements recommended."
                elif overall_score >= 50:
                    status = "🟡 FAIR"
                    status_color = "orange"
                    description = "Your email security has notable gaps. Several issues need to be addressed."
                else:
                    status = "🔴 POOR"
                    status_color = "red"
                    description = "Your email security is weak and requires immediate attention. You are vulnerable to spoofing and phishing attacks."

                st.markdown(f"### Status: {status}")
                st.markdown(f"> {description}")

                # Score Breakdown
                with st.expander("📈 Score Breakdown (Weighted)", expanded=True):
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("SPF", f"{spf_score}/35 (35% weight)")
                    with col2:
                        st.metric("DKIM", f"{dkim_score}/30 (30% weight)")
                    with col3:
                        st.metric("DMARC", f"{dmarc_score}/35 (35% weight)")

                    st.caption("Formula: (SPF×0.35) + (DKIM×0.30) + (DMARC×0.35)")

                # Summary Issues
                all_issues = dkim_issues + dmarc_issues
                if spf_issues:
                    all_issues = spf_issues + all_issues

                if all_issues:
                    with st.expander("⚠️ Summary of Issues Found", expanded=True):
                        for i, issue in enumerate(all_issues, 1):
                            st.write(f"**{i}. {issue}**")

            except Exception as e:
                st.error(f"An error occurred during analysis: {str(e)}")
                st.info("This may happen if DNS is unreachable or the domain is invalid. Please try again.")

# ============================================
# TAB 3: HOW TO USE
# ============================================

with tab_guide:
    st.markdown('<div class="section-header">📖 How to Use MailGuard</div>', unsafe_allow_html=True)

    st.markdown("""
    ### Step-by-Step Guide

    #### **Step 1: Enter Your Domain**
    - Click on the **"Analyzer"** tab
    - Enter your domain name (e.g., `example.com`, `company.org`)
    - Do NOT include `http://`, `https://`, or `www.`
    - Click **"Analyze"** button

    #### **Step 2: Review Results**
    MailGuard will scan your DNS records and display:
    - ✅ **SPF Record Status** - Detects if you have Sender Policy Framework configured
    - ✅ **DKIM Record Status** - Checks for DomainKeys Identified Mail signatures
    - ✅ **DMARC Record Status** - Validates Domain-based Message Authentication policy
    - ✅ **Overall Security Score** - 0-100 rating of your email security

    #### **Step 3: Understand Your Score**

    | Score | Status | Meaning |
    |-------|--------|---------|
    | 90-100 | 🟢 Excellent | Your domain email security is well-configured |
    | 75-89 | 🟢 Good | Minor improvements recommended |
    | 50-74 | 🟡 Fair | Notable gaps exist |
    | 0-49 | 🔴 Poor | Urgent action required |

    #### **Step 4: View Recommendations**
    - Click "Recommendations" sections to see specific fixes
    - Each recommendation includes step-by-step instructions
    - Provider-specific guides help with implementation

    #### **Step 5: Take Action**
    - Follow the recommended fixes in order of priority
    - Update your DNS records in your domain registrar
    - Changes typically take 24-48 hours to propagate
    - Re-analyze after 2-3 days to verify improvements

    ---

    ### Understanding Email Authentication

    #### **SPF (Sender Policy Framework)** - RFC 7208
    - **What it does**: Authorizes which mail servers can send emails from your domain
    - **Why it matters**: Prevents attackers from sending emails that appear to come from your domain
    - **Example**: `v=spf1 include:_spf.google.com -all`
    - **Best practice**: Use `-all` (hardfail) not `~all` (softfail)

    #### **DKIM (DomainKeys Identified Mail)** - RFC 6376
    - **What it does**: Digitally signs emails with your domain's private key
    - **Why it matters**: Recipients can cryptographically verify emails came from you
    - **Key size**: 2048-bit minimum (4096 recommended)
    - **Algorithm**: SHA256 (SHA1 is deprecated)
    - **Example selector**: `google._domainkey.example.com`

    #### **DMARC (Domain-based Message Authentication, Reporting and Conformance)** - RFC 7489
    - **What it does**: Enforces SPF/DKIM alignment and defines how to handle failures
    - **Why it matters**: Provides policy enforcement and visibility into authentication failures
    - **Policies**:
      - `p=reject` - Block emails that fail authentication (strongest)
      - `p=quarantine` - Send failed emails to spam (medium)
      - `p=none` - Monitor only, no enforcement (weakest)
    - **Reporting**: `rua=` (aggregate) and `ruf=` (forensic) email addresses

    ---

    ### Common Issues & Fixes

    #### ❌ **"No SPF Record Found"**
    **Problem**: Your domain doesn't have SPF configured
    **Fix**: Add SPF TXT record to your DNS
    ```
    Domain: example.com
    Type: TXT
    Value: v=spf1 include:_spf.google.com -all
    ```

    #### ❌ **"Multiple SPF Records"**
    **Problem**: You have more than one SPF record (only first is used)
    **Fix**: Consolidate all SPF mechanisms into a single TXT record

    #### ❌ **"Using Softfail (~all)"**
    **Problem**: Your SPF uses `~all` instead of `-all`
    **Fix**: Change to `-all` after verifying all sending sources are included
    ```
    Old: v=spf1 include:_spf.google.com ~all
    New: v=spf1 include:_spf.google.com -all
    ```

    #### ❌ **"No DKIM Record Found"**
    **Problem**: DKIM signing is not enabled
    **Fix**: Contact your email provider to enable DKIM signing

    #### ❌ **"1024-bit DKIM Key"**
    **Problem**: Your DKIM key uses weak 1024-bit encryption
    **Fix**: Rotate to 2048-bit or stronger key

    #### ❌ **"No DMARC Record"**
    **Problem**: No policy enforcement for SPF/DKIM
    **Fix**: Add DMARC record (start with `p=none` for monitoring):
    ```
    Domain: _dmarc.example.com
    Type: TXT
    Value: v=DMARC1; p=none; rua=mailto:admin@example.com
    ```

    #### ❌ **"DMARC p=none"**
    **Problem**: DMARC is in monitoring mode only (no enforcement)
    **Fix**: Upgrade to `p=quarantine` after validating alignment
    """)

# ============================================
# TAB 4: ABOUT
# ============================================

with tab_about:
    st.markdown('<div class="section-header">ℹ️ About MailGuard</div>', unsafe_allow_html=True)

    st.markdown("""
    ### 🎯 Mission

    MailGuard's mission is to democratize email security by making professional-grade DNS authentication analysis accessible to everyone, from small business owners to enterprise administrators.

    ---

    ### 📋 Purpose of Building MailGuard

    #### **Problem We're Solving**
    - **Email Spoofing Crisis**: 85%+ of phishing attacks exploit unverified email senders
    - **Configuration Complexity**: Most organizations don't properly configure SPF, DKIM, and DMARC
    - **Accessibility Gap**: Professional email security tools are expensive and complex
    - **Knowledge Barrier**: Non-technical users struggle to understand email authentication
    - **Reactive Approach**: Most organizations discover issues only after being compromised

    #### **Why It Matters**
    - 🚨 **Security**: Email spoofing enables phishing, fraud, and malware distribution
    - 📧 **Deliverability**: Misconfigured authentication causes legitimate emails to be rejected
    - 🏢 **Reputation**: Compromised domains damage brand trust and customer confidence
    - 💰 **Business Impact**: Average phishing incident costs $140,000+ (Verizon DBIR)
    - 📋 **Compliance**: Email authentication is required for many security frameworks (NIST, CIS)

    ---

    ### ✅ How MailGuard Helps

    #### **For Small Business Owners**
    - Quickly understand if your domain is secure
    - Get simple, actionable recommendations
    - Reduce risk of being impersonated
    - Improve email deliverability
    - Free tool - no subscription required

    #### **For IT Professionals**
    - Audit email security configuration quickly
    - Identify specific gaps and weaknesses
    - Get provider-specific fix instructions
    - Document compliance status
    - Establish baseline security posture

    #### **For Security Teams**
    - Assess organizational email security
    - Identify domains needing attention
    - Validate remediation efforts
    - Generate compliance reports
    - Share standardized analysis with stakeholders

    #### **For Email Administrators**
    - Verify DNS records are correct
    - Troubleshoot authentication issues
    - Check alignment of SPF/DKIM/DMARC
    - Validate provider configurations
    - Ensure proper policy enforcement

    ---

    ### 🔍 How MailGuard Works

    #### **Technical Process**
    1. **Domain Validation**: Validates domain format per RFC 1123
    2. **DNS Resolution**: Queries authoritative DNS servers for TXT records
    3. **Record Parsing**: Extracts and analyzes SPF, DKIM, and DMARC records
    4. **Validation**: Checks against RFC standards (7208, 6376, 7489)
    5. **Scoring**: Calculates weighted score based on configuration quality
    6. **Reporting**: Generates actionable recommendations

    #### **Data Privacy**
    - ✅ No data is stored or logged
    - ✅ No personal information collected
    - ✅ No emails sent on your behalf
    - ✅ Direct DNS queries only
    - ✅ Public DNS records only (no sensitive data accessed)
    - ✅ Each analysis is independent and temporary

    #### **Limitations**
    - DNS propagation may cause delays (24-48 hours for changes)
    - Some DKIM selectors may not be detected (only common ones checked)
    - Firewall rules may block DNS queries
    - Some DNS providers rate-limit lookups
    - Analysis shows current state only (not historical)

    ---

    ### 📚 Standards & References

    MailGuard validates configurations against international standards:

    - **SPF (RFC 7208)**: Sender Policy Framework
    - **DKIM (RFC 6376)**: DomainKeys Identified Mail
    - **DMARC (RFC 7489)**: Domain-based Message Authentication, Reporting and Conformance
    - **DNS (RFC 1035)**: Domain Names - Implementation and Specification

    ---

    ### ⚠️ Disclaimer & Liability

    #### **Use of MailGuard**
    - MailGuard is provided "as-is" for informational purposes
    - Analysis results are based on publicly available DNS records
    - MailGuard makes no warranty of accuracy or completeness
    - Email security is complex; this tool provides guidance, not guarantees
    - Always validate results with your DNS provider or IT team
    - Professional security audit may be needed for critical systems

    #### **No Liability**
    - Users are solely responsible for actions taken based on MailGuard analysis
    - No liability for incorrect, incomplete, or outdated results
    - No liability for damages from implementation of recommendations
    - Always test changes in non-production environments first
    - Keep backups before modifying DNS records

    #### **Third-Party Services**
    - MailGuard uses DNS services provided by your configured DNS servers
    - MailGuard is not responsible for DNS service availability
    - Some queries may fail due to network issues

    ---

    ### 🛠️ Technical Stack

    - **Frontend**: Streamlit (Python web framework)
    - **Backend**: Python with dns2 library
    - **Hosting**: Streamlit Cloud (free tier)
    - **Data Storage**: None (stateless analysis)
    - **SSL/HTTPS**: Automatic (Streamlit Cloud)

    ---

    ### 📞 Support & Feedback

    - Found an issue? Submit feedback in app
    - Suggestions for improvements? We'd love to hear them
    - Questions? Check the "How to Use" tab above

    ---

    ### 📄 Legal

    - **License**: This tool is free to use for any purpose
    - **Attribution**: MailGuard - Email Authentication Security Analyzer
    - **Terms**: By using MailGuard, you agree to use it only for legitimate purposes
    - **Privacy**: We don't collect or store any personal data

    ---

    **Version**: 1.0
    **Last Updated**: August 2026
    **Status**: ✅ Production Ready
    """)

# ============================================
# FOOTER
# ============================================

st.write("---")
st.markdown("""
<div style='text-align: center; color: gray; font-size: 0.85em;'>
    <p>🛡️ <b>MailGuard</b> - Email Authentication Security Analyzer</p>
    <p>Free tool to analyze your domain's email security configuration (SPF, DKIM, DMARC)</p>
    <p>No personal data collected • No emails sent • Direct DNS queries only</p>
    <p><i>Always validate critical security changes with your IT team or DNS provider</i></p>
</div>
""", unsafe_allow_html=True)
