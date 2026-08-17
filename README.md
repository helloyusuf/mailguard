# 🛡️ MailGuard - Email Authentication Security Analyzer

## Overview

**MailGuard** is a free, professional-grade email authentication analyzer that helps you verify your domain's email security configuration and prevent spoofing attacks.

### Key Features

✅ **SPF Analysis** - Verify Sender Policy Framework configuration  
✅ **DKIM Validation** - Check DomainKeys Identified Mail setup  
✅ **DMARC Auditing** - Validate Domain-based Message Authentication policy  
✅ **Security Scoring** - Get 0-100 security score with breakdown  
✅ **Issue Detection** - Identify critical security gaps  
✅ **Recommendations** - Step-by-step fix guidance  
✅ **100% Free** - No signup, no payment, no limits  

---

## 🎯 Why Email Authentication Matters

Email spoofing is a critical security threat:
- 🚨 85%+ of phishing attacks exploit unverified senders
- 💰 Average phishing incident costs $140,000+
- 📧 Improper configuration causes email delivery failures
- 🏢 Damages brand reputation and customer trust

**SPF, DKIM, and DMARC** prevent attackers from:
- Forging emails claiming to be from your domain
- Bypassing email filters
- Distributing malware
- Committing fraud

---

## 🚀 Quick Start

### Option 1: Use Online (Easiest)
1. Visit: `https://share.streamlit.io/yourusername/mailguard/app.py`
2. Enter your domain (e.g., `example.com`)
3. Review results and recommendations

### Option 2: Run Locally
```bash
# Install Python 3.8+
# Clone this repository
git clone https://github.com/yourusername/mailguard.git
cd mailguard

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py

# Open browser to http://localhost:8501
```

---

## 📖 How to Use

### **Step 1: Enter Domain**
- Click "Analyzer" tab
- Type your domain (e.g., `example.com`)
- Click "Analyze"

### **Step 2: Review Results**
- **SPF Status**: Is Sender Policy Framework configured?
- **DKIM Status**: Are emails digitally signed?
- **DMARC Status**: Is authentication policy enforced?
- **Security Score**: 0-100 rating of your configuration

### **Step 3: Understand Score**
- **90-100**: Excellent - Well protected
- **75-89**: Good - Minor improvements recommended
- **50-74**: Fair - Notable gaps exist
- **0-49**: Poor - Urgent action required

### **Step 4: Fix Issues**
- Click recommendation sections for step-by-step guides
- Provider-specific instructions for Cloudflare, GoDaddy, Route 53, etc.
- Changes take 24-48 hours to propagate

### **Step 5: Re-analyze**
- After 2-3 days, re-run analysis
- Verify all issues are resolved

---

## 📚 Understanding Email Authentication

### **SPF (Sender Policy Framework)** - RFC 7208
