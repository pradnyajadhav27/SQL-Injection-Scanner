# SQL Injection Scanner

🛡️ **Educational & Authorized SQL Injection Detection Tool**

A Python-based SQL injection scanner designed **strictly for educational purposes and authorized security testing**. This tool helps identify SQL injection vulnerabilities through controlled payload testing and advanced false positive detection.

## ⚠️ **CRITICAL LEGAL DISCLAIMER**

**THIS TOOL IS FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY.**

### ✅ **AUTHORIZED TESTING TARGETS ONLY**
- **Localhost applications** (127.0.0.1, localhost)
- **Private network addresses** (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
- **Educational laboratories** (DVWA, Juice Shop, WebGoat)
- **Systems you own** or have **explicit written permission** to test

### ❌ **STRICTLY PROHIBITED**
- **Public websites** and production systems
- **API services** (httpbin.org, reqres.in, etc.)
- **Any unauthorized testing** or exploitation
- **Data extraction**, database dumping, or credential theft

---

## 🚀 **Quick Start**

### **Simple Usage**
```bash
# Install dependencies
pip install -r requirements.txt

# Basic scan
python simple_main.py "http://localhost/test.php?id=1"

# Advanced scan
python main.py "http://localhost/test.php?id=1" --delay 2 --output-json report.json
```

### **Two Versions Available**

#### **1. Simple Version** (`simple_main.py`)
- ✅ Minimal output
- ✅ Easy language
- ✅ Fast scanning
- ✅ Perfect for beginners

#### **2. Full Version** (`main.py`)
- ✅ Detailed logging
- ✅ Comprehensive reports
- ✅ Advanced features
- ✅ Professional use

---

## 📁 **Project Structure**

```
SQL Injection Scanner/
├── main.py              # Full-featured scanner
├── simple_main.py       # Simple minimal scanner
├── scanner.py           # Core scanning engine
├── detector.py          # Vulnerability detection
├── payloads.py          # SQL injection payloads
├── logger.py            # Logging system
├── utils.py             # Utility functions
├── requirements.txt     # Dependencies
└── README.md           # This documentation
```

---

## 🎯 **Features**

### **Core Capabilities**
- ✅ **GET and POST support** with automatic parameter detection
- ✅ **35+ SQL injection payloads** across 5 categories
- ✅ **Advanced false positive detection**
- ✅ **Target validation** - educational targets only
- ✅ **Rate limiting** and responsible scanning
- ✅ **Multiple result classifications**

### **Result Classifications**
- ✅ **SAFE** - No vulnerabilities detected
- ⚠️ **POSSIBLY_VULNERABLE** - Response differences need verification
- ❌ **VULNERABLE** - SQL errors or obvious injection success
- ❗ **FALSE_POSITIVE** - Non-database endpoint (API, static content)
- 🔴 **NOT_REACHABLE** - Target not running or accessible
- 🚫 **BLOCKED** - Unauthorized target (public websites)
- ⚠️ **NOT_TESTED** - All payload requests failed

---

## 📖 **Usage Examples**

### **Simple Scanner**
```bash
# Basic scan
python simple_main.py "http://127.0.0.1:8080/test.php?id=1"

# Save results
python simple_main.py "http://127.0.0.1:8080/test.php?id=1" --output results.txt

# Fast scan
python simple_main.py "http://127.0.0.1:8080/test.php?id=1" --delay 0.05
```

### **Full Scanner**
```bash
# Comprehensive scan
python main.py "http://localhost/test.php?id=1" --delay 2 --threads 5

# POST request
python main.py "http://localhost/login.php" --method POST --data "user=admin&pass=test"

# Generate reports
python main.py "http://localhost/test.php?id=1" --output-json report.json --output-text report.txt
```

---

## 📊 **Sample Output**

### **Simple Version**
```
Target: http://127.0.0.1:8080/vulnerable.php?id=1
Method: GET
Delay: 0.1s

Scanning 35 payloads...
Testing: id
   1/35
   11/35
   21/35
   31/35
==================================================
SCAN RESULTS
==================================================
Total Parameters: 1
Vulnerable: 1
False Positives: 0

id: VULNERABLE
   Found 35 issues

Overall Status: VULNERABLE
SQL Injection found! Fix needed.
```

### **NOT_REACHABLE Example**
```
Target: http://127.0.0.1:8080/nonexistent.php?id=1
Method: GET
Delay: 0.1s

==================================================
SCAN RESULTS
==================================================
Total Parameters: 0
Vulnerable: 0
False Positives: 0

Overall Status: NOT_REACHABLE
Target not running or accessible. Start server and retry.
```

### **BLOCKED Example**
```
Target must be localhost, private network, or educational lab environment
Only localhost and private networks allowed
```

---

## 🛡️ **Security Best Practices**

### **For Developers**
1. **Use parameterized queries** to prevent SQL injection
2. **Validate and sanitize** all user input
3. **Implement least privilege** database access
4. **Regular security testing** with authorized tools
5. **Keep software updated** with security patches

### **For Security Professionals**
1. **Get proper authorization** before testing
2. **Use established methodologies** for vulnerability assessment
3. **Document findings** and provide remediation guidance
4. **Follow responsible disclosure** practices
5. **Stay within legal boundaries** at all times

---

## 📚 **Educational Resources**

### **Recommended Learning**
- **OWASP SQL Injection Guide**: https://owasp.org/www-community/attacks/SQL_Injection
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security/sql-injection
- **DVWA Documentation**: https://github.com/digininja/DVWA
- **OWASP Juice Shop**: https://github.com/juice-shop/juice-shop

### **Testing Environments**
1. **DVWA** (Damn Vulnerable Web Application)
2. **OWASP Juice Shop**
3. **Local vulnerable applications**
4. **Authorized penetration testing labs**

---

## ⚖️ **License & Legal Statement**

This project is provided **for educational purposes only**. Use responsibly and in accordance with all applicable laws and regulations.

### **Authorized Use**
- Educational learning about cybersecurity
- Authorized penetration testing on owned systems
- Vulnerability assessment with explicit permission
- Security research in controlled environments

### **Prohibited Use**
- Unauthorized testing of production systems
- Any form of exploitation or data theft
- Violation of computer crime laws
- Commercial exploitation without permission

---

**Remember: With great knowledge comes great responsibility. Use this tool ethically, legally, and exclusively for educational purposes to help make the digital world more secure!** 🛡️
