
# 🔒 Slack Security Scanner 

## 📋 Description
A Python-based security scanner for Slack integration code that identifies vulnerabilities, exposed secrets, and misconfigurations in your Slack applications.

## 📁 Folder Structure
```
main-folder/
├── app1/                 # Your Slack app 1
├── app2/                 # Your Slack app 2
├── app3/                 # Your Slack app 3
└── secret_scanner.py      # Scanner script
```

## 🚀 Installation
1. Save the scanner script as `secret_scanner.py` in your main folder
2. No additional libraries needed - uses only Python standard library
3. Requires Python 3.6+

## 💻 Usage Commands

### Basic Commands
```bash
# Scan a single app
python slack_scanner.py app1

# Scan current directory
python slack_scanner.py .

# Scan with verbose output
python slack_scanner.py app1 -v
```

### Advanced Options
```bash
# Save report to file
python slack_scanner.py app1 -s

# Exclude directories
python slack_scanner.py app1 -e "node_modules,.git,__pycache__"

# Show only HIGH and CRITICAL issues
python slack_scanner.py app1 --severity HIGH

# JSON output format
python slack_scanner.py app1 -o json
```

---
### Sample output report 

Recommanded 
```
# Save report to file
python slack_scanner.py app1 -s
```
JSON format output  : [View Scan Output Report](./security_scan_20260305_171115.json)    
TXT format output   : [View Scan Output Report](./security_scan_20260305_171115.txt)  

-------------------
Please NOTE : 
Sample code does not belongs to me.. I just use sample-code to test scanner.   

