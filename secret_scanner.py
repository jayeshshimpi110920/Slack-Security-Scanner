#!/usr/bin/env python3
"""
Advanced Security Scanner for Slack Integration Code
all specified patterns and keywords
"""

import os
import re
import argparse
import json
import hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import fnmatch

class SlackSecurityScanner:
    def __init__(self, root_path, exclude_dirs=None, verbose=False):
        self.root_path = Path(root_path)
        self.verbose = verbose
        self.exclude_dirs = exclude_dirs or [
            '.git', '__pycache__', 'node_modules', 'venv', 'env','.env'
            '.venv', 'dist', 'build', '*.pyc', '.idea', '.vscode',
            'tests', 'test', 'docs', 'examples'
        ]
        self.findings = defaultdict(list)
        self.severity_colors = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'INFO': '⚪'
        }

    def should_exclude(self, filepath):
        """Check if file should be excluded"""
        for pattern in self.exclude_dirs:
            if pattern in str(filepath) or fnmatch.fnmatch(str(filepath), f"*/{pattern}/*"):
                return True
        return False

    def mask_secret(self, secret, show_first=4, show_last=4):
        """Mask secret for safe display"""
        if not secret or len(secret) < 8:
            return '*' * len(secret) if secret else ''
        
        secret_str = str(secret)
        if len(secret_str) > show_first + show_last:
            return secret_str[:show_first] + '*' * (len(secret_str) - show_first - show_last) + secret_str[-show_last:]
        return '*' * len(secret_str)

    def scan_file(self, filepath):
        """Scan a single file for all patterns"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                self.check_tokens_and_secrets(filepath, line, line_num, line)
                self.check_insecure_protocols(filepath, line, line_num, line)
                self.check_ssl_verification(filepath, line, line_num, line)
                self.check_dangerous_functions(filepath, line, line_num, line)
                self.check_command_injection(filepath, line, line_num, line)
                self.check_weak_crypto(filepath, line, line_num, line)
                self.check_slack_specific(filepath, line, line_num, line)
                self.check_webhooks(filepath, line, line_num, line)
                self.check_retry_handling(filepath, line, line_num, line)
                self.check_debug_info(filepath, line, line_num, line)
                self.check_redirects(filepath, line, line_num, line)
                self.check_oauth(filepath, line, line_num, line)
                self.check_api_calls(filepath, line, line_num, line)
                self.check_scope_permissions(filepath, line, line_num, line)
                self.check_ip_addresses(filepath, line, line_num, line)
                self.check_url_params(filepath, line, line_num, line)
                
        except (UnicodeDecodeError, PermissionError, IsADirectoryError):
            pass

    def check_tokens_and_secrets(self, filepath, line, line_num, raw_line):
        """Check for tokens, API keys, secrets"""
        patterns = {
            'CRITICAL': [
                (r'xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}', 'Slack Bot/User Token'),
                (r'xoxb-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}', 'Slack Bot Token'),
                (r'xapp-[0-9]-[A-Z0-9]{10,}', 'Slack App Token'),
                (r'gh[opsu]_[0-9a-zA-Z]{36}', 'GitHub Token'),
                (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
                (r'(?i)(slack_token|bot_token|app_token|verification_token|signing_token)\s*[=:]\s*[\'"]([^\'"]+)[\'"]', 'Slack Token Assignment'),
                (r'(?i)(api[_-]?key|secret|password|auth)\s*[=:]\s*[\'"]([^\'"]+)[\'"]', 'Generic Secret'),
                (r'(?i)(azure_client_secret|client_secret)\s*[=:]\s*[\'"]([^\'"]+)[\'"]', 'Azure Client Secret'),
            ],
            'HIGH': [
                (r'(?i)(token|api_key|secret)\s*=\s*[\'"]([^\'"]{8,})[\'"]', 'Token/Key Assignment'),
                (r'bearer\s+[A-Za-z0-9\-_\.]{20,}', 'Bearer Token'),
                (r'-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----', 'Private Key'),
                (r'xox[ar]', 'Slack Token Pattern'),
            ]
        }
        
        for severity, pattern_list in patterns.items():
            for pattern, desc in pattern_list:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    secret = match.group(0)
                    self.add_finding(
                        severity, desc, filepath, line_num, 
                        secret, raw_line.strip()
                    )

    def check_insecure_protocols(self, filepath, line, line_num, raw_line):
        """Check for insecure protocols"""
        patterns = [
            (r'http://(?!localhost|127\.0\.0\.1)', 'HTTP (insecure)'),
            (r'ftp://', 'FTP (insecure)'),
            (r'telnet://', 'Telnet (insecure)'),
            (r'smtp://(?!.*starttls)', 'SMTP without TLS'),
            (r'ldap://', 'LDAP (insecure)'),
            (r'SSLv2|SSLv3', 'Obsolete SSL version'),
            (r'TLSv1[\._]?[01]', 'Obsolete TLS version'),
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                self.add_finding('HIGH', f'Insecure Protocol: {desc}', 
                               filepath, line_num, pattern, raw_line.strip())

    def check_ssl_verification(self, filepath, line, line_num, raw_line):
        """Check for disabled SSL verification"""
        patterns = [
            (r'verify\s*=\s*False', 'SSL Verification Disabled'),
            (r'check_hostname\s*=\s*False', 'Hostname Verification Disabled'),
            (r'context\.check_hostname\s*=\s*False', 'SSL Context Hostname Check Disabled'),
            (r'create_unverified_context', 'Unverified SSL Context'),
            (r'cert_reqs\s*=\s*ssl\.CERT_NONE', 'SSL Certificate Validation Disabled'),
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, line):
                self.add_finding('CRITICAL', desc, filepath, line_num, 
                               pattern, raw_line.strip())

    def check_dangerous_functions(self, filepath, line, line_num, raw_line):
        """Check for dangerous function usage"""
        patterns = [
            (r'eval\(', 'eval() usage - code injection risk'),
            (r'exec\(', 'exec() usage - code injection risk'),
            (r'os\.system\(', 'os.system() usage - command injection risk'),
            (r'subprocess\.(call|Popen|run)\(.*shell\s*=\s*True', 'subprocess with shell=True - command injection risk'),
            (r'pickle\.loads?\(', 'pickle deserialization - RCE risk'),
            (r'yaml\.load\(.*(?!Loader)', 'yaml.load() without safe loader - deserialization risk'),
            (r'__import__\(', 'Dynamic import - potential code injection'),
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, line):
                self.add_finding('CRITICAL', f'Dangerous Function: {desc}', 
                               filepath, line_num, pattern, raw_line.strip())

    def check_command_injection(self, filepath, line, line_num, raw_line):
        """Check for potential command injection"""
        # Check if user input flows into command execution
        if re.search(r'(request\.(json|args|form|get_json)|payload|text|data)', line, re.IGNORECASE):
            if re.search(r'(subprocess|os\.system|eval|exec)', line):
                self.add_finding('CRITICAL', 'Potential Command Injection - User input in execution', 
                               filepath, line_num, line, raw_line.strip())

    def check_weak_crypto(self, filepath, line, line_num, raw_line):
        """Check for weak cryptographic algorithms"""
        patterns = [
            (r'hashlib\.(md5|sha1)', 'Weak Hash Algorithm (MD5/SHA1)'),
            (r'Crypto\.Cipher\.(DES|ARC4)', 'Weak Cipher (DES/RC4)'),
            (r'algorithms\.(DES|RC4|Blowfish)', 'Weak Algorithm in cryptography.hazmat'),
            (r'PBKDF2.*count\s*=\s*\d{1,4}\b', 'Low PBKDF2 iterations (<10000)'),
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, line):
                self.add_finding('MEDIUM', desc, filepath, line_num, 
                               pattern, raw_line.strip())

    def check_slack_specific(self, filepath, line, line_num, raw_line):
        """Check Slack-specific security issues"""
        patterns = {
            'HIGH': [
                (r'X-Slack-Signature.*(?!verify|check).*', 'Slack signature handling - verification might be missing'),
                (r'X-Slack-Request-Timestamp', 'Slack timestamp - check for replay attack protection'),
                (r'hmac\.new.*sha256', 'Slack signature verification - good'),
                (r'@app\.route\(.*slack/events', 'Slack Events endpoint'),
                (r'@app\.route\(.*slack/command', 'Slack Command endpoint'),
            ],
            'MEDIUM': [
                (r'event[_-]?id.*(?!unique|duplicate|check).*', 'Event ID - check for duplicate handling'),
                (r'trigger[_-]?id', 'Trigger ID - potential for replay'),
                (r'Processed events.*(cache|redis|setnx)', 'Event deduplication implementation'),
                (r'insert.*event[_-]?id.*unique', 'Event ID deduplication - good'),
            ]
        }
        
        for severity, pattern_list in patterns.items():
            for pattern, desc in pattern_list:
                if re.search(pattern, line, re.IGNORECASE):
                    self.add_finding(severity, f'Slack: {desc}', filepath, 
                                   line_num, pattern, raw_line.strip())

    def check_webhooks(self, filepath, line, line_num, raw_line):
        """Check for Slack webhooks"""
        patterns = [
            (r'hooks\.slack\.com/services/[A-Za-z0-9/_-]+', 'Slack Webhook URL'),
            (r'hooks\.slack\.com/services', 'Slack Webhook reference'),
            (r'webhook.*slack', 'Slack webhook configuration'),
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                self.add_finding('HIGH', desc, filepath, line_num, 
                               self.mask_secret(line if 'services' in pattern else pattern), 
                               raw_line.strip())

    def check_retry_handling(self, filepath, line, line_num, raw_line):
        """Check for retry logic and rate limiting"""
        patterns = [
            (r'429.*Retry-After', 'Rate limit handling'),
            (r'backoff|retry|sleep.*(?:\d+)', 'Retry/backoff implementation'),
            (r'max_?retries\s*=\s*(\d+)', f'Max retries configured: {{}}'),
            (r'flask[_-]?limiter', 'Flask rate limiter'),
            (r'X-Slack-Retry-Num', 'Slack retry header'),
            (r'X-Slack-Retry-Reason', 'Slack retry reason'),
        ]
        
        for pattern, desc in patterns:
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                full_desc = desc.format(match.group(1)) if '{}' in desc else desc
                self.add_finding('MEDIUM', f'Retry/Rate Limit: {full_desc}', 
                               filepath, line_num, match.group(0), raw_line.strip())

    def check_debug_info(self, filepath, line, line_num, raw_line):
        """Check for debug information leakage"""
        patterns = [
            (r'print\(', 'Print statement - possible info leakage'),
            (r'logging\.(debug|info)', 'Logging - check for sensitive data'),
            (r'traceback\.print_exc', 'Traceback exposure'),
            (r'debug\s*=\s*True', 'Debug mode enabled'),
            (r'chat\.postMessage.*(token|secret|key)', 'Message content might expose secrets'),
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, line):
                self.add_finding('LOW', f'Info Leakage: {desc}', filepath, 
                               line_num, pattern, raw_line.strip())

    def check_redirects(self, filepath, line, line_num, raw_line):
        """Check for open redirects"""
        patterns = [
            (r'redirect\(.*request\.(args|GET|form|values)', 'Open redirect - user-controlled URL'),
            (r'return redirect\(.*url.*\)', 'Redirect - verify URL validation'),
            (r'redirect.*callback', 'Callback redirect - check for validation'),
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, line):
                self.add_finding('HIGH', f'Open Redirect Risk: {desc}', 
                               filepath, line_num, pattern, raw_line.strip())

    def check_oauth(self, filepath, line, line_num, raw_line):
        """Check OAuth implementation"""
        patterns = [
            (r'oauth.*callback|authorize|access_token', 'OAuth endpoint'),
            (r'state\s*[=:].*request\.(args|GET)', 'OAuth state parameter - check for CSRF protection'),
            (r'state\s*[=:].*(?!random|csrf|secure).*', 'Weak state parameter'),
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                self.add_finding('MEDIUM', f'OAuth: {desc}', filepath, 
                               line_num, pattern, raw_line.strip())

    def check_api_calls(self, filepath, line, line_num, raw_line):
        """Check API calls for security issues"""
        patterns = [
            (r'requests\.(get|post|put|delete|patch).*headers\s*=\s*\{.*Authorization.*Bearer', 'API call with Bearer token'),
            (r'requests\.(get|post|put|delete).*(?!headers.*Authorization).*', 'API call without Auth header - check'),
            (r'httpx\.(get|post|put|delete)', 'HTTPX API call'),
            (r'urllib\.request', 'urllib request - check for auth'),
            (r'aiohttp', 'aiohttp request - check for auth'),
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, line):
                # Special handling for missing auth
                if 'without Auth' in desc:
                    if not re.search(r'headers.*Authorization', line, re.IGNORECASE):
                        self.add_finding('MEDIUM', desc, filepath, line_num, 
                                       pattern, raw_line.strip())
                else:
                    self.add_finding('INFO', desc, filepath, line_num, 
                                   pattern, raw_line.strip())

    def check_scope_permissions(self, filepath, line, line_num, raw_line):
        """Check Slack OAuth scopes"""
        patterns = [
            (r'commands', 'Slack commands scope'),
            (r'chat:write', 'Chat write permission'),
            (r'channels:history', 'Channel history access'),
            (r'users:read', 'User read access'),
            (r'admin', 'Admin scope - high privilege'),
            (r'oauth\.scope', 'OAuth scope definition'),
        ]
        
        for pattern, desc in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                severity = 'HIGH' if 'admin' in pattern.lower() else 'MEDIUM'
                self.add_finding(severity, f'Permission Scope: {desc}', 
                               filepath, line_num, pattern, raw_line.strip())

    def check_ip_addresses(self, filepath, line, line_num, raw_line):
        """Check for hardcoded IP addresses"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        matches = re.finditer(ip_pattern, line)
        for match in matches:
            ip = match.group(0)
            # Skip local IPs
            if not (ip.startswith('127.') or ip.startswith('192.168.') or 
                   ip.startswith('10.') or ip.startswith('172.')):
                self.add_finding('LOW', f'Hardcoded IP: {ip}', filepath, 
                               line_num, ip, raw_line.strip())

    def check_url_params(self, filepath, line, line_num, raw_line):
        """Check URLs with sensitive parameters"""
        url_pattern = r'https?://[^\s]+[?&](token|api_key|secret|key|auth)=[^&\s]+'
        matches = re.finditer(url_pattern, line, re.IGNORECASE)
        for match in matches:
            url = match.group(0)
            self.add_finding('CRITICAL', 'URL with exposed credentials', 
                           filepath, line_num, self.mask_secret(url), raw_line.strip())

    def add_finding(self, severity, issue_type, filepath, line_num, match, context):
        """Add a finding to the results"""
        finding = {
            'file': str(filepath),
            'line': line_num,
            'issue': issue_type,
            'match': match,
            'context': context[:150] + '...' if len(context) > 150 else context,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        self.findings[severity].append(finding)
        
        if self.verbose:
            print(f"{self.severity_colors[severity]} [{severity}] {filepath}:{line_num} - {issue_type}")

    def scan(self):
        """Scan all files in directory"""
        total_files = 0
        for root, _, files in os.walk(self.root_path):
            for file in files:
                filepath = Path(root) / file
                if not self.should_exclude(filepath):
                    if self.verbose:
                        print(f"Scanning: {filepath}", end='\r')
                    self.scan_file(filepath)
                    total_files += 1
        
        if self.verbose:
            print(f"\nScanned {total_files} files")
        return self.findings

    def generate_report(self, output_format='text'):
        """Generate detailed report"""
        if output_format == 'json':
            return json.dumps({
                'scan_time': datetime.now().isoformat(),
                'scan_path': str(self.root_path),
                'total_findings': sum(len(v) for v in self.findings.values()),
                'findings_by_severity': self.findings
            }, indent=2, default=str)
        
        else:
            report = []
            report.append("=" * 100)
            report.append(f"🔒 SLACK SECURITY SCANNER REPORT")
            report.append(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report.append(f"📁 Scan Path: {self.root_path}")
            report.append("=" * 100)
            
            total = sum(len(v) for v in self.findings.values())
            
            if total == 0:
                report.append("\n✅ No security issues found!")
            else:
                report.append(f"\n⚠️  Found {total} potential security issues:\n")
                
                # Summary by severity
                report.append("📊 SUMMARY BY SEVERITY:")
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                    count = len(self.findings.get(severity, []))
                    if count > 0:
                        report.append(f"  {self.severity_colors[severity]} {severity}: {count}")
                
                # Detailed findings
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                    findings = self.findings.get(severity, [])
                    if findings:
                        report.append(f"\n{'=' * 80}")
                        report.append(f"{self.severity_colors[severity]} {severity} SEVERITY ISSUES ({len(findings)})")
                        report.append(f"{'=' * 80}")
                        
                        for i, finding in enumerate(findings, 1):
                            report.append(f"\n{i}. {finding['issue']}")
                            report.append(f"   📁 File: {finding['file']}")
                            report.append(f"   📍 Line: {finding['line']}")
                            report.append(f"   🔍 Match: {finding['match']}")
                            report.append(f"   📝 Context: {finding['context']}")
                            report.append(f"   {'-' * 60}")
            
            return "\n".join(report)

    def save_report(self, filename=None):
        """Save report to file"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"security_scan_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write(self.generate_report('text'))
        
        # Also save JSON version
        json_filename = filename.replace('.txt', '.json')
        with open(json_filename, 'w') as f:
            f.write(self.generate_report('json'))
        
        return filename, json_filename

def main():
    parser = argparse.ArgumentParser(description='Advanced Slack Security Scanner')
    parser.add_argument('path', nargs='?', default='.', help='Path to scan')
    parser.add_argument('--exclude', '-e', help='Comma-separated exclude patterns')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--output', '-o', choices=['text', 'json'], default='text', 
                       help='Output format')
    parser.add_argument('--save', '-s', action='store_true', help='Save report to file')
    parser.add_argument('--severity', '-sev', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                       help='Minimum severity to report')
    
    args = parser.parse_args()
    
    exclude_dirs = args.exclude.split(',') if args.exclude else None
    
    print("🔒 Starting Slack Security Scanner...")
    scanner = SlackSecurityScanner(args.path, exclude_dirs, args.verbose)
    scanner.scan()
    
    if args.save:
        txt_file, json_file = scanner.save_report()
        print(f"\n📄 Reports saved:")
        print(f"   - {txt_file}")
        print(f"   - {json_file}")
    else:
        print(scanner.generate_report(args.output))
    
    # Return exit code based on findings
    critical = len(scanner.findings.get('CRITICAL', []))
    high = len(scanner.findings.get('HIGH', []))
    
    if critical > 0:
        print(f"\n❌ Found {critical} CRITICAL issues! Please review immediately.")
        return 1
    elif high > 0:
        print(f"\n⚠️  Found {high} HIGH issues. Should be reviewed.")
        return 0
    else:
        print(f"\n✅ No critical or high issues found.")
        return 0

if __name__ == "__main__":
    exit(main())