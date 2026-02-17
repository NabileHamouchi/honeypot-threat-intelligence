#!/usr/bin/env python3
"""
Incident Report Generator
Génère un rapport d'incident formaté en Markdown
"""

import sys
import argparse
from datetime import datetime

def generate_report(args):
    """
    Génère le rapport IR en Markdown
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    report = f"""# 🚨 Incident Response Report

**Incident ID**: {args.incident_id}
**Date**: {timestamp}
**Analyst**: {args.analyst}
**Severity**: {args.severity}
**Status**: IN PROGRESS

---

## 📋 Executive Summary

{args.summary if args.summary else '[Brief description of the incident]'}

---

## 🔍 Technical Details

### Source Information
- **IP Address**: {args.ip if args.ip else 'N/A'}
- **Country**: {args.country if args.country else 'N/A'}
- **ISP**: {args.isp if args.isp else 'N/A'}

### Affected Asset
- **User/Account**: {args.user if args.user else 'N/A'}
- **System**: {args.system if args.system else 'N/A'}
- **First Detection**: {args.detection_time if args.detection_time else timestamp}

### Attack Timeline
```
{args.timeline if args.timeline else '''
[Time] - Event description
[Time] - Event description
[Time] - Event description
'''}
```

### Actions Observed

{args.actions if args.actions else '''
- Action 1
- Action 2
- Action 3
'''}

---

## 📊 Investigation

### Splunk Queries Used
```spl
{args.queries if args.queries else '''
index=* src_ip="X.X.X.X" earliest=-24h
| stats count by eventid, user
'''}
```

### Key Findings

{args.findings if args.findings else '''
1. Finding 1
2. Finding 2
3. Finding 3
'''}

---

## ⚡ Response Actions

### Containment
- [x] Source IP blocked on firewall
- [x] Affected account disabled
- [ ] System isolated from network

### Eradication
- [ ] Malware removed
- [ ] Backdoors eliminated
- [ ] Vulnerabilities patched

### Recovery
- [ ] Services restored
- [ ] Accounts re-enabled (with password reset)
- [ ] Monitoring enhanced

---

## 📌 Indicators of Compromise (IoCs)

### Network
- IP: {args.ip if args.ip else 'X.X.X.X'}

### Accounts
- User: {args.user if args.user else 'username'}

### Files/Hashes
{args.iocs if args.iocs else '- [List file hashes if applicable]'}

---

## 💡 Recommendations

### Short-term (0-7 days)
- Monitor for similar activity patterns
- Review access logs for other compromised accounts
- Strengthen authentication mechanisms

### Medium-term (1-4 weeks)
- Implement MFA on all accounts
- Review and update firewall rules
- Conduct security awareness training

### Long-term (1-6 months)
- Implement zero-trust architecture
- Enhance logging and monitoring capabilities
- Regular penetration testing

---

## 📝 Lessons Learned

### What Worked Well
- Quick detection (<{args.detection_delay if args.detection_delay else '1'} minute)
- Rapid response and containment
- Good documentation and communication

### Areas for Improvement
- Earlier detection possible with enhanced rules
- Faster escalation process needed
- Better automated response capabilities

---

## ✅ Conclusion

{args.conclusion if args.conclusion else '''
Incident successfully contained with no data exfiltration detected.
Root cause: Weak password policy allowing brute-force attack.
Remediation actions completed. System monitored for 48h post-incident.
'''}

---

**Report Generated**: {timestamp}
**Analyst**: {args.analyst}
**Next Review**: [Schedule follow-up review date]

---

*This report follows NIST Incident Response framework (SP 800-61 Rev. 2)*
"""
    
    return report


def main():
    """
    Fonction principale
    """
    parser = argparse.ArgumentParser(description='Generate Incident Response Report')
    
    parser.add_argument('--incident-id', default='INC-2026-XXX', help='Incident ID')
    parser.add_argument('--analyst', default='[Your Name]', help='Analyst name')
    parser.add_argument('--severity', default='HIGH', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], help='Severity level')
    parser.add_argument('--summary', help='Executive summary')
    parser.add_argument('--ip', help='Source IP address')
    parser.add_argument('--country', help='Source country')
    parser.add_argument('--isp', help='ISP/Organization')
    parser.add_argument('--user', help='Affected user/account')
    parser.add_argument('--system', help='Affected system')
    parser.add_argument('--detection-time', help='Detection timestamp')
    parser.add_argument('--detection-delay', help='Detection delay')
    parser.add_argument('--timeline', help='Attack timeline')
    parser.add_argument('--actions', help='Actions observed')
    parser.add_argument('--queries', help='SPL queries used')
    parser.add_argument('--findings', help='Key findings')
    parser.add_argument('--iocs', help='IoCs list')
    parser.add_argument('--conclusion', help='Conclusion')
    parser.add_argument('--output', default='incident_report.md', help='Output filename')
    
    args = parser.parse_args()
    
    print(f"\n📝 Incident Report Generator")
    print(f"Generating report: {args.output}\n")
    
    # Generate report
    report = generate_report(args)
    
    # Save to file
    with open(args.output, 'w') as f:
        f.write(report)
    
    print(f"✅ Report generated successfully!")
    print(f"📁 Saved to: {args.output}")
    print(f"\n💡 Tip: Edit the report to fill in the [bracketed] sections\n")


if __name__ == "__main__":
    main()