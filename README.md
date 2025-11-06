# WickedDNS
DNS-based Command and Control

## DISCLAIMER

**FOR EDUCATIONAL AND AUTHORIZED TESTING USE ONLY**

This tool is intended for:
- Legitimate security testing and research
- Red team exercises with proper authorization
- Educational purposes in controlled environments
- Improving defensive security capabilities

**WARNING:**
- Only use on systems you own or have explicit written permission to test
- Unauthorized use may violate local, state, and federal laws
- The authors are not responsible for misuse of this software
- Users assume all liability for proper and legal use
- Always use ethical hacking principles.

## DISCLAIMER

- DNS Covert Channels: Uses DNS TXT and A records for data exfiltration
- Stealthy Communication: Blends with normal DNS traffic
- Chunked Data Transfer: Splits large outputs into multiple DNS queries
- Multiple Client Support: Manage multiple agents from single server

## Requirements
- Python 3.6+

## Detection & Mitigation

### Indicators of Compromise

- Unusual DNS query patterns to specific subdomains
- High volume of TXT record queries
- DNS queries with base64-encoded data patterns
- Regular beaconing to the same domain

### Mitigation Strategies
    
- DNS monitoring and filtering
- Domain blacklisting
- Network traffic analysis
- DNS query rate limiting

    Regular beaconing to the same domain
