#!/usr/bin/env python3
"""
wireshark_filter.py - Convert natural language search terms to Wireshark display filters
and tshark CLI commands.

This script uses rule-based regex matching (no ML/AI) to comply with CTF rules.
"""

import sys
import re
import argparse

HELP_MENU = """
=== Wireshark Filter Helper - Available Search Patterns ===

=== Protocols ===
  http                    - HTTP traffic
  dns                     - DNS traffic
  tcp                     - TCP traffic
  udp                     - UDP traffic
  icmp                    - ICMP traffic
  arp                     - ARP traffic
  tls                     - TLS traffic
  ssl                     - SSL traffic
  ftp                     - FTP traffic
  smtp                    - SMTP traffic
  imap                    - IMAP traffic
  pop                     - POP traffic
  telnet                  - Telnet traffic
  ssh                     - SSH traffic
  ntp                     - NTP traffic
  snmp                    - SNMP traffic
  kerberos                - Kerberos traffic
  smb                     - SMB traffic
  ldap                    - LDAP traffic

=== Port Filtering ===
  port <NUM>              - TCP or UDP port <NUM>
  tcp port <NUM>           - TCP port <NUM>
  udp port <NUM>           - UDP port <NUM>
  http port <NUM>          - HTTP on port <NUM>
  dns port <NUM>          - DNS on port <NUM>
  tcp srcport <NUM>        - TCP source port <NUM>
  tcp dstport <NUM>       - TCP destination port <NUM>
  http ports              - Common HTTP ports (80, 8080, 8000, 8888)
  https ports             - Common HTTPS ports (443, 8443)

=== IP Address Filtering ===
  source ip <IP>          - Source IP address
  destination ip <IP>     - Destination IP address
  ip <IP>                 - Any IP address (src or dst)
  ipv6 source <IPV6>      - IPv6 source address
  ipv6 destination <IPV6> - IPv6 destination address

=== IP Specifics ===
  ip ttl <NUM>            - IP TTL equals <NUM>
  ipv6 hoplimit <NUM>     - IPv6 Hop Limit equals <NUM>
  ip flags df             - IP Don't Fragment flag set
  ip flags mf             - IP More Fragments flag set

=== Combined Filters ===
  http source ip <IP>     - HTTP traffic from source IP
  dns destination ip <IP> - DNS traffic to destination IP
  http or dns            - HTTP or DNS traffic
  tcp and port 80        - TCP traffic on port 80
  not arp               - Non-ARP traffic

=== HTTP Filtering ===
  http request            - HTTP requests
  http response          - HTTP responses
  http method get        - HTTP GET request
  http method post       - HTTP POST request
  http method put       - HTTP PUT request
  http method delete    - HTTP DELETE request
  http host <HOST>       - HTTP Host header
  http user agent <UA>   - HTTP User-Agent
  http referer <REF>    - HTTP Referer header
  http status <CODE>    - HTTP status code (e.g., 200, 404, 500)
  http cookie <COOKIE>   - HTTP Cookie header
  http content type <TYPE> - HTTP Content-Type (e.g., application/json)
  http request uri <URI> - HTTP Request URI
  http authorization    - HTTP Authorization header
  http basic auth       - HTTP Basic Authentication
  http bearer token     - HTTP Bearer Token
  http stream           - HTTP Stream

=== TCP Flags ===
  tcp syn                - TCP SYN flag set
  tcp ack                - TCP ACK flag set
  tcp fin                - TCP FIN flag set
  tcp rst                - TCP RST flag set
  tcp psh                - TCP PSH flag set
  tcp urg                - TCP URG flag set

=== TCP Specifics ===
  tcp seq <NUM>          - TCP Sequence Number
  tcp acknum <NUM>       - TCP Acknowledgment Number
  tcp window <NUM>      - TCP Window Size
  tcp stream <NUM>     - TCP Stream <NUM>

=== DNS Filtering ===
  dns query              - DNS queries
  dns response           - DNS responses
  dns query for <DOMAIN> - DNS query for <DOMAIN>
  dns query type <TYPE>  - DNS query type (a, aaaa, mx, txt, cname, ns, ptr, srv)
  dns response code <CODE> - DNS response code (e.g., nxdomain)

=== ICMP Filtering ===
  icmp echo request     - ICMP Echo Request
  icmp echo reply      - ICMP Echo Reply
  icmp destination unreachable - ICMP Destination Unreachable
  icmp time exceeded   - ICMP Time Exceeded

=== ARP Filtering ===
  arp request           - ARP Request
  arp reply             - ARP Reply
  arp who has <IP>      - ARP who has <IP>
  arp tell <IP>         - ARP tell <IP>

=== MAC / VLAN Filtering ===
  source mac <MAC>      - Ethernet source MAC address
  destination mac <MAC> - Ethernet destination MAC address
  mac <MAC>             - Any MAC address
  vlan id <NUM>         - VLAN ID
  vlan                  - VLAN tagged traffic

=== TLS/SSL Filtering ===
  tls version <VER>      - TLS Version
  tls handshake type <NUM> - TLS Handshake Type
  ssl version <VER>     - SSL Version

=== FTP/SMTP Specifics ===
  ftp filename <FILE>   - FTP Request filename
  smtp from <ADDR>     - SMTP From address
  smtp to <ADDR>       - SMTP To address
  smtp data contains <TEXT> - SMTP payload contains <TEXT>

=== Kerberos/SMB/LDAP ===
  kerberos ticket name <NAME> - Kerberos Client Name
  kerberos service <SVC>  - Kerberos Service
  smb command <NUM>      - SMB Command
  smb pipe <PIPE>       - SMB Named Pipe
  ldap query <TEXT>    - LDAP Query contains <TEXT>

=== Packet/Frame Filtering ===
  packet length <NUM>   - Packet length equals <NUM>
  packet length greater than <NUM> - Packet length > <NUM>
  packet length less than <NUM>    - Packet length < <NUM>
  timestamp greater than <NUM>     - Timestamp > <NUM> seconds
  timestamp less than <NUM>      - Timestamp < <NUM> seconds

=== Content Search / Find Patterns (CTF) ===
  flag                       - Search for "flag" in payload
  find <TEXT>               - Search for <TEXT> in payload
  search <TEXT>             - Search for <TEXT> in payload
  contains <TEXT>          - Contains <TEXT> in payload
  search flag              - Search for "flag"
  search password          - Search for "password"
  search secret            - Search for "secret"
  search key               - Search for "key"
  search token             - Search for "token"
  search cookie            - Search for "cookie"
  search session           - Search for "session"
  search auth              - Search for "auth"
  search login             - Search for "login"
  search admin             - Search for "admin"
  search root              - Search for "root"
  search passwd            - Search for "passwd"
  search credential        - Search for "credential"
  search jwt              - Search for JWT token (starts with eyJ)
  search base64            - Search for Base64 encoded data
  search http body <TEXT> - Search HTTP body for <TEXT>
  search xml               - Search for XML data
  search json              - Search for JSON data
  flag in http            - Find "flag" in HTTP traffic
  flag in dns             - Find "flag" in DNS traffic
  flag in tcp             - Find "flag" in TCP traffic
  password in http        - Find "password" in HTTP traffic
  admin in http           - Find "admin" in HTTP traffic
  login in http           - Find "login" in HTTP traffic
  session in http         - Find "session" in HTTP traffic

=== Substring/Contains Patterns ===
  cookie contains <TEXT>      - HTTP Cookie contains <TEXT>
  http user agent contains <TEXT> - HTTP User-Agent contains <TEXT>
  http request uri contains <TEXT>  - HTTP Request URI contains <TEXT>
  http referer contains <TEXT>    - HTTP Referer contains <TEXT>
  dns query name contains <TEXT>   - DNS query name contains <TEXT>
  tcp payload contains <TEXT>    - TCP payload contains <TEXT>
  udp payload contains <TEXT>   - UDP payload contains <TEXT>
  raw payload contains <TEXT>    - Raw payload contains <TEXT>

=== Boolean Operations ===
  http or dns              - HTTP or DNS
  tcp and port 80         - TCP AND port 80
  not arp                 - NOT ARP

=== Usage ===
  python3 wireshark_filter.py "http"                   - Convert query to filter
  python3 wireshark_filter.py "http" -i eth0        - With live capture interface
  python3 wireshark_filter.py "http" -r file.pcap   - With pcap file
  python3 wireshark_filter.py -f                   - Display this help menu
  python3 wireshark_filter.py -l                   - List all patterns

=== Example Commands ===
  python3 wireshark_filter.py "find flag"
  python3 wireshark_filter.py "http source ip 192.168.1.1"
  python3 wireshark_filter.py "search password"
  python3 wireshark_filter.py "dns query for example.com"
  python3 wireshark_filter.py "flag in http" -r capture.pcap
  python3 wireshark_filter.py "http method post and source ip 10.0.0.1"
"""

DESCRIPTION_TEXT = """
=== Wireshark Filter Generator - Detailed Description ===

=== WHAT IS THIS? ===
This tool converts natural language search terms into Wireshark display filters
and tshark CLI commands. It uses pure regex pattern matching (no ML/AI) to
comply with CTF competition rules.

=== WHY USE THIS? ===
- Quickly convert English-like queries to Wireshark filters without remembering
  the exact filter syntax
- Generate tshark commands for command-line packet analysis
- Find flags/secrets in pcap files during CTF challenges
- Filter by protocols, ports, IPs, headers, payloads, and more

=== WHEN TO USE THIS? ===
1. CTF (Capture The Flag) competitions:
   - Analyzing pcap files to find flags or secrets
   - Filtering network traffic for敏感 data
   - Reconstructing sessions or extracting files

2. Network troubleshooting:
   - Isolating specific traffic types
   - Finding error packets or anomalies
   - Analyzing HTTP requests/responses

3. Security auditing:
   - Hunting for credentials or tokens
   - Finding exposed secrets in network captures
   - Analyzing attack patterns

=== HOW IT WORKS ===
1. You provide a natural language query (e.g., "find flag")
2. The script matches against predefined regex patterns
3. It generates a Wireshark display filter
4. It also outputs a tshark CLI command you can run directly

=== FILTER TYPES EXPLAINED ===

PROTOCOL FILTERS:
  Input: "http"           Output: "http"
  Used for: Filtering HTTP traffic (both requests and responses)

PORT FILTERS:
  Input: "port 80"        Output: "tcp.port == 80 or udp.port == 80"
  Used for: Filtering traffic on specific ports

IP ADDRESS FILTERS:
  Input: "source ip 192.168.1.1"  Output: "ip.src == 192.168.1.1"
  Input: "ip 10.0.0.1"     Output: "ip.addr == 10.0.0.1"
  Used for: Filtering by source/destination IP

TCP FLAG FILTERS:
  Input: "tcp syn"         Output: "tcp.flags.syn == 1"
  Used for: Finding TCP handshake initiation packets

HTTP FILTERS:
  Input: "http method get"    Output: "http.request.method == "get""
  Input: "http status 200"   Output: "http.response.code == 200"
  Input: "http host example.com"  Output: "http.host == "example.com""
  Used for: Filtering HTTP requests/responses by various attributes

DNS FILTERS:
  Input: "dns query for example.com"  Output: "dns.qry.name == "example.com""
  Input: "dns query type a"  Output: "dns.qry.type == a"
  Used for: Analyzing DNS queries and responses

CONTENT SEARCH (CTF):
  Input: "find flag"       Output: "data-text contains "flag""
  Input: "search password"  Output: "data-text contains "password""
  Input: "flag in http"   Output: "http contains "flag""
  Used for: Finding sensitive data in packet payloads

=== TSHARK COMMAND USAGE ===
tshark -Y "<filter>" -r <pcap_file>   Read from pcap and apply filter
tshark -Y "<filter>" -i <interface>  Live capture on interface

Examples:
  # Find all HTTP traffic
  tshark -Y "http" -r capture.pcap

  # Find all packets containing "flag"
  tshark -Y "data-text contains "flag"" -r capture.pcap

  # Extract HTTP GET requests
  tshark -Y "http.request.method == "GET"" -r capture.pcap -w output.pcap

  # Count DNS queries for a domain
  tshark -Y "dns.qry.name == "example.com"" -r capture.pcap -q

=== LIMITATIONS ===
- Only supports predefined patterns (no custom field creation)
- Some advanced Wireshark filters may not be available
- Uses "contains" for substring matching (not full regex in Wireshark)
- IP address patterns accept any valid IP format (minimal validation)

=== COMPLIANCE ===
- NO machine learning or artificial intelligence used
- Pure rule-based regex pattern matching
- No external API calls or cloud services
- Fully offline operation
- CTF competition compliant
"""

def display_detailed_description():
    print(DESCRIPTION_TEXT)

def display_help_menu():
    print(HELP_MENU)

def nl_to_wireshark_filter(nl_text):
    """
    Convert natural language description to Wireshark display filter.
    Returns a tuple (filter_string, description) or (None, error_msg) if not recognized.
    """
    nl_text = nl_text.lower().strip()

    # Define patterns and corresponding Wireshark filters
    patterns = [
        # Protocols
        (r'^http$', 'http', 'HTTP traffic'),
        (r'^dns$', 'dns', 'DNS traffic'),
        (r'^tcp$', 'tcp', 'TCP traffic'),
        (r'^udp$', 'udp', 'UDP traffic'),
        (r'^icmp$', 'icmp', 'ICMP traffic'),
        (r'^arp$', 'arp', 'ARP traffic'),
        (r'^tls$', 'tls', 'TLS traffic'),
        (r'^ssl$', 'ssl', 'SSL traffic'),

        # Ports
        (r'^http port (\d+)$', 'tcp.port == \\1', 'HTTP on port \\1'),
        (r'^dns port (\d+)$', 'udp.port == \\1', 'DNS on port \\1'),
        (r'^tcp port (\d+)$', 'tcp.port == \\1', 'TCP port \\1'),
        (r'^udp port (\d+)$', 'udp.port == \\1', 'UDP port \\1'),
        (r'^port (\d+)$', 'tcp.port == \\1 or udp.port == \\1', 'Port \\1 (TCP or UDP)'),

        # IP addresses
        (r'^source ip ([0-9.]+)$', 'ip.src == \\1', 'Source IP \\1'),
        (r'^destination ip ([0-9.]+)$', 'ip.dst == \\1', 'Destination IP \\1'),
        (r'^ip ([0-9.]+)$', 'ip.addr == \\1', 'IP address \\1 (src or dst)'),
        (r'^ipv6 source ([0-9a-f:]+)$', 'ipv6.src == \\1', 'IPv6 source \\1'),
        (r'^ipv6 destination ([0-9a-f:]+)$', 'ipv6.dst == \\1', 'IPv6 destination \\1'),

        # Combined
        (r'^http source ip ([0-9.]+)$', 'http && ip.src == \\1', 'HTTP traffic from source IP \\1'),
        (r'^dns destination ip ([0-9.]+)$', 'dns && ip.dst == \\1', 'DNS traffic to destination IP \\1'),

        # HTTP methods/hosts (simplified)
        (r'^http request$', 'http.request.method', 'HTTP requests'),
        (r'^http response$', 'http.response', 'HTTP responses'),
        (r'^http host ([^\\s]+)$', 'http.host == "\\1"', 'HTTP host \\1'),

        # TCP flags
        (r'^tcp syn$', 'tcp.flags.syn == 1', 'TCP SYN flag set'),
        (r'^tcp ack$', 'tcp.flags.ack == 1', 'TCP ACK flag set'),
        (r'^tcp fin$', 'tcp.flags.fin == 1', 'TCP FIN flag set'),
        (r'^tcp rst$', 'tcp.flags.rst == 1', 'TCP RST flag set'),
        (r'^tcp psh$', 'tcp.flags.psh == 1', 'TCP PSH flag set'),
        (r'^tcp urg$', 'tcp.flags.urg == 1', 'TCP URG flag set'),

        # DNS queries/responses
        (r'^dns query$', 'dns.qry.name', 'DNS queries'),
        (r'^dns response$', 'dns.flags.response == 1', 'DNS responses'),
        (r'^dns query for ([^\\s]+)$', 'dns.qry.name == "\\1"', 'DNS query for \\1'),

        # Size/length
        (r'^packet length greater than (\d+)$', 'frame.len > \\1', 'Packet length > \\1 bytes'),
        (r'^packet length less than (\d+)$', 'frame.len < \\1', 'Packet length < \\1 bytes'),
        (r'^packet length (\d+)$', 'frame.len == \\1', 'Packet length == \\1 bytes'),

        # More HTTP specifics
        (r'^http method (get|post|put|delete|head|options|patch)$', 'http.request.method == "\\1"', 'HTTP \\1 request'),
        (r'^http status ([0-9]{3})$', 'http.response.code == \\1', 'HTTP status code \\1'),
        (r'^http status ([0-9]{2}[0-9]{2})$', 'http.response.code == \\1', 'HTTP status code \\1'),
        (r'^http user agent ([^\\s]+)$', 'http.user_agent == "\\1"', 'HTTP User-Agent \\1'),
        (r'^http referer ([^\\s]+)$', 'http.referer == "\\1"', 'HTTP Referer \\1'),
        (r'^http request uri ([^\\s]+)$', 'http.request.uri == "\\1"', 'HTTP Request URI \\1'),

        # More TCP specifics
        (r'^tcp seq ([0-9]+)$', 'tcp.seq == \\1', 'TCP Sequence Number == \\1'),
        (r'^tcp acknum ([0-9]+)$', 'tcp.ack == \\1', 'TCP Acknowledgment Number == \\1'),
        (r'^tcp window ([0-9]+)$', 'tcp.window_size == \\1', 'TCP Window Size == \\1'),
        (r'^tcp srcport ([0-9]+)$', 'tcp.srcport == \\1', 'TCP Source Port == \\1'),
        (r'^tcp dstport ([0-9]+)$', 'tcp.dstport == \\1', 'TCP Destination Port == \\1'),

        # More DNS specifics
        (r'^dns query type (a|aaaa|mx|txt|cname|ns|ptr|srv)$', 'dns.qry.type == \\1', 'DNS Query Type \\1'),
        (r'^dns response code (noerr|formerr|servfail|nxdomain|notimp|refused|yxdomain|yxrrset|nxrrset|notauth|notzone)$', 'dns.rcode == \\1', 'DNS Response Code \\1'),
        (r'^dns response code ([0-9]+)$', 'dns.rcode == \\1', 'DNS Response Code \\1'),

        # More IP specifics
        (r'^ip ttl ([0-9]+)$', 'ip.ttl == \\1', 'IP TTL == \\1'),
        (r'^ipv6 hoplimit ([0-9]+)$', 'ipv6.hoplim == \\1', 'IPv6 Hop Limit == \\1'),
        (r'^ip flags df$', 'ip.flags.df == 1', 'IP Don\'t Fragment flag set'),
        (r'^ip flags mf$', 'ip.flags.mf == 1', 'IP More Fragments flag set'),

        # Search/Find patterns for CTF
        (r'^find (.+)$', 'data-text contains "\\1"', 'Search for "\1" in payload'),
        (r'^search (.+)$', 'data-text contains "\\1"', 'Search for "\1" in payload'),
        (r'^contains (.+)$', 'data-text contains "\\1"', 'Contains "\1" in payload'),
        (r'^search flag$', 'data-text contains "flag"', 'Search for "flag"'),
        (r'^search password$', 'data-text contains "password"', 'Search for "password"'),
        (r'^search secret$', 'data-text contains "secret"', 'Search for "secret"'),
        (r'^search key$', 'data-text contains "key"', 'Search for "key"'),
        (r'^search token$', 'data-text contains "token"', 'Search for "token"'),
        (r'^search cookie$', 'data-text contains "cookie"', 'Search for "cookie"'),
        (r'^search session$', 'data-text contains "session"', 'Search for "session"'),
        (r'^search auth$', 'data-text contains "auth"', 'Search for "auth"'),
        (r'^search login$', 'data-text contains "login"', 'Search for "login"'),
        (r'^search admin$', 'data-text contains "admin"', 'Search for "admin"'),
        (r'^search root$', 'data-text contains "root"', 'Search for "root"'),
        (r'^search passwd$', 'data-text contains "passwd"', 'Search for "passwd"'),
        (r'^search credential$', 'data-text contains "credential"', 'Search for "credential"'),
        (r'^search jwt$', 'data-text contains "eyJ"', 'Search for JWT token (starts with eyJ)'),
        (r'^search base64$', 'data-text contains "=="', 'Search for Base64 encoded data'),
        (r'^search http body$', 'http.file_data contains "\\1"', 'Search HTTP body for "\1"'),
        (r'^search xml$', 'data-text contains "<?xml"', 'Search for XML data'),
        (r'^search json$', 'data-text contains "{"', 'Search for JSON data'),

        # Other protocols
        (r'^ftp$', 'ftp', 'FTP traffic'),
        (r'^smtp$', 'smtp', 'SMTP traffic'),
        (r'^imap$', 'imap', 'IMAP traffic'),
        (r'^pop$', 'pop', 'POP traffic'),
        (r'^telnet$', 'telnet', 'Telnet traffic'),
        (r'^ssh$', 'ssh', 'SSH traffic'),

        # MAC addresses
        (r'^source mac ([0-9a-f:]+)$', 'eth.src == \\1', 'Ethernet source MAC \\1'),
        (r'^destination mac ([0-9a-f:]+)$', 'eth.dst == \\1', 'Ethernet destination MAC \\1'),
        (r'^mac ([0-9a-f:]+)$', 'eth.addr == \\1', 'Ethernet MAC address \\1 (src or dst)'),

        # VLAN
        (r'^vlan id ([0-9]+)$', 'vlan.id == \\1', 'VLAN ID == \\1'),
        (r'^vlan$', 'vlan', 'VLAN tagged traffic'),

        # Timestamps (relative to capture start)
        (r'^timestamp greater than ([0-9.]+)$', 'frame.time_relative > \\1', 'Timestamp > \\1 seconds'),
        (r'^timestamp less than ([0-9.]+)$', 'frame.time_relative < \\1', 'Timestamp < \\1 seconds'),

        # HTTP cookies and headers
        (r'^http cookie ([^\\s]+)$', 'http.cookie == "\\1"', 'HTTP Cookie \\1'),
        (r'^http content type ([^\\s]+/[^\\s]+)$', 'http.content_type == "\\1"', 'HTTP Content-Type \\1'),

        # TLS/SSL specifics
        (r'^tls version ([0-9.]+)$', 'tls.record.version == 0x\\1', 'TLS Version 0x\\1'),  # Note: simplified
        (r'^tls handshake type ([0-9]+)$', 'tls.handshake.type == \\1', 'TLS Handshake Type \\1'),
        (r'^ssl version ([0-9.]+)$', 'ssl.record.version == 0x\\1', 'SSL Version 0x\\1'),  # Note: simplified

        # More specific port combinations
        (r'^http ports?$', 'tcp.port == 80 or tcp.port == 8080 or tcp.port == 8000 or tcp.port == 8888', 'Common HTTP ports'),
        (r'^dns ports?$', 'udp.port == 53', 'DNS port'),
        (r'^https ports?$', 'tcp.port == 443 or tcp.port == 8443', 'Common HTTPS ports'),

        # Common CTF-related filters
        (r'^flag in http$', 'http contains "flag"', 'HTTP traffic containing "flag"'),
        (r'^flag in dns$', 'dns contains "flag"', 'DNS traffic containing "flag"'),
        (r'^flag in tcp$', 'tcp contains "flag"', 'TCP traffic containing "flag"'),
        (r'^password in http$', 'http contains "password"', 'HTTP traffic containing "password"'),
        (r'^admin in http$', 'http contains "admin"', 'HTTP traffic containing "admin"'),
        (r'^login in http$', 'http contains "login"', 'HTTP traffic containing "login"'),
        (r'^session in http$', 'http contains "session"', 'HTTP traffic containing "session"'),

        # File transfers
        (r'^ftp filename ([^\\s]+)$', 'ftp.request.file == "\\1"', 'FTP Request filename \\1'),
        (r'^http file ([^\\s]+)$', 'http.request.uri == "\\1"', 'HTTP Request for file \\1'),

        # ICMP types
        (r'^icmp echo request$', 'icmp.type == 8', 'ICMP Echo Request'),
        (r'^icmp echo reply$', 'icmp.type == 0', 'ICMP Echo Reply'),
        (r'^icmp destination unreachable$', 'icmp.type == 3', 'ICMP Destination Unreachable'),
        (r'^icmp time exceeded$', 'icmp.type == 11', 'ICMP Time Exceeded'),

        # ARP specifics
        (r'^arp request$', 'arp.opcode == 1', 'ARP Request'),
        (r'^arp reply$', 'arp.opcode == 2', 'ARP Reply'),
        (r'^arp who has ([0-9.]+)$', 'arp.dst.proto_ipv4 == \\1', 'ARP who has \\1'),
        (r'^arp tell ([0-9.]+)$', 'arp.src.proto_ipv4 == \\1', 'ARP tell \\1'),

        # Boolean combinations examples
        (r'^http or dns$', 'http or dns', 'HTTP or DNS traffic'),
        (r'^tcp and port 80$', 'tcp and tcp.port == 80', 'TCP traffic on port 80'),
        (r'^not arp$', 'not arp', 'Non-ARP traffic'),

        # Substring / extraction patterns (using "contains" for simplicity)
        (r'^cookie contains (.+)$', 'http.cookie contains \"\\1\"', 'HTTP Cookie contains \"\\1\"'),
        (r'^http user agent contains (.+)$', 'http.user_agent contains \"\\1\"', 'HTTP User-Agent contains \"\\1\"'),
        (r'^http request uri contains (.+)$', 'http.request.uri contains \"\\1\"', 'HTTP Request URI contains \"\\1\"'),
        (r'^http referer contains (.+)$', 'http.referer contains \"\\1\"', 'HTTP Referer contains \"\\1\"'),

# Generic contains for other fields
        (r'^dns query name contains (.+)$', 'dns.qry.name contains "\\1"', 'DNS query name contains "\\1"'),
        (r'^tcp payload contains (.+)$', 'tcp.payload contains "\\1"', 'TCP payload contains "\\1"'),
        (r'^udp payload contains (.+)$', 'udp.payload contains "\\1"', 'UDP payload contains "\\1"'),
        (r'^icmp contains (.+)$', 'icmp contains "\\1"', 'ICMP payload contains "\\1"'),
        (r'^raw payload contains (.+)$', 'data contains "\\1"', 'Raw payload contains "\\1"'),

        # Data extraction / patterns for CTF flags
        (r'^flag$', 'data-text contains "flag"', 'Contains "flag" in payload'),
        (r'^flag contains (.+)$', 'data-text contains "\\1"', 'Payload contains "\1"'),
        (r'^find (.+)$', 'data-text contains "\\1"', 'Searching for "\1" in payload'),

        # TCP stream / conversation patterns
        (r'^tcp stream (\d+)$', 'tcp.stream == \\1', 'TCP Stream \1'),
        (r'^follow tcp stream (\d+)$', 'tcp.stream == \\1', 'Follow TCP Stream \1'),
        (r'^http stream$', 'http.stream', 'HTTP Stream'),
        (r'^http conversation$', 'http.request.uri', 'HTTP Conversation'),

        # Byte extraction patterns (using "contains" with hex/binary)
        (r'^contains hex (.+)$', 'data contains \\1', 'Contains hex string \1'),
        (r'^contains binary (.+)$', 'data contains \\1', 'Contains binary string \1'),

        # HTTP authentication
        (r'^http authorization$', 'http.authorization', 'HTTP Authorization header'),
        (r'^http basic auth$', 'http.authbasic', 'HTTP Basic Authentication'),
        (r'^http bearer token$', 'http.bearer', 'HTTP Bearer Token'),

        # SMTP specifics
        (r'^smtp from ([^\\s]+)$', 'smtp.from == "\\1"', 'SMTP From \1'),
        (r'^smtp to ([^\\s]+)$', 'smtp.to == "\\1"', 'SMTP To \1'),
        (r'^smtp mail from (.+)$', 'smtp.mail_from == "\\1"', 'SMTP Mail From \1'),
        (r'^smtp rcpt to (.+)$', 'smtp.rcpt_to == "\\1"', 'SMTP Recipient To \1'),
        (r'^smtp data contains (.+)$', 'smtp contains "\\1"', 'SMTP contains "\1"'),

        # NTP specifics
        (r'^ntp$', 'ntp', 'NTP traffic'),
        (r'^ntp mode (\d+)$', 'ntp.mode == \\1', 'NTP Mode \1'),
        (r'^ntp version (\d+)$', 'ntp.version == \\1', 'NTP Version \1'),

        # SNMP specifics
        (r'^snmp$', 'snmp', 'SNMP traffic'),
        (r'^snmp community (.+)$', 'snmp.community == "\\1"', 'SNMP Community \1'),

        # Kerberos specifics
        (r'^kerberos$', 'kerberos', 'Kerberos traffic'),
        (r'^kerberos ticket name (.+)$', 'kerberos.CNameString == "\\1"', 'Kerberos Client Name \1'),
        (r'^kerberos service (.+)$', 'kerberos.SNameString == "\\1"', 'Kerberos Service \1'),

        # SMB specifics
        (r'^smb$', 'smb', 'SMB traffic'),
        (r'^smb command (\d+)$', 'smb.cmd == \\1', 'SMB Command \1'),
        (r'^smb pipe (.+)$', 'smb.named_pipe == "\\1"', 'SMB Named Pipe \1'),

        # LDAP specifics
        (r'^ldap$', 'ldap', 'LDAP traffic'),
        (r'^ldap query (.+)$', 'ldap contains "\\1"', 'LDAP Query contains "\1"'),
    ]

    for pattern, filter_template, description in patterns:
        match = re.match(pattern, nl_text)
        if match:
            # Replace placeholders with captured groups
            filter_str = filter_template
            for i, group in enumerate(match.groups(), start=1):
                filter_str = filter_str.replace('\\' + str(i), group)
            return filter_str, description

    return None, "No matching rule found for the given natural language input."

def main():
    parser = argparse.ArgumentParser(
        description="Convert natural language search terms to Wireshark display filters and tshark commands."
    )
    parser.add_argument(
        'query',
        nargs='?',
        help="Natural language description of the filter (e.g., 'http source ip 192.168.1.1')"
    )
    parser.add_argument(
        '-i', '--interface',
        help="Network interface for live capture (tshark -i <interface>)"
    )
    parser.add_argument(
        '-r', '--read',
        help="Input pcap file for offline analysis (tshark -r <file>)"
    )
    parser.add_argument(
        '-f', '--find',
        action='store_true',
        help="Display all available search patterns and options"
    )
    parser.add_argument(
        '-l', '--list',
        action='store_true',
        help="List all available natural language filter patterns"
    )
    parser.add_argument(
        '-d', '--description',
        action='store_true',
        help="Display detailed description and usage information"
    )
    args = parser.parse_args()

    if args.description:
        display_detailed_description()
        sys.exit(0)

    if args.find or args.list:
        display_help_menu()
        sys.exit(0)

    if not args.query:
        # Interactive mode if no query provided
        try:
            nl_text = input("Enter natural language filter description: ").strip()
        except EOFError:
            print("\nNo input provided.")
            sys.exit(1)
    else:
        nl_text = args.query

    filter_str, description = nl_to_wireshark_filter(nl_text)

    if filter_str is None:
        print(f"Error: {description}")
        sys.exit(1)

    print(f"Input: {nl_text}")
    print(f"Description: {description}")
    print(f"Wireshark display filter: {filter_str}")

    # Build tshark command
    tshark_cmd = ["tshark", "-Y", f'"{filter_str}"']
    if args.interface:
        tshark_cmd.extend(["-i", args.interface])
    elif args.read:
        tshark_cmd.extend(["-r", args.read])
    else:
        # Default: ask user to specify either -i or -r
        tshark_cmd.append("<input>")  # placeholder
        print("\nNote: You must specify either -i <interface> or -r <pcap_file> for tshark.")

    print(f"Tshark command: {' '.join(tshark_cmd)}")

if __name__ == "__main__":
    main()