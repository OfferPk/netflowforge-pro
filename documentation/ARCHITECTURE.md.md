\# NetFlowForge Pro (v1.0.0) \- Technical Architecture Specification

\#\# 1\. System Overview

Network flow telemetry enables real-time volumetric DDoS detection, intrusion analysis, capacity planning, and traffic accounting across enterprise campuses, cloud datacenters, and transit peering backbones.

The two dominant standards are \*\*NetFlow v9 (RFC 3954)\*\* and \*\*IPFIX (IP Flow Information Export \- RFC 7011)\*\*. Both protocol architectures decouple data records from their schema definitions using \*\*Template FlowSets\*\*.

\*\*NetFlowForge Pro\*\* eliminates fatal real-world flow monitoring failures:  
\- \*\*Collector Decoder Desync ("Unknown Template ID")\*\*: If the template refresh timer exceeds 60s or is omitted, collector packet drops result in complete telemetry blackouts.  
\- \*\*Elephant Flow Stalling\*\*: Active timeouts set to 30 minutes conceal massive ongoing DDoS volumetric attacks until the flow terminates.  
\- \*\*Switch Hardware TCAM Exhaustion\*\*: High-rate spoofed random-IP SYN floods overwhelm switch hardware flow tables unless hardware rate-limiters and rapid inactive timeouts (\$\\le 15\$s) are configured.  
\- \*\*Sampling Distortion\*\*: Misaligned 1:1000 or 1:4096 sampling rates distort volumetric metrics in SIEM/SOAR platforms by up to 1000x.  
\- \*\*Security Visibility Blind Spots\*\*: Omitting TCP control flags (\`tcpControlBits\`) prevents SYN flood, FIN scan, and port sweep detection.

\---

\#\# 2\. Protocol Header & FlowSet Wireframe Layout (RFC 7011 / RFC 3954\)

\#\#\# 2.1 IPFIX Message Header (16 Bytes \- RFC 7011\)  
\`\`\`  
 0                   1                   2                   3  
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  
\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
|       Version Number (10)     |          Length               |  
\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
|                          Export Time                          |  
\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
|                       Sequence Number                         |  
\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
|                    Observation Domain ID                      |  
\+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
\`\`\`

\#\#\# 2.2 Template FlowSet (Set ID \= 2 for IPFIX; Set ID \= 0 for NetFlow v9)  
\- \*\*Set ID\*\* (16 bits): \`0x0002\` (IPFIX Template) or \`0x0000\` (NetFlow v9 Template)  
\- \*\*Length\*\* (16 bits): Total Set Length in octets  
\- \*\*Template ID\*\* (16 bits): \$\\ge 256\$  
\- \*\*Field Count\*\* (16 bits): Number of fields in this template  
\- \*\*Field Definitions\*\*: For each field:  
  \- Information Element ID (16 bits)  
  \- Field Length in octets (16 bits)

\#\#\# 2.3 Data FlowSet  
\- \*\*Set ID\*\* (16 bits): Matches Template ID (e.g. \`0x0100\` / 256\)  
\- \*\*Length\*\* (16 bits): Total Set Length in octets  
\- \*\*Record Data\*\*: Raw octet values matching template field lengths  
\- \*\*Padding\*\*: 0–3 zero bytes to align set to 4-octet boundaries

\---

\#\# 3\. Standard IANA Information Elements (RFC 7012\)

| Element Name | Element ID | Length (Bytes) | Description |  
|--------------|------------|----------------|-------------|  
| \`octetDeltaCount\` | 1 | 4 or 8 | Number of octets transferred in flow |  
| \`packetDeltaCount\`| 2 | 4 or 8 | Number of packets transferred in flow |  
| \`protocolIdentifier\` | 4 | 1 | IP Protocol (6=TCP, 17=UDP, 1=ICMP) |  
| \`ipClassOfService\` | 5 | 1 | IPv4 ToS or IPv6 Traffic Class |  
| \`tcpControlBits\` | 6 | 1 or 2 | TCP control flags (SYN, ACK, RST, FIN, PSH, URG) |  
| \`sourceTransportPort\` | 7 | 2 | TCP/UDP source port |  
| \`sourceIPv4Address\` | 8 | 4 | IPv4 source address |  
| \`ingressInterface\` | 10 | 4 | Input interface SNMP ifIndex |  
| \`destinationTransportPort\` | 11 | 2 | TCP/UDP destination port |  
| \`destinationIPv4Address\` | 12 | 4 | IPv4 destination address |  
| \`egressInterface\` | 14 | 4 | Output interface SNMP ifIndex |  
| \`bgpSourceAsNumber\` | 16 | 4 | Originating BGP Autonomous System |  
| \`bgpDestinationAsNumber\` | 17 | 4 | Destination BGP Autonomous System |

\---

\#\# 4\. 10-Point Zero-Trust Flow Telemetry Audit Rubric

| \# | Check | Verification Metric | Weight |  
|---|-------|---------------------|--------|  
| 1 | \*\*Template Refresh & Decoder Sync\*\* | Template refresh timer \$\\le 60\$s or \$\\le 1000\$ packets | 10 pts |  
| 2 | \*\*Active Flow Timeout Tuning\*\* | Active timeout \$\\le 60\$s (optimal 30s) for live DDoS tracking | 10 pts |  
| 3 | \*\*Inactive Flow Timeout Tuning\*\* | Inactive timeout \$\\le 15\$s to rapidly evict idle TCAM entries | 10 pts |  
| 4 | \*\*Sampling Ratio Calibration\*\* | Calibrated sampling rate (1:1 to 1:4096) matching collector scaling | 10 pts |  
| 5 | \*\*Security Field Coverage\*\* | TCP control flags (\`tcpControlBits\`) \+ L4 transport ports | 10 pts |  
| 6 | \*\*BGP AS Attribution\*\* | BGP Source/Destination AS numbers for transit attribution | 10 pts |  
| 7 | \*\*Hardware TCAM Flood Policer\*\* | Hardware TCAM flow-rate policer active against spoofed attacks | 10 pts |  
| 8 | \*\*Collector Redundancy\*\* | Dual redundant collectors configured for high availability | 10 pts |  
| 9 | \*\*Directional Flow Monitoring\*\* | Ingress and egress monitoring active for asymmetric paths | 10 pts |  
| 10 | \*\*DDoS Volumetric Alerting\*\* | Calibrated PPS and BPS microburst threshold triggers enabled | 10 pts |  
