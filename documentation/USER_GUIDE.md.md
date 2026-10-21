\# NetFlowForge Pro \- User Guide & CI/CD Telemetry Pipeline Manual

\#\# 1\. Web Studio Quickstart

1\. Open \`source-code/index.html\` in any modern web browser.  
2\. Select an industry preset from the top dropdown:  
   \- \*\*Enterprise Core FNF (Cisco IOS-XE) \[Grade A+\]\*\*: Cisco IOS-XE Flexible NetFlow with IPFIX, 30s active timeout, 15s inactive timeout, TCP flags, dual collectors.  
   \- \*\*Cloud Border J-Flow (Juniper Junos) \[Grade A+\]\*\*: Juniper Junos inline J-Flow for carrier border router with 1:1000 sampling, BGP AS attribution.  
   \- \*\*Vulnerable Stale NetFlow \[Grade F\]\*\*: 1800s active timeout, 600s inactive timeout, missing template refresh, missing TCP flags, no hardware TCAM rate-limiting.  
3\. Review the \*\*10-Point Zero-Trust Scorecard\*\* to inspect template refresh timers, active/inactive timeouts, and TCAM flood protection.  
4\. Modify telemetry parameters (Protocol, Template ID, Active Timeout, Sampling Rate, Collectors, Information Elements).  
5\. Inspect the generated \*\*RFC 7011 IPFIX / NetFlow v9 Binary Message & Hex Dump\*\* with byte offsets and decoded field markers.  
6\. Switch synthesizer tabs to export production configurations:  
   \- \*\*Cisco IOS-XE (FNF)\*\*: \`flow record\`, \`flow exporter\`, \`flow monitor\`, \`ip flow monitor input/output\`.  
   \- \*\*Cisco Nexus NX-OS\*\*: \`feature netflow\`, \`flow record\`, \`flow exporter\`, \`flow monitor\`.  
   \- \*\*Juniper Junos\*\*: \`set forwarding-options inline-jflow\`, \`set services flow-monitoring version-ipfix\`.  
   \- \*\*Arista EOS\*\*: \`sflow sample\`, \`sflow destination\`, \`sflow run\`.  
   \- \*\*Linux OVS / Prometheus\*\*: \`ovs-vsctl \-- set Bridge br0 ipfix=@i\` and standalone Prometheus Exporter on \`:9127/metrics\`.

\---

\#\# 2\. DevSecOps CLI Tool (\`netflowforge-cli.py\`)

The standalone Python CLI tool requires zero external dependencies and runs on Python 3.8+.

\#\#\# 2.1 Encoding IPFIX / NetFlow v9 Binary Hex Dumps  
\`\`\`bash  
python3 build/netflowforge-cli.py encode-ipfix \-p presets/enterprise-core-cisco-fnf.json  
\`\`\`

\#\#\# 2.2 Calculating Flow Sampling & TCAM Footprint  
\`\`\`bash  
python3 build/netflowforge-cli.py calc-flow \--link-gbps 10 \--sample-rate 1000 \--active-timeout 30 \--inactive-timeout 15  
\`\`\`  
Output:  
\`\`\`  
\=== IPFIX / NetFlow Telemetry Sizing Analysis \===  
Interface Link Speed:    10.0 Gbps  
Configured Sampling:     1:1000  
Line-Rate Packets/sec:   1,562,500 PPS  
Sampled Export PPS:      1,562 PPS  
Active Concurrent Flows: 46,860  
Switch TCAM Capacity:    131,072 entries  
TCAM Table Utilization:  36%  
Export Telemetry Rate:   0.8 Mbps  
Status:                  PASSED (TCAM Safe)  
\`\`\`

\#\#\# 2.3 Running CI/CD Pipeline Telemetry Audits  
\`\`\`bash  
\# Clean production configuration \-\> Exits code 0  
python3 build/netflowforge-cli.py audit \-p presets/enterprise-core-cisco-fnf.json \--strict

\# Insecure/fragile configuration \-\> Exits code 1 (Pipeline Fails)  
python3 build/netflowforge-cli.py audit \-p presets/vulnerable-stale-netflow-config.json \--strict  
\`\`\`

\#\#\# 2.4 Synthesizing Router Configurations  
\`\`\`bash  
python3 build/netflowforge-cli.py synthesize \-p presets/enterprise-core-cisco-fnf.json \-f cisco-xe  
python3 build/netflowforge-cli.py synthesize \-p presets/cloud-ddos-juniper-inline-jflow.json \-f juniper  
\`\`\`

\---

\#\# 3\. GitHub Actions CI/CD Pipeline Gate

Add this workflow to your NetDevOps repository (\`.github/workflows/netflow-audit-gate.yml\`):

\`\`\`yaml  
name: Zero-Trust Flow Telemetry CI/CD Gate

on:  
  pull\_request:  
    paths:  
      \- 'netflow/\*\*'  
      \- 'ipfix/\*\*'  
      \- 'telemetry/\*\*'

jobs:  
  flow-audit:  
    runs-on: ubuntu-latest  
    steps:  
      \- name: Checkout Code  
        uses: actions/checkout@v4

      \- name: Set up Python  
        uses: actions/setup-python@v5  
        with:  
          python-version: '3.11'

      \- name: Audit Flow Telemetry Configuration (Strict Gate)  
        run: |  
          python3 build/netflowforge-cli.py audit \-p presets/enterprise-core-cisco-fnf.json \--strict  
\`\`\`  
