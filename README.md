# Network-Threat-Investigation
Executive Summary

Analysis of a provided PCAP file captured on 2023-12-15 revealed a malware infection consistent with Pikabot activity. The investigation identified an initial payload download via HTTP, followed by suspicious DNS activity linked to recently registered and known malicious domains. Based on network indicators and OSINT correlation, the host was likely compromised shortly after the payload delivery.

Scope & Data Provided

Data Source: Network packet capture (PCAP)

Host Under Investigation: 10.12.15.101

Limitations:
This investigation is based solely on the provided PCAP. No endpoint telemetry, EDR, or SIEM data was available. As a result, conclusions are limited to observed network activity.

Timeline of Activity (UTC)
Time	Activity
16:01:58	Host accessed malicious domain jinjadiocese[.]com
16:02:04	ZIP file GURVU.zip downloaded via HTTP
16:05:18	Suspicious DNS queries to multiple malicious domains
Post-16:05	TLS connections observed to external infrastructure
Key Findings
Initial Access & Payload Delivery
![2](https://github.com/user-attachments/assets/fa2ddfdc-9a9e-4528-bede-edaa4dea7888)

The host accessed jinjadiocese[.]com, which responded with an HTTP 200 OK and delivered an archived file.

The downloaded file was identified as:

Filename: GURVU.zip

Size: ~114 KB

Content-Type: application/octet-stream

Post-Download Network Activity

Shortly after the download, the host issued DNS queries to multiple domains with the following characteristics:
![TCP stream](https://github.com/user-attachments/assets/eee26dc1-8921-4ab4-a88c-5e8354db07bf)
Recently registered (December 2023)

Flagged as malicious by multiple security vendors
Reported in association with Pikabot
![additional - PIKABOT](https://github.com/user-attachments/assets/e817d98d-b7ab-40bb-b489-d8ee9e873f3e)

OSINT & Malware Attribution

OSINT enrichment was performed on domains observed in the PCAP:

Domain	Notes
keebling[.]com	Flagged by multiple vendors; linked to Pikabot
baumbachers[.]com	Flagged by multiple vendors; linked to Pikabot
ionister[.]com	Flagged by multiple vendors; linked to Pikabot
![TCP stream](https://github.com/user-attachments/assets/ee9f02fd-00e6-4ab4-808a-61b4ccfbf9e4)

WHOIS data showed all domains were registered on 2023-12-12

Malpedia identifies Pikabot as a malware family comprising:

Downloader / installer

Loader

Core backdoor component

File Analysis

The ZIP file extracted from the PCAP was hashed in an isolated environment.
SHA256

F24888DA47BAE0149AB5C0D887D32FC155CB42AC8138D22699AE12CE1DCA6BD1


VirusTotal results showed 28 security vendors flagging the file as malicious.
![5](https://github.com/user-attachments/assets/62500e11-fa1b-4cc8-8a50-d67d8212125a)

Detection labels were consistent with Pikabot-related malware.

Indicators of Compromise (IOCs)
Domains

jinjadiocese[.]com

keebling[.]com

baumbachers[.]com

ionister[.]com

IP Addresses

68.66.226.89

66.42.96.18

45.77.85.150

207.246.75.243

File

Filename: GURVU.zip

SHA256: F24888DA47BAE0149AB5C0D887D32FC155CB42AC8138D22699AE12CE1DCA6BD1

MITRE ATT&CK Mapping

T1071.001 – Application Layer Protocol: Web Protocols

T1105 – Ingress Tool Transfer

T1041 – Exfiltration Over C2 Channel (potential, based on Pikabot behavior)

T1566.002 – Phishing: Link (suspected initial vector)

Assessment & Confidence

Based on the observed payload delivery, subsequent DNS activity, and OSINT correlation, there is high confidence that host 10.12.15.101 was infected with Pikabot malware.

Due to the limited scope of data, it cannot be determined with certainty whether the malicious activity persisted beyond the timeframe captured in the PCAP.

Recommendations

Immediately isolate the affected host and perform a full forensic investigation or reimage the system.

Hunt for IOCs (domains, IPs, file hash) across enterprise telemetry to identify additional compromised hosts.

Block known malicious domains and IPs at network and proxy layers where feasible.

Implement detections for:

ZIP or executable downloads followed by rare DNS queries

DNS queries to newly registered domains

Similar HTTP delivery patterns observed in this case

Notes

This investigation demonstrates how meaningful conclusions can be drawn from limited data by correlating network evidence with threat intelligence. Real-world incident response often operates under similar constraints.
