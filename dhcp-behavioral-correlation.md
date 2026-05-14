# DHCP Behavioral Correlation & Threat Hunting Using Splunk

---

##  Overview

This project focused on correlating DHCP lease behavior using Splunk and Zeek logs to identify abnormal client-to-server DHCP relationships.

The investigation aimed to detect clients communicating with multiple DHCP servers and validate baseline DHCP behavior within the monitored environment.

---

## Objective

To perform behavioral correlation analysis on DHCP activity and investigate potential rogue DHCP indicators through structured threat hunting techniques.

---

##  Lab Setup

- **Log Source:** Zeek (`dhcp.log`)
- **SIEM:** Splunk
- **Environment:** Virtual Lab (Kali Linux + VirtualBox)

---

##  Dataset

The DHCP logs contained:

- Client IP addresses
- DHCP server IP addresses
- MAC addresses
- Lease assignment activity

---

##  Detection Methodology

### 1. DHCP Behavioral Correlation

Used Splunk statistical aggregation to correlate DHCP server activity per client.

```spl
index=main sourcetype=zeek_dhcp
| rex field=_raw "(?<ts>\d+\.\d+)\s+(?<uid>\S+)\s+(?<client_ip>\d+\.\d+\.\d+\.\d+)\s+(?<client_port>\d+)\s+(?<server_ip>\d+\.\d+\.\d+\.\d+)\s+(?<server_port>\d+)\s+(?<mac>[0-9a-f:]{17})"
| stats values(server_ip) as dhcp_servers dc(server_ip) as server_count by client_ip
| sort - server_count
```

---

##  Analysis & Findings

The behavioral analysis showed:

- All clients communicated with only one DHCP server
- No abnormal DHCP correlation behavior was observed
- No evidence of rogue DHCP activity was identified during the investigation period

---

##  Key Observations

- DHCP lease behavior remained consistent across observed clients
- No client interacted with multiple DHCP servers
- Baseline network behavior was successfully validated

---

## Sample Output

![DHCP Behavioral Correlation](./dhcp_behavioral_correlation.png)

---

##  SOC Insight

Threat hunting is not only about identifying malicious activity.

A significant part of SOC operations involves validating normal behavior, reducing false positives, and establishing trusted baselines through behavioral analysis.

---

## Key Takeaway

Behavioral correlation improves detection accuracy and strengthens anomaly validation workflows within modern SOC environments.

---

## Next Steps

- Correlate DHCP activity with DNS traffic
- Develop anomaly detection dashboards
- Expand detection coverage using additional Zeek logs

---

`Splunk` `Zeek` `Threat Hunting` `Detection Engineering` `SOC Analyst` `DHCP`
