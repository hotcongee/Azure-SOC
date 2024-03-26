# Azure-SOC

# SOC & HoneyNet in Azure (Live Traffic)
![Azure Cloud](https://github.com/hotcongee/Azure-SOC/assets/107250466/8b5bd7ad-5cdc-412b-bdda-b2ff0fc14e6f)



## Introduction

In this project, I built a live small scale SOC and honeynet in Azure. Log Analytics Workspace was used to ingest logs from various sources which is then leveraged by Microsoft Sentinel to build attack maps, trigger alerts, and create incidents. 
Microsoft Defender for Cloud was used as a data source for Log Analytics Workspace and to assess the Virtual Machines configuration of regulatory frameworks/security controls.
I measured some security metrics in the insecure environment for 24 hours, apply some security controls to harden the environment, measure metrics for another 24 hours. The metrics were collected on the environment post-remediation are:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)

## Architecture Before Hardening / Security Controls
![Azure before hardening](https://github.com/hotcongee/Azure-SOC/assets/107250466/162d60fc-f4df-4f54-affa-b5307cf3b591)

The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Azure Key Vault
- Azure Storage Account
- Microsoft SQL Server
- SQL Server Management Studio (SSMS)
- Microsoft Entra ID

The SOC utilised following tools, components and regulations:
- Microsoft Sentinel (SIEM)
- Microsoft Defender for Cloud (MDC)
    - NIST SP 800-53 R5
    - PCI DSS 3.2.1
- Log Analytics Workspace (LAW)
- Windows Event Viewer
- Kusto Query Language (KQL)

To collect these metrics, I deliberately configure the Network Security Group to allow all traffic without restrictions. All resources were originally deployed, exposed to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and all other resources are deployed with public endpoints visible to the Internet.

## Attack Maps Before Hardening / Security Controls
### NSG Allowed Inbound Malicious Flows
![NSG Allowed Inbound Malicious Flows](https://github.com/hotcongee/Azure-SOC/assets/107250466/3f6d5715-65a9-4b3b-b610-98752f9de1ab)<br>
### Linux Syslog Auth Failures
![Linux Syslog Auth Failures](https://github.com/hotcongee/Azure-SOC/assets/107250466/ad0595db-8628-4199-85d2-49b21bfed3c6)<br>
### MS SQL Server Authentication Failures
![MS SQL Server Authentication Failures](https://github.com/hotcongee/Azure-SOC/assets/107250466/8dcc2ba3-baf9-404f-a6ed-d5bcb6e0cf89)<br>
### Windows RDP/SMB Auth Failures
![Windows RDP/SMB Auth Failures](https://github.com/hotcongee/Azure-SOC/assets/107250466/e791cabb-7ca3-429f-9965-c30f33596073)<br>

## Metrics Before Hardening / Security Controls

The following table shows the metrics I measured in our insecure environment for 24 hours:

Start Time 18:22:20 07-03-2024

Stop Time  18:22:20 07-03-2024

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 31546
| Syslog                   | 384
| SecurityAlert            | 21
| SecurityIncident         | 213
| AzureNetworkAnalytics_CL | 1418



---------------------------------------------------------------------------

## Architecture After Hardening / Security Controls
![Azure after hardening](https://github.com/hotcongee/Azure-SOC/assets/107250466/16983717-eef0-49e9-8dfa-0206374c34dc)





## Attack Maps Before Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics I measured in our environment for another 24 hours, but after I have applied security controls:

Start Time 21:22:20 09-03-2024

Stop Time  21:22:20 10-03-2024

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 20917
| Syslog                   | 25
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

## Impact of Security Controls

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 33.69%
| Syslog                   | 93.49%
| SecurityAlert            | 100%
| SecurityIncident         | 100%
| AzureNetworkAnalytics_CL | 100%

## Simulated Attacks

The attacks that were simulated in this project etiher using another Virtual Machines or manual triggering, they are:

- Linux Brute Force Attempt
- AAD Brute Force Success
- Windows Brute Force Success
- Malware Detection (EICAR Test File)
- Privilege Escalation


## Conclusion

In this project, a mini honeynet was constructed in Microsoft Azure and log sources were integrated into a Log Analytics workspace. Microsoft Sentinel was employed to trigger alerts and create incidents based on the ingested logs. Additionally, metrics were measured in the insecure environment before security controls were applied, and then again after implementing security measures. It is noteworthy that the number of security events and incidents were drastically reduced after the security controls were applied, demonstrating their effectiveness.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.
