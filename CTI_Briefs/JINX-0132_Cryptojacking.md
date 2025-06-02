# JINX-0132 Cryotojacking Campaign 
- **DATE:** 2025-06-02
- **Targeted Technologies:** Docker, HashiCorp Nomad, HashiCorp Consul, Gitea
- **Geolocation:**  China, United States, Germany, Singapore, Finland, the Netherlands, and the United Kingdom.

## Summary

A newly identified cryptojacking campaign dubbed JINX-0132, is actively targeting publicly accessible DevOps infrastructure. The campaign exploits misconfigurations and known vulnerabilities in tools such as Docker, HashiCorp Nomad, HashiCorp Consul, and Gitea to deploy cryptocurrency mining software, specifically XMRig. 

## TTPs Observed

- Intial Access: Exploit public facing application

    - Exploiting misconfigured Docker, Gitea, Consul, and Nomad APIs. 

- Command and Scripting interpreter: Bash

    - Health checks in Consul executing Bash scripts.
  
- Persistence: Miner persistence through cron jobs or scheduled tasks

- Persistence: Container Orchestration Job

    - Nomad jobs spawning long-running containers. 

- Defense Evasion: Using public GitHub tools that appear benign.

- Resource Hijacking: Using compromised compute resources to mine cryptocurrency. 

- Impact: Endpoint Denial of Service
    
    - High CPU and memory usage degrading services. 

## Mitre Att&ck Mapping

- Discovery - System Information Discovery               T1082
- Initial Access                                         TA0001
- Explot Public-Facing Application                       T1190
- Execution                                              TA0002
- Execution - Command and Scripting Interpreter: Bash    T1059.004
- Persistence: Scheduled Task/Cron job                   T1053.003
- Persistence: Container Orchestration job               T1053.007
- Defense Evasion: Masquerading                          T1036
- Impact: Resource Hijacking                             T1496
- Impact: Endpoint Denial of Service                     T1499

## Recommended Mitigations

- Audit and Secure DevOps Tools
- Apply the principle of least privilege to all services and APIs
- Regularly patch known vulnerabilities
- Enforce authentication mechanisms for all DevOps tools
- Disable default of unused accounts or services
- Deploy monitoring solutions to detect abnormal CPU and memory usage indicative of cryptomining.
- Setup alerts for the creation of unexpected containers, jobs, or services.
- Limit the ability of internal systems to download and execute code from external sources like GitHub
- Implement network controls to prevent unauthorized outbound traffic.
- Provide training on secure configuration practices for DevOps tools.
- Raise awareness about the risk of misconfigurations and default settings. 

## Detection Guidance

- This campaign primarily targets Linux-based DevOps infrastructure. While some detections may apply, full visibility requires endpoint telemetry from Linux hosts or container runtime logging.

## Microsoft Defender XDR and Microsoft Sentinel Queries

Suspicious container activity via Docker CLI (XDR):

    DeviceProcessEvents
    | where FileName has_any ("docker.exe", dockerd", "containerd")
    | where ProcessCommandLine has_any ("-v", "--mount", "run", "--privileged", "--entrypoint")
    | where InitiatingProcessCommandLine has_any ("wget", "curl", "git clone", "chmod +x", "xmrig"))
    | project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine

Execution of XMRig or Related Miners (XDR)

    DeviceProcessEvents
    | where ProcessCommandLine has_any ("xmrig", "monero", "minerd", "--donate-level", "--cpu-priority")
    | project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName

Health Check Abuse in HashiCorp Consul (XDR)

    DeviceProcessEvents
    | where FileName in~ ("bash", "sh", "curl", "wget")
    | where ProcessCommandLine has_any ("--c", "http://", "https://", "github.com")
    | where InitiatingProcessFileName has_any ("consul", "consul.exe")
    | project Timestamp, DeviceName, FileName, ProcessCommandLine

Suspicious Outbound Connections From Containers

    DeviceNetworkEvents
    | where RemoteUrl has_any ("github.com", "raw.githubusercontent.com", "pastebin.com")
    | where IntitiatingProcessFileName has_any ("docker.exe", "xmrig", "bash", "wget", "curl")
    | project TimeStamp, DeviceName, RemoteURL, InitiatingProcessFileName, InitiatingProcessCommandLine

## Sources

- https://thehackernews.com/2025/06/cryptojacking-campaign-exploits-devops.html








  
