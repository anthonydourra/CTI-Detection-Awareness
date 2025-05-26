# Interlock Ransomware 
- **DATE:** 2025-05-26
- **Industry/Sector Relevance:** Healthcare, Public Services, Education, Aerospace, Manufacturing, Technology, among others. 
- **Geolocation:** United States, Europe

## Summary

The Interlock ransomware group has been actively targeting the healthcare sector causing significant disruptions and raising serious concerns about patient data privacy. While they have a strong prescence targeting the healthcare industry, they've demonstrated the capacity and willingness to target other industries as well. 

## TTPs Observed

- Intial Access: Fake CAPTCHAs and ClickFix tricks

When a user clicks on a link, it takes them to a fake website with a fake CAPTCHA, which trick the user to use basic commands (CTRL+C, Win+R and CTRL+V) to copy and paste PowerShell commands into their run box.

- Execution: PowerShell commands are executed by the user unknowingly
- Persistence: PowerShell scripts create Windows Registry Run Keys

After persistence is gained and system information is received by the attackers, they can then harvest credentials using various expolits.

- Lateral Movement: Valid credentials are used to login to other systems via RDP
Collection and Exfiltration: Sensitive data is uploaded to Azure Blob Storage controlled by attackers and is published to an .onion site.

- Execution: Ransomware Deployment
    
After exfiltrating sensitive data, files are encrypted and a ransom is demanded. 

This attack is two-fold: sensitve data is exfiltrated and then ransomware is deployed

## Mitre Att&ck Mapping

- Initial Access             TA0001
- Phishing                   T1566
- Spearphishing via Link     T1566.002
- Powershell                 T1059.01
- User Execution             T1562.001
- Lateral Movement           TA0008
- Remote Services: RDP       T1021.001
- Valid Accounts             T1078
- Data Encryption for Impact T1486

## Recommended Mitigations

- Block access to domains with uncommon TLDs (.xyz, .top, .click, .etc)
- Enable SmartScreen
- Educate users to be on the lookout for fake CAPTCHAs and to report them immediately

## Detection Guidance

- Monitor for unexpected executions of files from the '%TEMP%' and '%APPDATA%' folders
- Look for parent-child process relationships (ex. Chrome.exe spawning PowerShell.exe) to detect fake websites/CAPTCHAs spawning Powershell.exe
- Monitor RDP connections to detect lateral movement

## Microsoft Defender XDR and Microsoft Sentinel Queries

For Kusto Notebook see 'interlock_ransomware_attack.knb' under Direction_Queries directory.

Browser spawns PowerShell (XDR):

    DeviceProcessEvents
    | where InitiatingpProcessFilename has_any ("chrome.exe, msedge.exe, "firefox.exe")
    | where FileName == "powershell.exe"
    | where ProcessCommandLine has_any ("Invoke-WebRequest", "IEX", ".ps1", "DownloadFile")
    | project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine

Browser accesses suspicious CAPTCHA domain (XDR)

    DeviceNetworkEvents
    | where RemoteUrl has "captcha"
    | where RemoteUrl matches regex @".*\.(xyz|top|click|ru|cn)"
    | where InitiatingProcessFileName has_any ("chrome.exe, "msedge.exe", "firefox.exe")
    | project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName

User executes suspicious file from Downloads folder (XDR)

    DeviceProcessEvents
    | where FolderPath has "\\Downloads\\"
    | where FileName has_any (".exe", ".js", ".vbs", ".ps1")
    | where InitiatingProcessFileName has_any ("chrome.exe", "msedge.exe", firefox.exe")
    | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName

PowerShell connecting to unusual domains (Sentinel)

    DeviceNetworkEvents
    | where InitiatingProcessName == "powershell.exe"
    | where RemoteUrl matches regex (@.*\.(xyz|click|ru|cn|top)"
    | summarize count() by RemoteUrl, DeviceName, bin(Timestamp, 1h)

## Sources

- https://www.bleepingcomputer.com/news/security/kettering-health-hit-by-system-wide-outage-after-ransomware-attack/
- https://www.kaspersky.com/blog/interlock-ransomware-clickfix-attack/53414/
- https://www.picussecurity.com/resource/blog/interlock-clickfix-ransomware-healthcare-attack
- https://blog.sekoia.io/interlock-ransomware-evolving-under-the-radar/









  
