export interface DetectionRule {
  id: string;
  title: string;
  language: string;
  mitreId: string;
  mitreTechnique: string;
  snippet: string;
  category: string;
  description: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
}

export interface MitreTactic {
  tactic: string;
  techniques: MitreTechnique[];
}

export interface Playbook {
  id: string;
  title: string;
  description: string;
  category: string;
  readingTime: string;
  pdfUrl: string;
  mitreMapping?: MitreTactic[];
}

export interface WorkflowStep {
  title: string;
  description: string;
}

export interface Workflow {
  id: string;
  title: string;
  description: string;
  tool: string;
  steps: WorkflowStep[];
  pdfUrl: string; 
  screenshot: string; 
}

export interface TeamMember {
  id: string;
  name: string;
  role: string;
  bio: string;
  image: string;
  color: string;
  linkedin: string;
  portfolio: string;
}

export const detectionRules: DetectionRule[] = [
    {
    id: "rule-001",
    title: "Suspicious PowerShell Execution",
    language: "Sigma",
    mitreId: "T1059",
    mitreTechnique: "Command and Scripting Interpreter",
    snippet: "selection:\n  Image|endswith: '\\powershell.exe'\n  CommandLine|contains: '-enc'",
    category: "Execution",
    description: "Detects suspicious PowerShell execution with encoded commands"
  },
  {
    id: "rule-002",
    title: "Malware Hash Detection",
    language: "YARA",
    mitreId: "T1204",
    mitreTechnique: "User Execution",
    snippet: "rule malware_hash {\n  meta:\n    description = \"Known malware hash\"\n  strings:\n    $hash = {4D 5A 90}",
    category: "Initial Access",
    description: "YARA rule for detecting known malware file hashes"
  },
  {
    id: "rule-003",
    title: "Network Intrusion Alert",
    language: "Snort",
    mitreId: "T1190",
    mitreTechnique: "Exploit Public-Facing Application",
    snippet: "alert tcp any any -> $HOME_NET 80\n(msg:\"HTTP SQL Injection\"; content:\"UNION\";\nsid:1001;)",
    category: "Initial Access",
    description: "Snort rule for detecting SQL injection attempts"
  },
  {
    id: "rule-004",
    title: "DNS Tunneling Detection",
    language: "Suricata",
    mitreId: "T1071",
    mitreTechnique: "Application Layer Protocol",
    snippet: "alert dns any any -> any any\n(msg:\"DNS Tunneling Detected\";\ndns_query; content:\"tunnel\";\nsid:2001;)",
    category: "Command and Control",
    description: "Suricata rule for detecting DNS tunneling activities"
  },
  {
    id: "rule-005",
    title: "Registry Persistence",
    language: "Sigma",
    mitreId: "T1547",
    mitreTechnique: "Boot or Logon Autostart Execution",
    snippet: "selection:\n  EventID: 13\n  TargetObject|contains: '\\CurrentVersion\\Run'\n  Details|contains: '.exe'",
    category: "Persistence",
    description: "Detects suspicious registry modifications for persistence"
  },
  {
    id: "rule-006",
    title: "Credential Dumping",
    language: "Sigma",
    mitreId: "T1003",
    mitreTechnique: "OS Credential Dumping",
    snippet: "selection:\n  Image|endswith: 'mimikatz.exe'\n  OR:\n  CommandLine|contains: 'sekurlsa::logonpasswords'",
    category: "Credential Access",
    description: "Detects credential dumping tools and techniques"
  },
  {
    id: "rule-007",
    title: "Valid Accounts Usage",
    language: "Sigma",
    mitreId: "T1078",
    mitreTechnique: "Valid Accounts",
    snippet: "detection:\n  EventID: 4624\n  LogonType: 3\n  AuthenticationPackageName: NTLM\n  AccountName|contains: 'admin'",
    category: "Initial Access",
    description: "Detects suspicious use of valid accounts for initial access or lateral movement."
  },
  {
    id: "rule-008",
    title: "Unsecured Credentials",
    language: "Sigma",
    mitreId: "T1552",
    mitreTechnique: "Unsecured Credentials",
    snippet: "detection:\n  keywords:\n    - 'password'\n    - 'api_key'\n    - 'credentials.json'",
    category: "Credential Access",
    description: "Detects unsecured credentials stored in files, scripts, or repositories."
  },
  {
    id: "rule-009",
    title: "Forge Web Credentials",
    language: "Sigma",
    mitreId: "T1606",
    mitreTechnique: "Forge Web Credentials",
    snippet: "detection:\n  EventID: 4663\n  ObjectName|endswith: 'cookies.sqlite'\n  AccessMask: '0x1'",
    category: "Credential Access",
    description: "Detects attempts to forge web credentials like session cookies."
  },
  {
    id: "rule-010",
    title: "Cloud Service Discovery",
    language: "Sigma",
    mitreId: "T1526",
    mitreTechnique: "Cloud Service Discovery",
    snippet: "detection:\n  action: 'Describe*'\n  service: 'ec2.amazonaws.com'\n  user_agent|contains: 'curl'",
    category: "Discovery",
    description: "Detects enumeration of cloud services by an adversary."
  },
  {
    id: "rule-011",
    title: "Resource Hijacking",
    language: "Sigma",
    mitreId: "T1496",
    mitreTechnique: "Resource Hijacking",
    snippet: "detection:\n  Image|endswith: 'xmrig.exe'\n  CommandLine|contains: '--donate-level'",
    category: "Impact",
    description: "Detects processes associated with cryptocurrency mining or other resource hijacking."
  },
  {
    id: "rule-012",
    title: "Supply Chain Compromise",
    language: "Sigma",
    mitreId: "T1195",
    mitreTechnique: "Supply Chain Compromise",
    snippet: "detection:\n  Signature: 'Trojan.Sunburst'\n  Source: 'SolarWinds.Orion.Core.BusinessLayer.dll'",
    category: "Initial Access",
    description: "Detects indicators of a supply chain compromise."
  },
  {
    id: "rule-013",
    title: "Data from Cloud Storage",
    language: "Sigma",
    mitreId: "T1530",
    mitreTechnique: "Data from Cloud Storage Object",
    snippet: "detection:\n  EventName: 'GetObject'\n  RequestParameters:\n    BucketName: 'sensitive-data-bucket'",
    category: "Collection",
    description: "Detects anomalous access to data in cloud storage objects."
  },
  {
    id: "rule-014",
    title: "Account Manipulation",
    language: "Sigma",
    mitreId: "T1098",
    mitreTechnique: "Account Manipulation",
    snippet: "detection:\n  EventID: 4738\n  TargetUserName: 'Administrator'\n  MemberSid|contains: 'S-1-5-21...'",
    category: "Persistence",
    description: "Detects manipulation of accounts, such as adding a new user to a privileged group."
  },
  {
    id: "rule-015",
    title: "External Remote Services",
    language: "Sigma",
    mitreId: "T1133",
    mitreTechnique: "External Remote Services",
    snippet: "detection:\n  EventID: 4625\n  LogonType: 10\n  ProcessName|endswith: 'svchost.exe'",
    category: "Initial Access",
    description: "Detects failed logon attempts from external remote services like VPN or RDP."
  },
  {
    id: "rule-016",
    title: "Exploitation for Privilege Escalation",
    language: "Sigma",
    mitreId: "T1068",
    mitreTechnique: "Exploitation for Privilege Escalation",
    snippet: "detection:\n  Image|endswith: 'cmd.exe'\n  ParentImage|endswith: 'services.exe'\n  CommandLine|contains: 'sc create'",
    category: "Privilege Escalation",
    description: "Detects exploitation of vulnerabilities for privilege escalation."
  },
  {
    id: "rule-017",
    title: "Pass the Hash",
    language: "Sigma",
    mitreId: "T1550.002",
    mitreTechnique: "Use Alternate Authentication Material: Pass the Hash",
    snippet: "detection:\n  EventID: 4624\n  LogonType: 9\n  AuthenticationPackageName: 'Negotiate'",
    category: "Lateral Movement",
    description: "Detects Pass-the-Hash activity by monitoring for specific logon types and authentication packages."
  },
  {
    id: "rule-018",
    title: "Pass the Ticket",
    language: "Sigma",
    mitreId: "T1550.003",
    mitreTechnique: "Use Alternate Authentication Material: Pass the Ticket",
    snippet: "detection:\n  EventID: 4769\n  Service Name: 'krbtgt'\n  TicketOptions: '0x40810010'",
    category: "Lateral Movement",
    description: "Detects Pass-the-Ticket activity by monitoring Kerberos TGS requests with suspicious ticket options."
  },
  {
    id: "rule-019",
    title: "Ingress Tool Transfer",
    language: "Sigma",
    mitreId: "T1105",
    mitreTechnique: "Ingress Tool Transfer",
    snippet: "detection:\n  CommandLine|contains:\n    - 'certutil -urlcache -split -f'\n    - 'bitsadmin /transfer'",
    category: "Command and Control",
    description: "Detects the use of built-in utilities to download tools from an external source."
  },
  {
    id: "rule-020",
    title: "Modify Authentication Process",
    language: "Sigma",
    mitreId: "T1556",
    mitreTechnique: "Modify Authentication Process",
    snippet: "detection:\n  TargetObject|contains: 'Winlogon\\SpecialAccounts'\n  EventType: 'CreateKey'",
    category: "Credential Access",
    description: "Detects attempts to modify authentication processes, such as manipulating Winlogon helper DLLs."
  },
  {
    id: "rule-021",
    title: "Steal Web Session Cookie",
    language: "Sigma",
    mitreId: "T1539",
    mitreTechnique: "Steal Web Session Cookie",
    snippet: "selection:\n  TargetFilename|endswith:\n    - '\\Cookies'\n    - '\\Web Data'",
    category: "Credential Access",
    description: "Detects access to files commonly used to store web session cookies."
  },
  {
    id: "rule-022",
    title: "Steal Application Access Token",
    language: "Sigma",
    mitreId: "T1528",
    mitreTechnique: "Steal Application Access Token",
    snippet: "selection:\n  powershell.file.script_block_text|contains:\n    - 'Get-AzureADToken'\n    - 'access_token'",
    category: "Credential Access",
    description: "Detects attempts to steal application access tokens, often through PowerShell."
  },
  {
    id: "rule-023",
    title: "Internal Spearphishing",
    language: "Sigma",
    mitreId: "T1534",
    mitreTechnique: "Internal Spearphishing",
    snippet: "selection:\n  Sender: '*@internal_domain.com'\n  Recipient: '*@internal_domain.com'\n  Subject|contains: 'Urgent Action Required'",
    category: "Lateral Movement",
    description: "Detects potential internal spearphishing attempts originating from within the organization."
  },
  {
    id: "rule-024",
    title: "Web Shell Persistence",
    language: "Sigma",
    mitreId: "T1505.003",
    mitreTechnique: "Server Software Component: Web Shell",
    snippet: "detection:\n  - CommandLine|contains:\n    - 'aspx_shell'\n    - 'pspy'\n  - Filename|endswith: '.aspx'",
    category: "Persistence",
    description: "Detects command execution from common web shell filenames or suspicious file uploads."
  }
];

export const irPlaybooks: Playbook[] = [
  {
    "id": "ir-003",
    "title": "Data Breach",
    "description": "A guide for responding to unauthorized access, disclosure, or exfiltration of sensitive, confidential, or proprietary data.",
    "category": "Data Security",
    "readingTime": "8 min read",
    "pdfUrl": "/irplaybooks/Data_Breach.pdf",
    "mitreMapping": [
      {
        "tactic": "Initial Access",
        "techniques": [
          { "id": "T1566", "name": "Phishing" },
          { "id": "T1190", "name": "Exploit Public-Facing Application" }
        ]
      },
      {
        "tactic": "Credential Access",
        "techniques": [
          { "id": "T1003", "name": "OS Credential Dumping" },
          { "id": "T1110", "name": "Brute Force" }
        ]
      },
      {
        "tactic": "Lateral Movement",
        "techniques": [{ "id": "T1021", "name": "Remote Services" }]
      },
      {
        "tactic": "Collection",
        "techniques": [
          { "id": "T1005", "name": "Data from Local System" },
          { "id": "T1530", "name": "Data from Cloud Storage Object" }
        ]
      },
      {
        "tactic": "Exfiltration",
        "techniques": [
          { "id": "T1041", "name": "Exfiltration Over C2 Channel" },
          { "id": "T1567", "name": "Exfiltration Over Web Service" }
        ]
      }
    ]
  },
  {
    "id": "ir-005",
    "title": "Data Exfiltration & Cloud-Related Activity",
    "description": "Operational guidance for responding to incidents where attackers or misconfigured systems move sensitive data out of the environment using cloud storage, file transfers, or APIs.",
    "category": "Data Security",
    "readingTime": "8 min read",
    "pdfUrl": "/irplaybooks/Data_Exfiltration_and_Cloud_Related_Activity.pdf",
    "mitreMapping": [
      {
        "tactic": "Exfiltration",
        "techniques": [
          { "id": "T1041", "name": "Exfiltration Over C2 Channel" },
          { "id": "T1537", "name": "Transfer Data to Cloud Account" },
          { "id": "T1567", "name": "Exfiltration Over Web Service" }
        ]
      },
      {
        "tactic": "Credential Access",
        "techniques": [
          { "id": "T1078", "name": "Valid Accounts" },
          { "id": "T1552", "name": "Unsecured Credentials" }
        ]
      },
      {
        "tactic": "Defense Evasion",
        "techniques": [
          { "id": "T1070", "name": "Indicator Removal on Host" },
          { "id": "T1027", "name": "Obfuscated Files or Information" }
        ]
      },
      {
        "tactic": "Collection",
        "techniques": [{ "id": "T1074", "name": "Data Staged" }]
      }
    ]
  },
  {
    "id": "ir-006",
    "title": "Email and Social Engineering Attacks",
    "description": "Procedures for responding to email and social engineering attacks to minimize credential compromise, financial fraud, and malware delivery.",
    "category": "Email Security",
    "readingTime": "8 min read",
    "pdfUrl": "/irplaybooks/Email_and_Social_Engineering_Attacks.pdf",
    "mitreMapping": [
      {
        "tactic": "Initial Access",
        "techniques": [{ "id": "T1566", "name": "Phishing" }]
      },
      {
        "tactic": "Credential Access",
        "techniques": [
          { "id": "T1110", "name": "Brute Force" },
          { "id": "T1556", "name": "Modify Authentication Process" }
        ]
      },
      {
        "tactic": "Persistence",
        "techniques": [{ "id": "T1098", "name": "Account Manipulation" }]
      },
      {
        "tactic": "Defense Evasion",
        "techniques": [{ "id": "T1078", "name": "Valid Accounts" }]
      },
      {
        "tactic": "Impact",
        "techniques": [{ "id": "T1499", "name": "Endpoint Denial of Service" }]
      }
    ]
  },
  {
    "id": "ir-007",
    "title": "Lateral Movement & Privilege Escalation",
    "description": "A repeatable, operational response for incidents involving techniques like Pass-the-Hash, token theft, and other escalation vectors.",
    "category": "Endpoint Security",
    "readingTime": "8 min read",
    "pdfUrl": "/irplaybooks/Lateral_Movement_and_Privilege_Escalation.pdf",
    "mitreMapping": [
      {
        "tactic": "Credential Access",
        "techniques": [
          { "id": "T1003", "name": "OS Credential Dumping" },
          { "id": "T1550", "name": "Use Alternate Authentication Material" },
          { "id": "T1078", "name": "Valid Accounts" }
        ]
      },
      {
        "tactic": "Lateral Movement",
        "techniques": [
          { "id": "T1021", "name": "Remote Services" },
          { "id": "T1570", "name": "Lateral Tool Transfer" },
          { "id": "T1563", "name": "Remote Service Session Hijacking" }
        ]
      },
      {
        "tactic": "Privilege Escalation",
        "techniques": [
          { "id": "T1068", "name": "Exploitation for Privilege Escalation" },
          { "id": "T1548", "name": "Abuse Elevation Control Mechanism" }
        ]
      },
      {
        "tactic": "Defense Evasion",
        "techniques": [
          { "id": "T1134", "name": "Access Token Manipulation" },
          { "id": "T1055", "name": "Process Injection" }
        ]
      }
    ]
  },
  {
    "id": "ir-008",
    "title": "Physical Devices & Insider Threats",
    "description": "Operational procedures for incidents involving suspicious USB device usage and insider-driven data exfiltration.",
    "category": "Insider Threat",
    "readingTime": "8 min read",
    "pdfUrl": "/irplaybooks/Physical_Devices_and_Insider_Threats.pdf",
    "mitreMapping": [
      {
        "tactic": "Initial Access",
        "techniques": [{ "id": "T1078", "name": "Valid Accounts" }]
      },
      {
        "tactic": "Collection",
        "techniques": [
          { "id": "T1113", "name": "Screen Capture" },
          { "id": "T1005", "name": "Data from Local System" },
          { "id": "T1074", "name": "Data Staged" }
        ]
      },
      {
        "tactic": "Exfiltration",
        "techniques": [
          { "id": "T1041", "name": "Exfiltration Over C2 Channel" },
          { "id": "T1567", "name": "Exfiltration Over Web Service" }
        ]
      },
      {
        "tactic": "Defense Evasion",
        "techniques": [
          { "id": "T1070", "name": "Indicator Removal on Host" },
          { "id": "T1027", "name": "Obfuscated Files or Information" }
        ]
      }
    ]
  },
  {
    "id": "ir-009",
    "title": "Command-and-Control (C2) & External Communication",
    "description": "Operational guidance for incidents involving C2 beaconing, covert channels, DGA-generated domains, and unusual outbound patterns.",
    "category": "Network Security",
    "readingTime": "8 min read",
    "pdfUrl": "/irplaybooks/Command_and_Control_and_External_Communication.pdf",
    "mitreMapping": [
      {
        "tactic": "Command and Control",
        "techniques": [
          { "id": "T1071", "name": "Application Layer Protocol" },
          { "id": "T1095", "name": "Non-Application Layer Protocol" },
          { "id": "T1105", "name": "Ingress Tool Transfer" },
          { "id": "T1483", "name": "Domain Generation Algorithms" }
        ]
      },
      {
        "tactic": "Exfiltration",
        "techniques": [
          { "id": "T1041", "name": "Exfiltration Over C2 Channel" },
          { "id": "T1567", "name": "Exfiltration Over Web Service" }
        ]
      },
      {
        "tactic": "Defense Evasion",
        "techniques": [
          { "id": "T1573", "name": "Encrypted Channel" },
          { "id": "T1090", "name": "Proxy" }
        ]
      }
    ]
  },
  {
    "id": "ir-010",
    "title": "Account Compromise & Credential-Based Attacks",
    "description": "Operational procedures for attacks leveraging stolen, guessed, or abused credentials, including brute-force, password-spraying, and token theft.",
    "category": "Identity & Access",
    "readingTime": "8 min read",
    "pdfUrl": "/irplaybooks/Account_Compromise_and_Credential_Based_Attacks.pdf",
    "mitreMapping": [
      {
        "tactic": "Initial Access",
        "techniques": [
          { "id": "T1110", "name": "Brute Force" },
          { "id": "T1078", "name": "Valid Accounts" }
        ]
      },
      {
        "tactic": "Credential Access",
        "techniques": [
          { "id": "T1530", "name": "Data from Cloud Storage Object" },
          { "id": "T1003", "name": "OS Credential Dumping" }
        ]
      },
      {
        "tactic": "Persistence",
        "techniques": [
          { "id": "T1098", "name": "Account Manipulation" },
          { "id": "T1543", "name": "Create or Modify System Process" }
        ]
      },
      {
        "tactic": "Defense Evasion",
        "techniques": [
          { "id": "T1550", "name": "Use Alternate Authentication Material" },
          { "id": "T1070", "name": "Indicator Removal on Host" }
        ]
      },
      {
        "tactic": "Lateral Movement",
        "techniques": [
          { "id": "T1021", "name": "Remote Services" },
          { "id": "T1570", "name": "Lateral Tool Transfer" }
        ]
      }
    ]
  },
  {
    "id": "ir-011",
    "title": "Network Scanning & Denial-of-Service Attacks",
    "description": "Steps for incidents involving active network probing, reconnaissance, and volumetric or application-layer DoS/DDoS attacks.",
    "category": "Network Security",
    "readingTime": "8 min read",
    "pdfUrl": "/irplaybooks/Network_Scanning_and_Denial_of_Service_Attacks.pdf",
    "mitreMapping": [
      {
        "tactic": "Reconnaissance",
        "techniques": [
          { "id": "T1595", "name": "Active Scanning" },
          { "id": "T1046", "name": "Network Service Discovery" }
        ]
      },
      {
        "tactic": "Impact",
        "techniques": [
          { "id": "T1498", "name": "Network Denial of Service" },
          { "id": "T1499", "name": "Endpoint Denial of Service" }
        ]
      },
      {
        "tactic": "Command and Control",
        "techniques": [{ "id": "T1071", "name": "Application Layer Protocol" }]
      }
    ]
  },
  {
    "id": "ir-012",
    "title": "Web Application & Internet-Facing Attacks",
    "description": "Procedures for incidents against internet-facing assets including web servers and APIs, focusing on exploits like web shells, SQLi, and XSS.",
    "category": "Application Security",
    "readingTime": "8 min read",
    "pdfUrl": "/irplaybooks/Web_Application_and_Internet_Facing_Attacks.pdf",
    "mitreMapping": [
      {
        "tactic": "Initial Access",
        "techniques": [
          { "id": "T1190", "name": "Exploit Public-Facing Application" },
          { "id": "T1505", "name": "Server Software Component" }
        ]
      },
      {
        "tactic": "Execution",
        "techniques": [{ "id": "T1059", "name": "Command and Scripting Interpreter" }]
      },
      {
        "tactic": "Persistence",
        "techniques": [{ "id": "T1505.003", "name": "Web Shell" }]
      },
      {
        "tactic": "Impact",
        "techniques": [{ "id": "T1486", "name": "Data Encrypted for Impact" }]
      },
      {
        "tactic": "Exfiltration",
        "techniques": [{ "id": "T1041", "name": "Exfiltration Over C2 Channel" }]
      },
      {
        "tactic": "Defense Evasion",
        "techniques": [
          { "id": "T1027", "name": "Obfuscated Files or Information" },
          { "id": "T1070", "name": "Indicator Removal on Host" }
        ]
      }
    ]
  },
  {
    "id": "ir-013",
    "title": "Critical Vulnerabilities & Patch Management",
    "description": "Response procedures for incidents related to zero-day exploits and high-impact CVEs, focusing on rapid risk assessment and patch coordination.",
    "category": "Vulnerability Management",
    "readingTime": "8 min read",
    "pdfUrl": "/irplaybooks/Critical_Vulnerabilities_and_Patch_Management.pdf",
    "mitreMapping": [
      {
        "tactic": "Initial Access",
        "techniques": [
          { "id": "T1190", "name": "Exploit Public-Facing Application" },
          { "id": "T1203", "name": "Exploitation for Client Execution" }
        ]
      },
      {
        "tactic": "Persistence",
        "techniques": [{ "id": "T1547", "name": "Boot or Logon Autostart Execution" }]
      },
      {
        "tactic": "Privilege Escalation",
        "techniques": [{ "id": "T1068", "name": "Exploitation for Privilege Escalation" }]
      },
      {
        "tactic": "Discovery",
        "techniques": [{ "id": "T1087", "name": "Account Discovery" }]
      },
      {
        "tactic": "Lateral Movement",
        "techniques": [{ "id": "T1021", "name": "Remote Services" }]
      },
      {
        "tactic": "Impact",
        "techniques": [{ "id": "T1486", "name": "Data Encrypted for Impact" }]
      },
      {
        "tactic": "Exfiltration",
        "techniques": [{ "id": "T1041", "name": "Exfiltration Over C2 Channel" }]
      }
    ]
  },
  {
    "id": "ir-014",
    "title": "Malware and Propagation Threats",
    "description": "Guidance for malware families that propagate laterally or achieve persistence, including ransomware, loaders, and process/DLL injection.",
    "category": "Endpoint Security",
    "readingTime": "8 min read",
    "pdfUrl": "/irplaybooks/Malware_and_Propagation_Threats.pdf",
    "mitreMapping": [
      {
        "tactic": "Initial Access",
        "techniques": [
          { "id": "T1566", "name": "Phishing" },
          { "id": "T1078", "name": "Valid Accounts" },
          { "id": "T1190", "name": "Exploit Public-Facing Application" }
        ]
      },
      {
        "tactic": "Execution",
        "techniques": [
          { "id": "T1059", "name": "Command and Scripting Interpreter" },
          { "id": "T1204", "name": "User Execution" }
        ]
      },
      {
        "tactic": "Persistence",
        "techniques": [
          { "id": "T1543", "name": "Create or Modify System Process" },
          { "id": "T1053", "name": "Scheduled Task/Job" }
        ]
      },
      {
        "tactic": "Privilege Escalation",
        "techniques": [
          { "id": "T1068", "name": "Exploitation for Privilege Escalation" },
          { "id": "T1134", "name": "Access Token Manipulation" }
        ]
      },
      {
        "tactic": "Defense Evasion",
        "techniques": [
          { "id": "T1027", "name": "Obfuscated Files or Information" },
          { "id": "T1070", "name": "Indicator Removal on Host" }
        ]
      },
      {
        "tactic": "Credential Access",
        "techniques": [{ "id": "T1003", "name": "OS Credential Dumping" }]
      },
      {
        "tactic": "Lateral Movement",
        "techniques": [
          { "id": "T1021", "name": "Remote Services" },
          { "id": "T1570", "name": "Lateral Tool Transfer" }
        ]
      },
      {
        "tactic": "Command and Control",
        "techniques": [
          { "id": "T1071", "name": "Application Layer Protocol" },
          { "id": "T1483", "name": "Domain Generation Algorithms" }
        ]
      },
      {
        "tactic": "Impact",
        "techniques": [{ "id": "T1486", "name": "Data Encrypted for Impact" }]
      }
    ]
  }
];

export const investigationPlaybooks: Playbook[] = [
  {
    id: "inv-001",
    title: "Digital Forensics Investigation",
    description: "Comprehensive guide for conducting digital forensic investigations including evidence acquisition, analysis techniques, and chain of custody procedures.",
    category: "Forensics",
    readingTime: "25 min read",
    pdfUrl: "/playbooks/digital-forensics-investigation.pdf"
  },
  {
    id: "inv-002",
    title: "Network Traffic Analysis",
    description: "Methods for analyzing network traffic patterns, identifying anomalies, and reconstructing attack timelines from packet captures and flow data.",
    category: "Network",
    readingTime: "18 min read",
    pdfUrl: "/playbooks/network-traffic-analysis.pdf"
  },
  {
    id: "inv-003",
    title: "Memory Dump Analysis",
    description: "Techniques for analyzing memory dumps to identify malware, extract volatile artifacts, and understand system compromise indicators.",
    category: "Memory",
    readingTime: "22 min read",
    pdfUrl: "/playbooks/memory-dump-analysis.pdf"
  }
];


export const workflows: Workflow[] = [
  {
    id: "wf-002",
    title: "Email Security Response",
    description: "Automated phishing email analysis and remediation workflow",
    tool: "SIEM",
    pdfUrl: "/pdfs/email-security-response.pdf",
    screenshot: "/screenshots/email-security-workflow.png",
    steps: [
      {
        title: "Email Collection",
        description: "Automated extraction of suspicious emails from mail server"
      },
      {
        title: "Header Analysis",
        description: "Parse email headers and analyze sender reputation"
      },
      {
        title: "Attachment Scan",
        description: "Sandbox analysis of email attachments for malware"
      },
      {
        title: "Email Quarantine",
        description: "Remove malicious emails from all user mailboxes"
      }
    ]
  },
  {
    id: "wf-003",
    title: "Malware Analysis Pipeline",
    description: "Automated malware sample analysis with EDR integration",
    tool: "EDR",
    pdfUrl: "/pdfs/malware-analysis-pipeline.pdf",
    screenshot: "/screenshots/malware-analysis-workflow.png",
    steps: [
      {
        title: "Sample Collection",
        description: "EDR agents automatically collect suspicious files for analysis"
      },
      {
        title: "Static Analysis",
        description: "Hash verification, signature analysis, and metadata extraction"
      },
      {
        title: "Dynamic Analysis",
        description: "Sandbox execution and behavior monitoring"
      },
      {
        title: "IOC Generation",
        description: "Extract indicators and update threat intelligence feeds"
      }
    ]
  },
  {
    id: "wf-004",
    title: "Phishing Email Detection",
    description: "Automated phishing detection workflow with webhook trigger and threat intelligence enrichment",
    tool: "SOAR",
    pdfUrl: "/workflows/Phishing_Email_Detection.docx.pdf",
    screenshot: "/screenshots/phishing-email-workflow.png",
    steps: [
      {
        title: "Webhook Trigger",
        description: "Receives incoming phishing alerts via HTTP POST with authentication validation"
      },
      {
        title: "Payload Validation",
        description: "Ensures authenticity of request and validates required fields (sender, URL, subject)"
      },
      {
        title: "URL Enrichment",
        description: "Queries PhishTank API to check if URL exists in phishing database"
      },
      {
        title: "Decision & Alert",
        description: "If phishing detected, sends Slack alert to SOC team; otherwise logs as clean event"
      }
    ]
  },
  {
    id: "wf-005",
    title: "Business Email Compromise Detection",
    description: "Webhook-based workflow for detecting and responding to BEC attacks with threat intelligence enrichment",
    tool: "SOAR",
    pdfUrl: "/workflows/Business_Email_Compromise_BEC.docx.pdf",
    screenshot: "/screenshots/bec-workflow.png",
    steps: [
      {
        title: "Webhook Trigger",
        description: "Receives BEC alerts via HTTP POST from monitoring systems"
      },
      {
        title: "Event Enrichment",
        description: "Enriches alert data using VirusTotal, AbuseIPDB, PhishTank, and GeoIP APIs"
      },
      {
        title: "Decision Logic",
        description: "Analyzes enrichment results to determine if the event is suspicious"
      },
      {
        title: "Alert & Logging",
        description: "Sends Slack alert to SOC team for suspicious events or logs clean events for audit"
      }
    ]
  },
  {
    id: "wf-006",
    title: "Ransomware Attack Detection",
    description: "Real-time ransomware detection workflow with VirusTotal hash analysis and automated alerting",
    tool: "SOAR",
    pdfUrl: "/workflows/Ransomware_Attack_Detection.docx.pdf",
    screenshot: "/screenshots/ransomware-workflow.png",
    steps: [
      {
        title: "Webhook Trigger",
        description: "Receives ransomware alerts with file hash and endpoint information via secure webhook"
      },
      {
        title: "Payload Validation",
        description: "Validates webhook secret and ensures required fields (hash, endpoint) are present"
      },
      {
        title: "Hash Analysis",
        description: "Queries VirusTotal API to check file hash against threat intelligence database"
      },
      {
        title: "Threat Response",
        description: "Sends high-priority Slack alert if malicious or logs clean file for audit trail"
      }
    ]
  },
  {
    id: "wf-007",
    title: "Website Scam Risk Detector",
    description: "AI-powered multi-agent workflow for evaluating website legitimacy using GPT-4o and SerpAPI",
    tool: "SOAR",
    pdfUrl: "/workflows/Website_Scam_Risk_Detector.docx.pdf",
    screenshot: "/screenshots/scam-detector-workflow.png",
    steps: [
      {
        title: "Form Submission",
        description: "User submits URL through form interface to initiate scam analysis"
      },
      {
        title: "Multi-Agent Analysis",
        description: "Four GPT-4o agents analyze domain details, search signals, pricing patterns, and content quality"
      },
      {
        title: "Data Aggregation",
        description: "All agent findings are collected and passed to the Analyzer agent"
      },
      {
        title: "Risk Assessment",
        description: "GPT-4o mini Analyzer scores site (1-10) and generates structured report with scam likelihood"
      }
    ]
  }
];

export const teamMembers: TeamMember[] = [
  {
    id: "team-001",
    name: "Mostafa Elsaeed",
    role: "SOC Engineer",
    bio: "SOC Analyst and Cybersecurity Engineering with hands-on in threat detection and incident response. Specializing in leveraging SIEM technologies like IBM QRadar to fortify network defenses and proactively hunt for emerging threats.",
    image: "/images/Mostafa.jpeg",
    color: "primary",
    linkedin: "https://www.linkedin.com/in/mostafa-elsaeed-eg/",
    portfolio: "https://mowael-encrypted.github.io/"
  },
  {
    id: "team-002",
    name: "Islam Walid",
    role: "SOC Engineer",
    bio: "rising cybersecurity talent with a track record of cracking challenges on TryHackMe, OverTheWire, and real-world SOC training programs. Backed by top-tier certifications like Cisco Cyber Ops and Huawei HCIA-Security (scoring a perfect 100%), I have sharpened my skills in threat detection, incident response, and penetration testing through internships at Telecom Egypt, NTI, Huawei, and DEPI. Blending my engineering background with hands-on cyber defense expertise, I thrive on turning complex security problems into smart, effective solutions. My mission is to grow into a standout SOC engineer who strengthens defenses and stays two steps ahead of attackers.",
    image: "/images/islam.jpg",
    color: "secondary",
    linkedin: "https://www.linkedin.com/in/islam-walid-1311b7326/",
    portfolio: "https://janedoe.com"
  },
  {
    id: "team-003",
    name: "Hamza Shaaban",
    role: "Security Engineer",
    bio: "SOAR platform specialist and DevSecOps engineer. Expert in Python automation, API integrations, and workflow orchestration for security operations.",
    image: "/images/hamza.jpg",
    color: "accent",
    linkedin: "https://www.linkedin.com/in/hamza-s-ahmed-614886258",
    portfolio: "#"
  },
    {
    id: "team-003",
    name: "Samar Elkharat",
    role: "Security Engineer",
    bio: "Aspiring Cybersecurity and Electronics Engineering student with hands-on experience in networking, hardware design, and security labs. Skilled in troubleshooting, system design, and tech projects, eager to apply knowledge through real-world challenges.",
    image: "/images/samar.jpg",
    color: "accent",
    linkedin: "https://www.linkedin.com/in/samar-elkharat-45540224a",
    portfolio: "https://mkmkh.my.canva.site/i-m-samar-mohmed"
  },
    {
    id: "team-003",
    name: "Shahd Emad",
    role: "Security Engineer",
    bio: "SOAR platform specialist and DevSecOps engineer. Expert in Python automation, API integrations, and workflow orchestration for security operations.",
    image: "/images/shahd.jpg",
    color: "accent",
    linkedin: "https://www.linkedin.com/in/shahd-emad-44840b241/",
    portfolio: "#"
  }
];