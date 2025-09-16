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

export interface Playbook {
  id: string;
  title: string;
  description: string;
  category: string;
  readingTime: string;
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
}

export interface TeamMember {
  id: string;
  name: string;
  role: string;
  bio: string;
  image: string;
  color: string;
  linkedin: string;
  twitter: string;
  github: string;
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
  }
];

export const irPlaybooks: Playbook[] = [
  {
    id: "ir-001",
    title: "Malware Incident Response",
    description: "Comprehensive guide for handling malware incidents including containment, eradication, recovery procedures, and post-incident activities. Covers both automated and manual response steps.",
    category: "Malware",
    readingTime: "15 min read"
  },
  {
    id: "ir-002",
    title: "Phishing Incident Response",
    description: "Step-by-step procedures for investigating and responding to phishing attacks. Includes email analysis, user impact assessment, and preventive measures.",
    category: "Phishing",
    readingTime: "12 min read"
  },
  {
    id: "ir-003",
    title: "Ransomware Incident Response",
    description: "Critical response procedures for ransomware attacks including isolation, backup verification, decryption options, and business continuity planning.",
    category: "Ransomware",
    readingTime: "20 min read"
  },
  {
    id: "ir-004",
    title: "Insider Threat Response",
    description: "Procedures for handling insider threat incidents including data access monitoring, privilege escalation detection, and evidence preservation.",
    category: "Insider Threat",
    readingTime: "18 min read"
  }
];

export const investigationPlaybooks: Playbook[] = [
  {
    id: "inv-001",
    title: "Digital Forensics Investigation",
    description: "Comprehensive guide for conducting digital forensic investigations including evidence acquisition, analysis techniques, and chain of custody procedures.",
    category: "Forensics",
    readingTime: "25 min read"
  },
  {
    id: "inv-002",
    title: "Network Traffic Analysis",
    description: "Methods for analyzing network traffic patterns, identifying anomalies, and reconstructing attack timelines from packet captures and flow data.",
    category: "Network",
    readingTime: "18 min read"
  },
  {
    id: "inv-003",
    title: "Memory Dump Analysis",
    description: "Techniques for analyzing memory dumps to identify malware, extract volatile artifacts, and understand system compromise indicators.",
    category: "Memory",
    readingTime: "22 min read"
  }
];

export const workflows: Workflow[] = [
  {
    id: "wf-001",
    title: "Automated Threat Containment",
    description: "SOAR-based workflow for isolating compromised endpoints and blocking malicious IPs",
    tool: "SOAR",
    steps: [
      {
        title: "Alert Detection",
        description: "SIEM triggers alert for suspicious activity and sends webhook to SOAR platform"
      },
      {
        title: "Threat Assessment",
        description: "Automated analysis of threat indicators against threat intelligence feeds"
      },
      {
        title: "Endpoint Isolation",
        description: "EDR API calls to isolate affected endpoints from network"
      },
      {
        title: "IP Blocking",
        description: "Firewall rules updated to block malicious IP addresses"
      }
    ]
  },
  {
    id: "wf-002",
    title: "Email Security Response",
    description: "Automated phishing email analysis and remediation workflow",
    tool: "SIEM",
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
  }
];

export const teamMembers: TeamMember[] = [
  {
    id: "team-001",
    name: "Alex Chen",
    role: "Lead Security Researcher",
    bio: "Former SOC analyst with 8 years experience in threat hunting and incident response. Specializes in MITRE ATT&CK framework mapping and detection engineering.",
    image: "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=400",
    color: "primary",
    linkedin: "#",
    twitter: "#",
    github: "#"
  },
  {
    id: "team-002",
    name: "Sarah Rodriguez",
    role: "Digital Forensics Expert",
    bio: "Certified forensic investigator with expertise in memory analysis, network forensics, and malware reverse engineering. GCFA and EnCE certified.",
    image: "https://images.unsplash.com/photo-1580489944761-15a19d654956?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=400",
    color: "secondary",
    linkedin: "#",
    twitter: "#",
    github: "#"
  },
  {
    id: "team-003",
    name: "Marcus Thompson",
    role: "Automation Engineer",
    bio: "SOAR platform specialist and DevSecOps engineer. Expert in Python automation, API integrations, and workflow orchestration for security operations.",
    image: "https://images.unsplash.com/photo-1519085360753-af0119f7cbe7?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=400&h=400",
    color: "accent",
    linkedin: "#",
    twitter: "#",
    github: "#"
  }
];
