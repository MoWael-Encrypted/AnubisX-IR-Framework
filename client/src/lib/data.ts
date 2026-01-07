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
  jsonPath: string; 
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
    title: "BEC - Suspicious Mailbox Rule or Forwarding Changes",
    language: "Sigma",
    mitreId: "T1531",
    mitreTechnique: "Account Access Removal",
    snippet: "mailbox_rule:\n  Operation|contains:\n    - 'New-InboxRule'\n    - 'Set-Mailbox'\n  Details|contains:\n    - 'ForwardTo'\n    - 'RedirectTo'\n    - 'DeleteMessage'",
    category: "Credential Access",
    description: "Detects creation of mailbox rules or forwarding configuration changes that may indicate account compromise."
  },
  {
    id: "rule-003",
    title: "Endpoint Beaconing - Periodic Callback Behavior",
    language: "Sigma",
    mitreId: "T1071",
    mitreTechnique: "Application Layer Protocol",
    snippet: "periodic_request:\n  Url|contains:\n    - '.tk'\n    - '.top'\n    - '.pw'\n    - '.ru'\n    - '.info'\n  RequestInterval|lt: 600",
    category: "Command and Control",
    description: "Detects periodic small network callbacks that may indicate C2 beacons."
  },
  {
    id: "rule-004",
    title: "Impossible Travel / Unusual VPN Login",
    language: "Sigma",
    mitreId: "T1078",
    mitreTechnique: "Valid Accounts",
    snippet: "travel:\n  User|is_not_null: true\n  LocationChange: true",
    category: "Initial Access",
    description: "Detects impossible travel or geographically inconsistent logins for the same account."
  },
  {
    id: "rule-005",
    title: "Ransomware - Mass File Encryption Activity",
    language: "Sigma",
    mitreId: "T1486",
    mitreTechnique: "Data Encrypted for Impact",
    snippet: "mass_write:\n  TargetFilename|endswith:\n    - '.locked'\n    - '.enc'\n    - '.encrypted'\n    - '.crypted'\nshadow_delete:\n  CommandLine|contains:\n    - 'vssadmin delete shadows'\n    - 'wmic shadowcopy delete'\n    - 'wbadmin delete catalog'",
    category: "Impact",
    description: "Detects mass file modifications and shadow copy deletion indicative of ransomware activity."
  },
  {
    id: "rule-006",
    title: "Web Shell Upload or Execution Activity",
    language: "Sigma",
    mitreId: "T1505.003",
    mitreTechnique: "Server Software Component: Web Shell",
    snippet: "upload_write:\n  RequestUri|contains:\n    - '/upload'\n    - '/wp-content/uploads/'\n    - '/uploads/'\n  ResponseStatus|in:\n    - '200'\n    - '201'\nshell_execution:\n  RequestUri|contains:\n    - '.php'\n    - '.asp'\n    - '.aspx'\n    - '.jsp'\n  RequestMethod|contains:\n    - 'POST'\n    - 'PUT'",
    category: "Persistence",
    description: "Detects file uploads to web roots and suspicious requests executing webshells."
  },
  {
    id: "rule-007",
    title: "Suspicious Executable Dropped to User Directory",
    language: "Sigma",
    mitreId: "T1204",
    mitreTechnique: "User Execution",
    snippet: "suspicious_path:\n  TargetFilename|contains:\n    - '\\AppData\\Roaming\\'\n    - '\\AppData\\Local\\Temp\\'\n    - '\\Users\\Public\\'\n    - '\\ProgramData\\'\n  TargetFilename|endswith:\n    - '.exe'\n    - '.dll'\n    - '.ps1'\n    - '.bat'\n    - '.cmd'",
    category: "Execution",
    description: "Detects executables, DLLs, and scripts dropped into user-writable directories commonly used by malware droppers."
  },
  {
    id: "rule-008",
    title: "Data Exfiltration via Cloud Storage",
    language: "Sigma",
    mitreId: "T1567",
    mitreTechnique: "Exfiltration Over Web Service",
    snippet: "cloud_upload:\n  Url|contains:\n    - 'dropboxusercontent'\n    - 'amazonaws.com'\n    - 'googleapis.com'\n    - 'drive.google.com'\n  Method|contains:\n    - 'PUT'\n    - 'POST'\n  ContentLength|gt: 10485760",
    category: "Exfiltration",
    description: "Detects large uploads to external cloud storage providers from internal accounts."
  },
  {
    id: "rule-009",
    title: "Cloud Account Compromise - Unusual Console Activity",
    language: "Sigma",
    mitreId: "T1078",
    mitreTechnique: "Valid Accounts",
    snippet: "unusual_activity:\n  Operation|contains:\n    - 'Add-AzureADApplication'\n    - 'CreateAccessKey'\n    - 'Set-Mailbox'\n    - 'CreateUser'\n  SigninRiskLevel|contains:\n    - 'high'\n    - 'medium'",
    category: "Initial Access",
    description: "Detects suspicious cloud management/API activity indicating potential account compromise."
  },
  {
    id: "rule-010",
    title: "Phishing - Suspicious Email with URL or Macro Attachment",
    language: "Sigma",
    mitreId: "T1566",
    mitreTechnique: "Phishing",
    snippet: "suspicious_attachment:\n  AttachmentName|endswith:\n    - '.doc'\n    - '.docm'\n    - '.xlsm'\n    - '.zip'\n    - '.hta'\nsuspicious_url:\n  Url|contains:\n    - 'bit.ly'\n    - 'tinyurl'\n    - 'goo.gl'\n    - 't.co'\n    - 'onelink'",
    category: "Initial Access",
    description: "Detects emails with likely malicious attachments or suspicious shortener/redirect URLs."
  },
  {
    id: "rule-011",
    title: "Suspicious PowerShell Command",
    language: "Sigma",
    mitreId: "T1059.001",
    mitreTechnique: "Command and Scripting Interpreter: PowerShell",
    snippet: "suspicious_ps:\n  CommandLine|contains:\n    - '-enc'\n    - 'IEX'\n    - 'DownloadString'\n    - 'Invoke-Expression'\n    - 'Bypass'",
    category: "Execution",
    description: "Detects obfuscated or encoded PowerShell and download-and-execute behaviors."
  },
  {
    id: "rule-012",
    title: "Brute Force - Multiple Failed SSH/RDP Logins",
    language: "Sigma",
    mitreId: "T1110",
    mitreTechnique: "Brute Force",
    snippet: "failed_login:\n  EventID|in:\n    - '4625'\n  FailureCount|gte: 10",
    category: "Credential Access",
    description: "Detects numerous failed authentication attempts indicating brute-force activity."
  },
  {
    id: "rule-013",
    title: "Password Spraying - Same Password Across Many Accounts",
    language: "Sigma",
    mitreId: "T1110.003",
    mitreTechnique: "Password Spraying",
    snippet: "spray:\n  Password|is_present: true\n  DistinctUsers|count: 10",
    category: "Credential Access",
    description: "Detects same password being tried across many distinct accounts (low-failure per account)."
  },
  {
    id: "rule-014",
    title: "Suspicious Windows Service Created",
    language: "Sigma",
    mitreId: "T1543",
    mitreTechnique: "Create or Modify System Process",
    snippet: "service_create:\n  CommandLine|contains:\n    - 'sc create'\n    - 'New-Service'\n  Image|contains:\n    - '\\AppData\\'\n    - '\\Temp\\'\n    - '\\Users\\Public\\'",
    category: "Persistence",
    description: "Detects new service creations with binaries located in user-writable paths."
  },
  {
    id: "rule-015",
    title: "Suspicious Scheduled Task Created",
    language: "Sigma",
    mitreId: "T1053",
    mitreTechnique: "Scheduled Task/Job",
    snippet: "schtask_create:\n  CommandLine|contains:\n    - 'schtasks /create'\n    - 'Register-ScheduledTask'\n  CommandLine|contains_any:\n    - '\\AppData\\'\n    - '\\Temp\\'\n    - '.ps1'\n    - '.bat'",
    category: "Persistence",
    description: "Detects creation of scheduled tasks pointing to user-writable paths or suspicious scripts."
  },
  {
    id: "rule-016",
    title: "SQL Injection Attempt Detected",
    language: "Sigma",
    mitreId: "T1190",
    mitreTechnique: "Exploit Public-Facing Application",
    snippet: "sqli_payload:\n  RequestUri|contains:\n    - \"' or 1=1\"\n    - 'union select'\n    - 'sleep('\n    - 'benchmark('\n    - 'information_schema'",
    category: "Initial Access",
    description: "Detects possible SQLi payloads in web requests."
  },
  {
    id: "rule-017",
    title: "Suspicious Registry Run Key Modification",
    language: "Sigma",
    mitreId: "T1547",
    mitreTechnique: "Boot or Logon Autostart Execution",
    snippet: "runkey_write:\n  TargetObject|contains:\n    - '\\Microsoft\\Windows\\CurrentVersion\\Run'\n    - 'RunOnce'\n    - 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'\n  Details|contains:\n    - '.exe'\n    - '.ps1'",
    category: "Persistence",
    description: "Detects writes to autorun registry keys indicating persistence attempts."
  },
  {
    id: "rule-018",
    title: "Suspicious DLL Loaded From User Directory",
    language: "Sigma",
    mitreId: "T1055",
    mitreTechnique: "Process Injection",
    snippet: "user_dll:\n  ImageLoaded|contains:\n    - '\\AppData\\'\n    - '\\Temp\\'\n    - '\\Users\\Public\\'\n  ImageLoaded|endswith:\n    - '.dll'",
    category: "Defense Evasion",
    description: "Detects DLLs loaded from user-writable locations and potential process injection activity."
  },
  {
    id: "rule-019",
    title: "Network Port Scanning Activity",
    language: "Sigma",
    mitreId: "T1046",
    mitreTechnique: "Network Service Scanning",
    snippet: "scanning:\n  DestPortCount|gt: 100\n  Flags|contains:\n    - 'SYN'",
    category: "Discovery",
    description: "Detects hosts scanning many ports/hosts in a short time window."
  },
  {
    id: "rule-020",
    title: "Potential DDoS - High Volume Traffic Spike",
    language: "Sigma",
    mitreId: "T1498",
    mitreTechnique: "Network Denial of Service",
    snippet: "volumetric_spike:\n  BytesIn|gt: 100000000\n  UniqueSourceIpCount|gt: 1000",
    category: "Impact",
    description: "Detects sudden volumetric spikes potentially indicating DDoS activity."
  },
  {
    id: "rule-021",
    title: "Suspicious USB Device Usage with Large File Copies",
    language: "Sigma",
    mitreId: "T1025",
    mitreTechnique: "Data from Removable Media",
    snippet: "usb_copy:\n  EventID|in:\n    - '1000'\n  FileCopyCount|gt: 100",
    category: "Exfiltration",
    description: "Detects removable media insertion events followed by large file copy activity."
  },
  {
    id: "rule-022",
    title: "DGA-like DNS Requests",
    language: "Sigma",
    mitreId: "T1568.002",
    mitreTechnique: "Dynamic Resolution: Domain Generation Algorithms",
    snippet: "dga_behavior:\n  QueryName|matches: '^[a-z0-9]{12,}\\.'\n  ResponseCode|contains:\n    - 'NXDOMAIN'",
    category: "Command and Control",
    description: "Detects algorithmically-generated domain patterns and many NXDOMAIN responses."
  },
  {
    id: "rule-023",
    title: "XSS Attempt Detected",
    language: "Sigma",
    mitreId: "T1190",
    mitreTechnique: "Exploit Public-Facing Application",
    snippet: "xss_payload:\n  RequestUri|contains:\n    - '<script>'\n    - '%3Cscript%3E'\n    - 'onerror='\n    - 'document.cookie'\n    - 'alert('",
    category: "Initial Access",
    description: "Detects reflected or stored XSS payloads in HTTP requests."
  },
  {
    id: "rule-024",
    title: "Phishing - Suspicious Email with URL or Macro Attachment",
    language: "EQL",
    mitreId: "T1566",
    mitreTechnique: "Phishing",
    snippet: "email where (attachment.name : \"*.docm\" or attachment.name : \"*.xlsm\" or attachment.name : \"*.hta\" ) or url.domain in (\"bit.ly\",\"tinyurl\",\"t.co\",\"goo.gl\")",
    category: "Initial Access",
    description: "Detects emails with likely malicious attachments or suspicious shortener/redirect URLs."
  },
  {
    id: "rule-025",
    title: "Suspicious API Key Usage or Token Abuse",
    language: "Sigma",
    mitreId: "T1078",
    mitreTechnique: "Valid Accounts",
    snippet: "token_use:\n  UserAgent|contains:\n    - 'curl'\n    - 'python-requests'\n    - 'aws-cli'\n  SourceIp|is_not_in:\n    - 'corporate_ip_ranges'\n  EventName|contains:\n    - 'GetObject'\n    - 'ListBuckets'\n    - 'GetSecretValue'",
    category: "Credential Access",
    description: "Detects API keys or tokens used from unusual IPs or with sudden spikes in activity."
  },
  {
    id: "rule-026",
    title: "Ransomware - Mass File Encryption Activity",
    language: "EQL",
    mitreId: "T1486",
    mitreTechnique: "Data Encrypted for Impact",
    snippet: "process where event.type == \"creation\" and (file.extension in (\"locked\",\"enc\",\"encrypted\",\"crypted\")) or (process.name == \"vssadmin.exe\" and process.args : \"delete shadows\")",
    category: "Impact",
    description: "Detects mass file modifications and shadow copy deletion indicative of ransomware activity."
  },
  {
    id: "rule-027",
    title: "Local Admin Created or SUID Changed",
    language: "Sigma",
    mitreId: "T1548",
    mitreTechnique: "Abuse Elevation Control Mechanism",
    snippet: "admin_add:\n  CommandLine|contains:\n    - 'net localgroup administrators'\n    - 'Add-LocalGroupMember'\n    - 'useradd'\n    - 'usermod -aG sudo'\nsuid_change:\n  CommandLine|contains:\n    - 'chmod +s'\n    - 'chown root'",
    category: "Privilege Escalation",
    description: "Detects creation of local admin accounts or SUID bit changes on Linux."
  },
  {
    id: "rule-028",
    title: "Potential Zero-Day Exploit",
    language: "Sigma",
    mitreId: "T1068",
    mitreTechnique: "Exploitation for Privilege Escalation",
    snippet: "anomaly:\n  EventType|contains:\n    - 'Crash'\n    - 'AccessViolation'\n    - 'Exception'\n  NewProcess|contains:\n    - 'cmd.exe'\n    - 'powershell.exe'\n    - 'rundll32.exe'",
    category: "Execution",
    description: "Generic detection of anomalous crashes followed by unexpected privileged process creation."
  },
  {
    id: "rule-029",
    title: "Insider Data Access Anomaly",
    language: "Sigma",
    mitreId: "T1039",
    mitreTechnique: "Data from Network Shared Drive",
    snippet: "bulk_access:\n  Action|contains:\n    - 'Read'\n    - 'Download'\n  FileCount|gt: 1000",
    category: "Exfiltration",
    description: "Detects bulk access or downloads of sensitive data by internal users."
  },
  {
    id: "rule-030",
    title: "Suspicious FTP/SCP File Transfer",
    language: "Sigma",
    mitreId: "T1048",
    mitreTechnique: "Exfiltration Over Alternative Protocol",
    snippet: "transfers:\n  Protocol|in:\n    - 'FTP'\n    - 'SCP'\n    - 'SFTP'\n  BytesSent|gt: 10485760",
    category: "Exfiltration",
    description: "Detects large FTP/SCP transfers to external destinations."
  },
  {
    id: "rule-031",
    title: "Password Spraying - Same Password Across Many Accounts",
    language: "EQL",
    mitreId: "T1110.003",
    mitreTechnique: "Password Spraying",
    snippet: "authentication where event.outcome == \"failure\" and event.authentication.method : \"password\" and count_distinct(user.name) by event.authentication.password >= 10",
    category: "Credential Access",
    description: "Detects same password attempted across multiple accounts."
  },
  {
    id: "rule-032",
    title: "Endpoint Beaconing - Periodic Callback Behavior",
    language: "EQL",
    mitreId: "T1071",
    mitreTechnique: "Application Layer Protocol",
    snippet: "network where (url.domain : /\\.(tk|top|pw|ru|info)$/) and event.repeat_count > 3",
    category: "Command and Control",
    description: "Detects low-bandwidth periodic HTTP/DNS callbacks to suspicious domains."
  },
  {
    id: "rule-033",
    title: "Cloud Account Compromise - Unusual Console Activity",
    language: "EQL",
    mitreId: "T1078",
    mitreTechnique: "Valid Accounts",
    snippet: "cloudtrail where eventName in (\"CreateAccessKey\",\"CreateUser\",\"PutUserPolicy\",\"AttachUserPolicy\") and sourceIPAddress not in (\"<corporate_ip_ranges>\")",
    category: "Initial Access",
    description: "Detects high-risk cloud admin operations or token creation."
  },
  {
    id: "rule-034",
    title: "BEC - Suspicious Mailbox Rule or Forwarding Changes",
    language: "EQL",
    mitreId: "T1531",
    mitreTechnique: "Account Access Removal",
    snippet: "office365 where event.action in (\"New-InboxRule\",\"Set-Mailbox\") and (event.data : \"ForwardTo\" or event.data : \"RedirectTo\")",
    category: "Persistence",
    description: "Detects mailbox rule or forwarding creation events in Office365 audit logs."
  },
  {
    id: "rule-035",
    title: "Brute Force - Multiple Failed SSH/RDP Logins",
    language: "EQL",
    mitreId: "T1110",
    mitreTechnique: "Brute Force",
    snippet: "authentication where event.outcome == \"failure\" and count() by source.ip, user.name >= 10",
    category: "Credential Access",
    description: "Detects high counts of failed authentication attempts."
  },
  {
    id: "rule-036",
    title: "Data Exfiltration via Cloud Storage",
    language: "EQL",
    mitreId: "T1567",
    mitreTechnique: "Exfiltration Over Web Service",
    snippet: "network where url.domain : (\"dropboxusercontent\",\"amazonaws.com\",\"googleapis.com\",\"drive.google.com\") and http.request.body.bytes > 10485760",
    category: "Exfiltration",
    description: "Detects large uploads to cloud storage endpoints."
  },
  {
    id: "rule-037",
    title: "Web Shell Upload or Execution Activity",
    language: "EQL",
    mitreId: "T1505.003",
    mitreTechnique: "Web Shell",
    snippet: "http where (url.path : \"/upload\" or url.path : \"/wp-content/uploads/\") and http.response.status in (200,201) or (http.request.path : /\\.(php|asp|aspx|jsp)$/ and http.method in (\"POST\",\"PUT\"))",
    category: "Persistence",
    description: "Detects file uploads into webroots and execution of web-facing script extensions."
  },
  {
    id: "rule-038",
    title: "Suspicious PowerShell Command",
    language: "EQL",
    mitreId: "T1059.001",
    mitreTechnique: "PowerShell",
    snippet: "process where process.name : \"powershell.exe\" and (process.args : \"-enc\" or process.args : \"IEX\" or process.args : \"DownloadString\")",
    category: "Execution",
    description: "Detects encoded or suspicious PowerShell command lines."
  },
  {
    id: "rule-039",
    title: "Impossible Travel / Unusual VPN Login",
    language: "EQL",
    mitreId: "T1078",
    mitreTechnique: "Valid Accounts",
    snippet: "authentication where user.name == user.name and (event.geo.location != prev(event.geo.location) and event.duration_between(prev(event.@timestamp), event.@timestamp) < 3600)",
    category: "Initial Access",
    description: "Detects geographically inconsistent logins for same user in short time."
  },
  {
    id: "rule-040",
    title: "Suspicious Executable Dropped to User Directory",
    language: "EQL",
    mitreId: "T1204",
    mitreTechnique: "User Execution",
    snippet: "process where file.path : \"\\\\AppData\\\\Roaming\\\\\" or file.path : \"\\\\Local\\\\Temp\\\\\" and file.extension in (\"exe\",\"dll\",\"ps1\",\"bat\")",
    category: "Execution",
    description: "Detects executables or scripts written to user-writable directories."
  },
  {
    id: "rule-041",
    title: "Insider Data Access Anomaly",
    language: "EQL",
    mitreId: "T1039",
    mitreTechnique: "Data from Network Shared Drive",
    snippet: "file where file.path : (\"/HR/\",\"/Finance/\") and count() by user.name > 1000",
    category: "Exfiltration",
    description: "Detects bulk reads/downloads of sensitive file locations."
  },
  {
    id: "rule-042",
    title: "Suspicious Registry Run Key Modification",
    language: "EQL",
    mitreId: "T1547.001",
    mitreTechnique: "Registry Run Keys / Startup Folder",
    snippet: "registry where registry.path : \"Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\" and registry.operation == \"SetValue\"",
    category: "Persistence",
    description: "Detects additions to Run/RunOnce autorun registry keys."
  },
  {
    id: "rule-043",
    title: "Network Port Scanning Activity",
    language: "EQL",
    mitreId: "T1046",
    mitreTechnique: "Network Service Scanning",
    snippet: "network where event.type == \"connection\" and count_distinct(destination.port) by source.ip >= 100",
    category: "Discovery",
    description: "Detects hosts that attempt connections to many destination ports in short time."
  },
  {
    id: "rule-044",
    title: "SQL Injection Attempt Detected",
    language: "EQL",
    mitreId: "T1190",
    mitreTechnique: "Exploit Public-Facing Application",
    snippet: "http where http.request.body : (\"' or 1=1\" or \"union select\" or \"sleep(\")",
    category: "Initial Access",
    description: "Detects SQLi-like payloads in HTTP request URIs."
  },
  {
    id: "rule-045",
    title: "Potential DDoS - High Volume Traffic Spike",
    language: "EQL",
    mitreId: "T1498",
    mitreTechnique: "Network Denial of Service",
    snippet: "netflow where sum(bytes) by destination.ip > 100000000 and count_distinct(source.ip) > 1000",
    category: "Impact",
    description: "Detects volumetric spikes suggesting DDoS."
  },
  {
    id: "rule-046",
    title: "Suspicious Scheduled Task Created",
    language: "EQL",
    mitreId: "T1053.005",
    mitreTechnique: "Scheduled Task",
    snippet: "process where process.command_line : (\"schtasks /create\" or \"Register-ScheduledTask\") and process.command_line : \"\\\\AppData\\\\\"",
    category: "Persistence",
    description: "Detects scheduled tasks created to run from user-writable paths."
  },
  {
    id: "rule-047",
    title: "Suspicious FTP/SCP File Transfer",
    language: "EQL",
    mitreId: "T1048",
    mitreTechnique: "Exfiltration Over Alternative Protocol",
    snippet: "network where (protocol : \"FTP\" or protocol : \"SCP\" or protocol : \"SFTP\") and bytes_sent > 10485760",
    category: "Exfiltration",
    description: "Detects large outbound FTP/SCP transfers."
  },
  {
    id: "rule-048",
    title: "Suspicious USB Device Usage with Large File Copies",
    language: "EQL",
    mitreId: "T1025",
    mitreTechnique: "Data from Removable Media",
    snippet: "process where event.type == \"file_create\" and file.path : \"\\\\RemovableMedia\\\\\" and count() by user.name > 100",
    category: "Exfiltration",
    description: "Detects removable media insertion followed by many file copies."
  },
  {
    id: "rule-049",
    title: "Suspicious DLL Loaded From User Directory",
    language: "EQL",
    mitreId: "T1055",
    mitreTechnique: "Process Injection",
    snippet: "process where event.type == \"image_load\" and file.path : \"\\\\AppData\\\\\" and file.extension == \"dll\"",
    category: "Defense Evasion",
    description: "Detects DLLs loaded from user-writable locations (possible injection)."
  },
  {
    id: "rule-050",
    title: "Suspicious Windows Service Created",
    language: "EQL",
    mitreId: "T1543.003",
    mitreTechnique: "Windows Service",
    snippet: "process where process.command_line : \"sc create\" and process.executable : \"*\" and file.path : \"\\\\AppData\\\\\"",
    category: "Persistence",
    description: "Detects service creation with binary in user-writable path."
  },
  {
    id: "rule-051",
    title: "Potential Zero-Day Exploit - Anomalous Process Crash",
    language: "EQL",
    mitreId: "T1068",
    mitreTechnique: "Exploitation for Privilege Escalation",
    snippet: "process where event.type : (\"process_crash\",\"exception\") and (process.parent.name in (\"services.exe\",\"lsass.exe\") and process.name in (\"cmd.exe\",\"powershell.exe\"))",
    category: "Execution",
    description: "Detects process crashes followed by unexpected privileged child process creation."
  },
  {
    id: "rule-052",
    title: "DGA-like DNS Requests",
    language: "EQL",
    mitreId: "T1568.002",
    mitreTechnique: "Domain Generation Algorithms",
    snippet: "dns where query.name : /[a-z0-9]{12,}\\./ and dns.response_code : \"NXDOMAIN\" and count() by source.ip > 5",
    category: "Command and Control",
    description: "Detects algorithmic domain lookups and many NXDOMAIN responses."
  },
  {
    id: "rule-053",
    title: "XSS Attempt Detected",
    language: "EQL",
    mitreId: "T1190",
    mitreTechnique: "Exploit Public-Facing Application",
    snippet: "http where http.request.body : (\"<script>\",\"onerror=\",\"document.cookie\")",
    category: "Initial Access",
    description: "Detects XSS payloads in HTTP requests."
  },
  {
    id: "rule-054",
    title: "Local Admin Created or SUID Changed",
    language: "EQL",
    mitreId: "T1548",
    mitreTechnique: "Abuse Elevation Control Mechanism",
    snippet: "process where process.command_line : (\"net localgroup administrators\",\"useradd\",\"usermod -aG sudo\") or process.command_line : \"chmod +s\"",
    category: "Privilege Escalation",
    description: "Detects new admin additions or SUID modifications."
  },
  {
    id: "rule-055",
    title: "Suspicious API Key Usage or Token Abuse",
    language: "EQL",
    mitreId: "T1078",
    mitreTechnique: "Valid Accounts",
    snippet: "cloudtrail where user_agent : (\"aws-cli\",\"python-requests\",\"curl\") and source_ip not in (\"<corporate_ip_ranges>\") and event_name in (\"GetObject\",\"ListBuckets\",\"GetSecretValue\")",
    category: "Credential Access",
    description: "Detects API keys/tokens used from new IPs or sudden usage spikes."
  },
  {
    id: "rule-056",
    title: "C2 Beacon - Suspicious Domain TLDs",
    language: "Snort",
    mitreId: "T1071",
    mitreTechnique: "Application Layer Protocol",
    snippet: "alert http any any -> any any (msg:\"C2 Beacon - suspicious domain TLDs\"; flow:established,to_server; content:\".tk\"; http_host; sid:1000001; rev:1; classtype:bad-unknown;)",
    category: "Command and Control",
    description: "Detects HTTP requests to suspicious Top Level Domains often used by C2 beacons."
  },
  {
    id: "rule-057",
    title: "DGA-like Domain Query - High Entropy",
    language: "Snort",
    mitreId: "T1568.002",
    mitreTechnique: "Domain Generation Algorithms",
    snippet: "alert dns any any -> any any (msg:\"DGA-like domain query - high entropy\"; dns_query; content:\"\"; pcre:\"/^[a-z0-9]{12,}/\"; sid:1000002; rev:1; classtype:trojan-activity;)",
    category: "Command and Control",
    description: "Detects DNS queries with high entropy patterns indicative of DGAs."
  },
  {
    id: "rule-058",
    title: "Cloud Storage Upload - Potential Exfiltration",
    language: "Snort",
    mitreId: "T1567",
    mitreTechnique: "Exfiltration Over Web Service",
    snippet: "alert http any any -> any any (msg:\"Cloud Storage Upload - potential exfil to S3/Drive/Dropbox\"; flow:established,to_server; content:\"amazonaws.com\"; http_uri; sid:1000003; rev:1; classtype:policy-violation;)",
    category: "Exfiltration",
    description: "Detects traffic to common cloud storage services that may indicate data exfiltration."
  },
  {
    id: "rule-059",
    title: "SCP/SFTP Large Transfer - Potential Exfiltration",
    language: "Snort",
    mitreId: "T1048",
    mitreTechnique: "Exfiltration Over Alternative Protocol",
    snippet: "alert tcp any any -> any 22 (msg:\"SCP/SFTP large transfer - potential exfil\"; flow:established,to_server; content:\"SSH-\"; sid:1000004; rev:1; classtype:policy-violation;)",
    category: "Exfiltration",
    description: "Detects large SSH/SCP/SFTP data transfers to external destinations."
  },
  {
    id: "rule-060",
    title: "Possible Webshell Upload",
    language: "Snort",
    mitreId: "T1505.003",
    mitreTechnique: "Web Shell",
    snippet: "alert http any any -> any any (msg:\"Possible Webshell Upload to uploads/ path\"; flow:established,to_server; uricontent:\"/wp-content/uploads/\"; sid:1000005; rev:1; classtype:web-application-attack;)",
    category: "Persistence",
    description: "Detects HTTP traffic attempting to upload files to common web directories."
  },
  {
    id: "rule-061",
    title: "WebShell PHP Patterns",
    language: "Yara",
    mitreId: "T1505.003",
    mitreTechnique: "Web Shell",
    snippet: "rule WebShell_PHP_Patterns\n{\n    strings:\n        $php1 = \"<?php\"\n        $cmd = \"system(\"\n        $eval = \"eval(\"\n    condition:\n        $php1 and any of ($cmd,$eval)\n}",
    category: "Persistence",
    description: "Detects common PHP webshell content patterns involving system execution or eval functions."
  },
  {
    id: "rule-062",
    title: "Suspicious DLL Load From Temp",
    language: "Yara",
    mitreId: "T1055",
    mitreTechnique: "Process Injection",
    snippet: "rule DLL_Load_From_Temp\n{\n    strings:\n        $s1 = \"This program cannot be run in DOS mode\" wide ascii\n    condition:\n        $s1 and filesize < 5MB\n}",
    category: "Defense Evasion",
    description: "Detects DLL files located in Temp or AppData directories based on header checks and file size."
  },
  {
    id: "rule-063",
    title: "Suspicious PowerShell Encoded",
    language: "Yara",
    mitreId: "T1059.001",
    mitreTechnique: "PowerShell",
    snippet: "rule Suspicious_PowerShell_Encoded\n{\n    strings:\n        $iex = \"IEX\"\n        $enc_flag = \"-enc\"\n    condition:\n        $iex or $enc_flag\n}",
    category: "Execution",
    description: "Detects base64-looking PowerShell encoded payloads or IEX usage."
  },
  {
    id: "rule-064",
    title: "Suspicious Malware Dropper",
    language: "Yara",
    mitreId: "T1105",
    mitreTechnique: "Ingress Tool Transfer",
    snippet: "rule Suspicious_Malware_Dropper\n{\n    strings:\n        $s1 = \"MZ\"\n        $powershell = \"powershell -enc\"\n    condition:\n        $s1 at 0 or $powershell\n}",
    category: "Initial Access",
    description: "Detects executables in user-writable paths or known dropper patterns using PE headers or PowerShell."
  },
  {
    id: "rule-065",
    title: "Ransomware Suspected File Extensions",
    language: "Yara",
    mitreId: "T1486",
    mitreTechnique: "Data Encrypted for Impact",
    snippet: "rule Ransomware_Suspected_File_Ext\n{\n    strings:\n        $ext1 = \".locked\"\n        $ext2 = \".enc\"\n        $note = \"YOUR_FILES_ARE_ENCRYPTED\"\n    condition:\n        any of ($ext*) or $note\n}",
    category: "Impact",
    description: "Detects files with ransomware-like extensions or ransom notes."
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
    "pdfUrl": "/irplaybooks/Data%20Exfiltration.pdf",
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
    "pdfUrl": "/irplaybooks/Email%20and%20Social%20Engineering.pdf",
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
    "pdfUrl": "/irplaybooks/Lateral%20Movement%20&%20Privilege%20Escalation.pdf",
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
    "pdfUrl": "/irplaybooks/Physical%20Devices%20.pdf",
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
    "pdfUrl": "/irplaybooks/Command-and-Control.pdf",
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
    "pdfUrl": "/irplaybooks/Account%20Compromise.pdf",
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
    "pdfUrl": "/irplaybooks/Network%20Scanning%20.pdf",
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
    "pdfUrl": "/irplaybooks/Web%20Application%20.pdf",
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
    "pdfUrl": "/irplaybooks/Critical%20Vulnerabilities.pdf",
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


export const workflows = [
  {
    id: "wf-001",
    title: "Monitor Security Logs for Failed Login Attempts",
    description: "A 5-node anomaly detection flow that schedules checks, fetches logs, counts failed logins, checks thresholds, and sends Slack alerts.",
    tool: "SOAR",
    pdfUrl: "/workflows/Monitor Security Logs for Failed Login Attempts.docx.pdf",
    jsonPath: "/workflows/json/monitor_security_logs.json.json", 
    screenshot: "/screenshots/Monitor Security Logs for Failed Login Attempts.png",
    steps: [
      { title: "Scheduled Trigger", description: "Cron node triggers the workflow at defined intervals." },
      { title: "Fetch Logs", description: "HTTP Request node retrieves the most recent batch of logs." },
      { title: "Anomaly Logic", description: "JavaScript Code node filters for 'login_failure' events." },
      { title: "Threshold Check & Alert", description: "If failures exceed the threshold, a Slack alert is sent." }
    ]
  },
  {
    id: "wf-002",
    title: "Automated GitHub Scanner for Exposed AWS IAM Keys",
    description: "Automatically scans GitHub for exposed AWS IAM access keys, generates security reports, and sends Slack notifications.",
    tool: "SOAR",
    pdfUrl: "/workflows/Automated GitHub Scanner for Exposed AWS IAM Keys.docx.pdf",
    jsonPath: "/workflows/json/Automated GitHub Scanner for Exposed AWS IAM Keys.json", // Added path
    screenshot: "/screenshots/Automated GitHub Scanner for Exposed AWS IAM Keys.png",
    steps: [
      { title: "AWS User Discovery", description: "Retrieves all AWS users and active access keys." },
      { title: "GitHub Scan", description: "Searches repositories for patterns matching active keys." },
      { title: "Risk Assessment", description: "Aggregates results and checks for compromises." },
      { title: "Actionable Alerting", description: "Sends a Slack notification with 'Disable Key' buttons." }
    ]
  },
  {
    id: "wf-003",
    title: "Endpoint Beaconing C2 Communication",
    description: "Detects and responds to C2 beaconing by validating webhooks, enriching events, and notifying the SOC team.",
    tool: "SOAR",
    pdfUrl: "/workflows/Endpoint_Beaconing_C2_Communication.docx.pdf",
    jsonPath: "/workflows/json/Endpoint Beaconing (C2 Communication).json", // Added path
    screenshot: "/screenshots/Endpoint_Beaconing_C2_Communication.png",
    steps: [
      { title: "Secure Webhook", description: "Entry point protected by Bearer token authentication." },
      { title: "Payload Validation", description: "Validates required fields are present." },
      { title: "Logic & Analysis", description: "Processes event data to determine if beaconing is suspicious." },
      { title: "Response", description: "Returns 200 OK and alerts SOC if malicious." }
    ]
  },
  {
    id: "wf-004",
    title: "Phishing Email Detection",
    description: "Automated phishing detection workflow with webhook trigger and threat intelligence enrichment.",
    tool: "SOAR",
    pdfUrl: "/workflows/Phishing_Email_Detection.docx.pdf",
    jsonPath: "/workflows/json/2-Phishing Email Attack.json", // Added path
    screenshot: "/screenshots/phishing-email-workflow.png",
    steps: [
      { title: "Webhook Trigger", description: "Receives alerts via HTTP POST." },
      { title: "Validation", description: "Validates authenticity and required fields." },
      { title: "Enrichment", description: "Queries PhishTank API for URL reputation." },
      { title: "Alerting", description: "Sends Slack alert if phishing is confirmed." }
    ]
  },
  {
    id: "wf-005",
    title: "Business Email Compromise Detection",
    description: "Webhook-based workflow for detecting and responding to BEC attacks with threat intelligence enrichment.",
    tool: "SOAR",
    pdfUrl: "/workflows/Business_Email_Compromise_BEC.docx.pdf",
    jsonPath: "/workflows/json/Business Email Compromise (BEC).json", // Added path
    screenshot: "/screenshots/bec-workflow.png",
    steps: [
      { title: "Webhook Trigger", description: "Receives BEC alerts from monitoring systems." },
      { title: "Enrichment", description: "Checks VirusTotal, AbuseIPDB, and GeoIP." },
      { title: "Decision Logic", description: "Analyzes enrichment results for suspicion." },
      { title: "Alerting", description: "Sends Slack alert or logs clean event." }
    ]
  },
  {
    id: "wf-006",
    title: "Ransomware Attack Detection",
    description: "Real-time ransomware detection workflow with VirusTotal hash analysis and automated alerting.",
    tool: "SOAR",
    pdfUrl: "/workflows/Ransomware_Attack_Detection.docx.pdf",
    jsonPath: "/workflows/json/1-Ransomware Attack.json", // Added path
    screenshot: "/screenshots/ransomware-workflow.png",
    steps: [
      { title: "Webhook Trigger", description: "Receives alerts with file hash and endpoint." },
      { title: "Validation", description: "Validates webhook secret and payload." },
      { title: "Hash Analysis", description: "Queries VirusTotal API for file hash." },
      { title: "Response", description: "Sends high-priority Slack alert if malicious." }
    ]
  },
  {
    id: "wf-007",
    title: "Website Scam Risk Detector",
    description: "AI-powered multi-agent workflow for evaluating website legitimacy using GPT-4o and SerpAPI.",
    tool: "SOAR",
    pdfUrl: "/workflows/Website Scam Risk Detector.docx.pdf",
    jsonPath: "/workflows/json/Website Scam Risk Detectorr.json", // Added path
    screenshot: "/screenshots/scam-detector-workflow.png",
    steps: [
      { title: "Form Submission", description: "User submits URL to initiate analysis." },
      { title: "Multi-Agent Analysis", description: "Agents analyze domain, signals, pricing, and content." },
      { title: "Aggregation", description: "Findings are collected for the Analyzer." },
      { title: "Risk Assessment", description: "Analyzer scores site and generates report." }
    ]
  },
  {
    id: "wf-008",
    title: "Unusual Login Detection",
    description: "Detects suspicious logins using GreyNoise for IP threat classification, IP-API for geolocation, and UserParser for device anomalies.",
    tool: "SOAR",
    pdfUrl: "/workflows/Unusual Login.docx.pdf",
    jsonPath: "/workflows/json/Unusual VPN Login.json", // Added path
    screenshot: "/screenshots/Unusual Login.png",
    steps: [
      { title: "Login Trigger", description: "Webhook receives login data (User, IP)." },
      { title: "Prioritization", description: "Queries GreyNoise to classify IP threat level." },
      { title: "Enrichment", description: "Adds IP-API geolocation and UserParser device analysis." },
      { title: "Alerting", description: "Sends Slack alerts and email notifications." }
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
    id: "team-004",
    name: "Samar Elkharat",
    role: "Security Engineer",
    bio: "Aspiring Cybersecurity and Electronics Engineering student with hands-on experience in networking, hardware design, and security labs. Skilled in troubleshooting, system design, and tech projects, eager to apply knowledge through real-world challenges.",
    image: "/images/samar.jpg",
    color: "accent",
    linkedin: "https://www.linkedin.com/in/samar-elkharat-45540224a",
    portfolio: "https://mkmkh.my.canva.site/i-m-samar-mohmed"
  },
    {
    id: "team-005",
    name: "Shahd Emad",
    role: "Security Engineer",
    bio: "Aspiring Cybersecurity and Electronics Engineering student with hands-on experience in networking, hardware design, and security labs. Skilled in troubleshooting, system design, and tech projects, eager to apply knowledge through real-world challenges.",
    image: "/images/shahd.jpg",
    color: "accent",
    linkedin: "#",
    portfolio: "#"
  }
];