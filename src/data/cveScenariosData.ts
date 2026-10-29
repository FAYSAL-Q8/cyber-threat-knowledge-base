import { ImportedCVECase } from '../types';

export const SEEDED_CVE_CASES: ImportedCVECase[] = [
  {
    "case_id": "CVE-2026-0257",
    "identity_metadata": {
      "vendor": "Palo Alto Networks",
      "product": "PAN-OS",
      "vulnerability_name": "Palo Alto Networks PAN-OS Authentication Bypass Vulnerability",
      "date_cataloged": "2026-05-29"
    },
    "vector_attributes": {
      "associated_cwes": ["CWE-565"],
      "ransomware_association": false
    },
    "mitre_attck_mapping": {
      "mapped_tactics": ["Initial Access", "Defense Evasion"],
      "mapped_techniques": ["T1190 - Exploit Public-Facing Application", "T1556 - Modify Authentication Process"]
    },
    "chronological_attack_scenario": {
      "summary_narrative": "Palo Alto Networks PAN-OS contains an authentication bypass vulnerability that allows attackers to bypass security restrictions and establish an unauthorized VPN connection.",
      "execution_flow": [
        "Step 1: Attacker targets open service ports handling session management or authentication handshakes.",
        "Step 2: Attacker injects a specially crafted parameter, malformed token, or engineered header missing standard validation.",
        "Step 3: The logical validation check on the host engine fails, treating the request as authenticated.",
        "Step 4: Unauthorized access or administrative system execution boundaries are bypassed completely."
      ]
    },
    "indicator_signatures": {
      "remediation_action": "Apply mitigations per vendor instructions...",
      "detection_heuristics": [
        "Flag rapid multi-session state registration ignoring standard authorization sequences.",
        "Audit access logs for requests targeting authentication routing with atypical header configurations."
      ]
    },
    "data_provenance": {
      "source_references": [
        "https://security.paloaltonetworks.com/CVE-2026-0257",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-0257"
      ]
    }
  },
  {
    "case_id": "CVE-2026-48027",
    "identity_metadata": {
      "vendor": "Nx",
      "product": "Nx Console",
      "vulnerability_name": "Nx Console Embedded Malicious Code Vulnerability",
      "date_cataloged": "2026-05-27"
    },
    "vector_attributes": {
      "associated_cwes": [
        "CWE-506"
      ],
      "ransomware_association": true
    },
    "mitre_attck_mapping": {
      "mapped_tactics": [
        "Initial Access",
        "Execution",
        "Credential Access"
      ],
      "mapped_techniques": [
        "T1195.001 - Supply Chain Compromise: Compromise Software Dependencies",
        "T1059 - Command and Scripting Interpreter"
      ]
    },
    "chronological_attack_scenario": {
      "summary_narrative": "Nx Console contains an embedded malicious code vulnerability that allowed a malicious version of Nx Console to be published. The compromised extension fetched an obfuscated payload that could harvested credentials from multiple sources on disk and in memory.",
      "execution_flow": [
        "Step 1: Threat actors compromise or fake developer build streams/repositories.",
        "Step 2: Poisoned or altered asset versions containing malicious code blocks are uploaded to trusted hubs.",
        "Step 3: Host applications pull and execute the component natively through automated scripts or updates.",
        "Step 4: Silent background routines exfiltrate host credentials, keys, or environmental arrays to a C2 asset."
      ]
    },
    "indicator_signatures": {
      "remediation_action": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
      "detection_heuristics": [
        "Scan dependencies for anomalous cryptographic version deviations or unpinned tracking updates.",
        "Monitor sudden outbound network connections initializing straight from internal IDE or build process bounds."
      ]
    },
    "data_provenance": {
      "source_references": [
        "https://github.com/nrwl/nx-console/security/advisories/GHSA-c9j4-9m59-847w",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-48027"
      ]
    }
  },
  {
    "case_id": "CVE-2026-45321",
    "identity_metadata": {
      "vendor": "TanStack",
      "product": "TanStack",
      "vulnerability_name": "TanStack Unspecified Vulnerability",
      "date_cataloged": "2026-05-27"
    },
    "vector_attributes": {
      "associated_cwes": [],
      "ransomware_association": true
    },
    "mitre_attck_mapping": {
      "mapped_tactics": [
        "Initial Access",
        "Execution",
        "Credential Access"
      ],
      "mapped_techniques": [
        "T1195.001 - Supply Chain Compromise: Compromise Software Dependencies",
        "T1059 - Command and Scripting Interpreter"
      ]
    },
    "chronological_attack_scenario": {
      "summary_narrative": "TanStack contains an unspecified vulnerability that allowed malicious versions of the product to be published to the npm registry to publish credential-stealing malware under a trusted identity.",
      "execution_flow": [
        "Step 1: Threat actors compromise or fake developer build streams/repositories.",
        "Step 2: Poisoned or altered asset versions containing malicious code blocks are uploaded to trusted hubs.",
        "Step 3: Host applications pull and execute the component natively through automated scripts or updates.",
        "Step 4: Silent background routines exfiltrate host credentials, keys, or environmental arrays to a C2 asset."
      ]
    },
    "indicator_signatures": {
      "remediation_action": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
      "detection_heuristics": [
        "Scan dependencies for anomalous cryptographic version deviations or unpinned tracking updates.",
        "Monitor sudden outbound network connections initializing straight from internal IDE or build process bounds."
      ]
    },
    "data_provenance": {
      "source_references": [
        "https://github.com/TanStack/router/security/advisories/GHSA-g7cv-rxg3-hmpx",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-45321"
      ]
    }
  },
  {
    "case_id": "CVE-2026-8398",
    "identity_metadata": {
      "vendor": "Daemon",
      "product": "Daemon Tools Lite",
      "vulnerability_name": "Daemon Tools Lite Embedded Malicious Code Vulnerability",
      "date_cataloged": "2026-05-27"
    },
    "vector_attributes": {
      "associated_cwes": [
        "CWE-506"
      ],
      "ransomware_association": false
    },
    "mitre_attck_mapping": {
      "mapped_tactics": [
        "Initial Access",
        "Execution",
        "Credential Access"
      ],
      "mapped_techniques": [
        "T1195.001 - Supply Chain Compromise: Compromise Software Dependencies",
        "T1059 - Command and Scripting Interpreter"
      ]
    },
    "chronological_attack_scenario": {
      "summary_narrative": "Daemon Tools contains an unspecified vulnerability that has a high impact on confidentiality, integrity, and availability.",
      "execution_flow": [
        "Step 1: Threat actors compromise or fake developer build streams/repositories.",
        "Step 2: Poisoned or altered asset versions containing malicious code blocks are uploaded to trusted hubs.",
        "Step 3: Host applications pull and execute the component natively through automated scripts or updates.",
        "Step 4: Silent background routines exfiltrate host credentials, keys, or environmental arrays to a C2 asset."
      ]
    },
    "indicator_signatures": {
      "remediation_action": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
      "detection_heuristics": [
        "Scan dependencies for anomalous cryptographic version deviations or unpinned tracking updates.",
        "Monitor sudden outbound network connections initializing straight from internal IDE or build process bounds."
      ]
    },
    "data_provenance": {
      "source_references": [
        "https://blog.daemon-tools.cc/post/security-incident",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-8398"
      ]
    }
  },
  {
    "case_id": "CVE-2026-48172",
    "identity_metadata": {
      "vendor": "LiteSpeed",
      "product": "cPanel Plugin",
      "vulnerability_name": "LiteSpeed cPanel Plugin Privilege Escalation Vulnerability",
      "date_cataloged": "2026-05-26"
    },
    "vector_attributes": {
      "associated_cwes": [
        "CWE-266"
      ],
      "ransomware_association": false
    },
    "mitre_attck_mapping": {
      "mapped_tactics": [
        "Initial Access"
      ],
      "mapped_techniques": [
        "T1190 - Exploit Public-Facing Application"
      ]
    },
    "chronological_attack_scenario": {
      "summary_narrative": "LiteSpeed cPanel Plugin contains privilege escalation vulnerability that is exposed via the user-end cPanel plugin, which can be abused by any cPanel user account to execute arbitrary scripts with root privileges.",
      "execution_flow": [
        "Step 1: Attacker identifies target software running a specific vulnerable configuration footprint.",
        "Step 2: Attacker sends an engineered payload designed to take advantage of specific processing boundaries.",
        "Step 3: System experiences state corruption, memory leak, or operational control transfer to the input vector."
      ]
    },
    "indicator_signatures": {
      "remediation_action": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
      "detection_heuristics": [
        "Verify installation baseline inventories against known public vulnerability maps.",
        "Flag atypical request sizes or malformed structure strings hitting exposed services."
      ]
    },
    "data_provenance": {
      "source_references": [
        "https://blog.litespeedtech.com/2026/05/21/security-update-for-litespeed-cpanel-plugin/",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-48172"
      ]
    }
  },
  {
    "case_id": "CVE-2026-9082",
    "identity_metadata": {
      "vendor": "Drupal",
      "product": "Core",
      "vulnerability_name": "Drupal Core SQL Injection Vulnerability",
      "date_cataloged": "2026-05-22"
    },
    "vector_attributes": {
      "associated_cwes": [
        "CWE-89"
      ],
      "ransomware_association": false
    },
    "mitre_attck_mapping": {
      "mapped_tactics": [
        "Initial Access",
        "Execution"
      ],
      "mapped_techniques": [
        "T1190 - Exploit Public-Facing Application",
        "T1059 - Command and Scripting Interpreter"
      ]
    },
    "chronological_attack_scenario": {
      "summary_narrative": "Drupal Core contains a SQL injection vulnerability that could allow for privilege escalation and remote code execution via specially crafted requests sent with the database abstraction API.",
      "execution_flow": [
        "Step 1: Attacker locates unvalidated input entry windows mapping directly to internal data parsing blocks.",
        "Step 2: Attacker crafts strings containing escape operators and syntax control instructions.",
        "Step 3: The interpreting engine treats the payload data as logical processing instructions, executing arbitrary actions.",
        "Step 4: Attacker reads restricted memory space, drops secondary system payloads, or executes operational controls."
      ]
    },
    "indicator_signatures": {
      "remediation_action": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
      "detection_heuristics": [
        "Monitor network queries containing raw syntactic parameters (e.g., UNION, SELECT, OR 1=1).",
        "Audit application error logs tracking runtime query processing failures."
      ]
    },
    "data_provenance": {
      "source_references": [
        "https://www.drupal.org/sa-core-2026-004",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-9082"
      ]
    }
  },
  {
    "case_id": "CVE-2025-34291",
    "identity_metadata": {
      "vendor": "Langflow",
      "product": "Langflow",
      "vulnerability_name": "Langflow Origin Validation Error Vulnerability",
      "date_cataloged": "2026-05-21"
    },
    "vector_attributes": {
      "associated_cwes": [
        "CWE-346"
      ],
      "ransomware_association": false
    },
    "mitre_attck_mapping": {
      "mapped_tactics": [
        "Initial Access",
        "Execution",
        "Credential Access"
      ],
      "mapped_techniques": [
        "T1195.001 - Supply Chain Compromise: Compromise Software Dependencies",
        "T1059 - Command and Scripting Interpreter"
      ]
    },
    "chronological_attack_scenario": {
      "summary_narrative": "Langflow contains an origin validation error vulnerability in which an overly permissive CORS configuration combined with a refresh token cookie configured as SameSite=None allows a malicious webpage to perform cross-origin requests that include credentials and successfully call the refresh endpoint. This could allow the attacker to execute arbitrary code and achieve full system compromise via obtained tokens that permit access to authenticated endpoints.",
      "execution_flow": [
        "Step 1: Threat actors compromise or fake developer build streams/repositories.",
        "Step 2: Poisoned or altered asset versions containing malicious code blocks are uploaded to trusted hubs.",
        "Step 3: Host applications pull and execute the component natively through automated scripts or updates.",
        "Step 4: Silent background routines exfiltrate host credentials, keys, or environmental arrays to a C2 asset."
      ]
    },
    "indicator_signatures": {
      "remediation_action": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
      "detection_heuristics": [
        "Scan dependencies for anomalous cryptographic version deviations or unpinned tracking updates.",
        "Monitor sudden outbound network connections initializing straight from internal IDE or build process bounds."
      ]
    },
    "data_provenance": {
      "source_references": [
        "https://github.com/langflow-ai/langflow",
        "https://github.com/langflow-ai/langflow/releases/tag/v1.9.3",
        "https://github.com/langflow-ai/langflow/issues/11465#event-25774545848",
        "https://nvd.nist.gov/vuln/detail/CVE-2025-34291"
      ]
    }
  },
  {
    "case_id": "CVE-2026-34926",
    "identity_metadata": {
      "vendor": "Trend Micro",
      "product": "Apex One",
      "vulnerability_name": "Trend Micro Apex One (On-Premise) Directory Traversal Vulnerability",
      "date_cataloged": "2026-05-21"
    },
    "vector_attributes": {
      "associated_cwes": [
        "CWE-23"
      ],
      "ransomware_association": false
    },
    "mitre_attck_mapping": {
      "mapped_tactics": [
        "Initial Access",
        "Execution",
        "Credential Access"
      ],
      "mapped_techniques": [
        "T1195.001 - Supply Chain Compromise: Compromise Software Dependencies",
        "T1059 - Command and Scripting Interpreter"
      ]
    },
    "chronological_attack_scenario": {
      "summary_narrative": "Trend Micro Apex One (on-premise) contains a directory traversal vulnerability that could allow a pre-authenticated local attacker to modify a key table on the server to inject malicious code to deploy to agents on affected installations.",
      "execution_flow": [
        "Step 1: Threat actors compromise or fake developer build streams/repositories.",
        "Step 2: Poisoned or altered asset versions containing malicious code blocks are uploaded to trusted hubs.",
        "Step 3: Host applications pull and execute the component natively through automated scripts or updates.",
        "Step 4: Silent background routines exfiltrate host credentials, keys, or environmental arrays to a C2 asset."
      ]
    },
    "indicator_signatures": {
      "remediation_action": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
      "detection_heuristics": [
        "Scan dependencies for anomalous cryptographic version deviations or unpinned tracking updates.",
        "Monitor sudden outbound network connections initializing straight from internal IDE or build process bounds."
      ]
    },
    "data_provenance": {
      "source_references": [
        "https://success.trendmicro.com/en-US/solution/KA-0023430",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-34926"
      ]
    }
  },
  {
    "case_id": "CVE-2008-4250",
    "identity_metadata": {
      "vendor": "Microsoft",
      "product": "Windows",
      "vulnerability_name": "Microsoft Windows Buffer Overflow Vulnerability",
      "date_cataloged": "2026-05-20"
    },
    "vector_attributes": {
      "associated_cwes": [
        "CWE-94"
      ],
      "ransomware_association": false
    },
    "mitre_attck_mapping": {
      "mapped_tactics": [
        "Execution",
        "Lateral Movement"
      ],
      "mapped_techniques": [
        "T1210 - Exploitation of Remote Services",
        "T1059 - Command and Scripting Interpreter"
      ]
    },
    "chronological_attack_scenario": {
      "summary_narrative": "Microsoft Windows contains a buffer overflow vulnerability in the Windows Server Service that allows remote attackers to execute arbitrary code via a crafted RPC request that triggers an overflow during path canonicalization.",
      "execution_flow": [
        "Step 1: Attacker targets exposed functions processing incoming untrusted object data or system payloads.",
        "Step 2: A request containing serialized malicious objects or arbitrary script blocks is directed at the engine.",
        "Step 3: Poor memory initialization or lack of sandboxing lets the system run the input under its execution context.",
        "Step 4: Attacker drops an interactive shell instance or command control binary onto the target asset."
      ]
    },
    "indicator_signatures": {
      "remediation_action": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
      "detection_heuristics": [
        "Trace system sub-process spawning chains originating directly from web server demons or interpreter engines.",
        "Log arbitrary binary writing actions to volatile system runtime directories."
      ]
    },
    "data_provenance": {
      "source_references": [
        "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067",
        "https://nvd.nist.gov/vuln/detail/CVE-2008-4250"
      ]
    }
  },
  {
    "case_id": "CVE-2026-20182",
    "identity_metadata": {
      "vendor": "Cisco",
      "product": "Catalyst SD-WAN",
      "vulnerability_name": "Cisco Catalyst SD-WAN Controller Authentication Bypass Vulnerability",
      "date_cataloged": "2026-05-14"
    },
    "vector_attributes": {
      "associated_cwes": [
        "CWE-287"
      ],
      "ransomware_association": false
    },
    "mitre_attck_mapping": {
      "mapped_tactics": [
        "Initial Access",
        "Defense Evasion"
      ],
      "mapped_techniques": [
        "T1190 - Exploit Public-Facing Application",
        "T1556 - Modify Authentication Process"
      ]
    },
    "chronological_attack_scenario": {
      "summary_narrative": "Cisco Catalyst SD-WAN Controller & Manager contain an authentication bypass vulnerability that allows an unauthenticated, remote attacker to bypass authentication and obtain administrative privileges on an affected system.",
      "execution_flow": [
        "Step 1: Attacker targets open service ports handling session management or authentication handshakes.",
        "Step 2: Attacker injects a specially crafted parameter, malformed token, or engineered header missing standard validation.",
        "Step 3: The logical validation check on the host engine fails, treating the request as authenticated.",
        "Step 4: Unauthorized access or administrative system execution boundaries are bypassed completely."
      ]
    },
    "indicator_signatures": {
      "remediation_action": "Please adhere to CISA’s guidelines to assess exposure and mitigate risks associated with Cisco SD-WAN devices as outlined in CISA’s Emergency Directive 26-03 and hunt queries.",
      "detection_heuristics": [
        "Flag rapid multi-session state registration ignoring standard authorization sequences.",
        "Audit access logs for requests targeting authentication routing with atypical header configurations."
      ]
    },
    "data_provenance": {
      "source_references": [
        "https://www.cisa.gov/news-events/directives/ed-26-03-mitigate-vulnerabilities-cisco-sd-wan-systems",
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa2-v69WY2SW"
      ]
    }
  },
  {
    "case_id": "CVE-2024-1708",
    "identity_metadata": {
      "vendor": "ConnectWise",
      "product": "ScreenConnect",
      "vulnerability_name": "ConnectWise ScreenConnect Path Traversal Vulnerability",
      "date_cataloged": "2026-04-28"
    },
    "vector_attributes": {
      "associated_cwes": [
        "CWE-22"
      ],
      "ransomware_association": true
    },
    "mitre_attck_mapping": {
      "mapped_tactics": [
        "Initial Access"
      ],
      "mapped_techniques": [
        "T1190 - Exploit Public-Facing Application"
      ]
    },
    "chronological_attack_scenario": {
      "summary_narrative": "ConnectWise ScreenConnect contains a path traversal vulnerability which could allow an attacker to execute remote code or directly impact confidential data and critical systems.",
      "execution_flow": [
        "Step 1: Attacker identifies target software running a specific vulnerable configuration footprint.",
        "Step 2: Attacker sends an engineered payload designed to take advantage of specific processing boundaries.",
        "Step 3: System experiences state corruption, memory leak, or operational control transfer to the input vector."
      ]
    },
    "indicator_signatures": {
      "remediation_action": "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
      "detection_heuristics": [
        "Verify installation baseline inventories against known public vulnerability maps.",
        "Flag atypical request sizes or malformed structure strings hitting exposed services."
      ]
    },
    "data_provenance": {
      "source_references": [
        "https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8",
        "https://nvd.nist.gov/vuln/detail/CVE-2024-1708"
      ]
    }
  }
];
