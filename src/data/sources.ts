import { SecuritySource, CVEFeedItem } from '../types';

export const RELIABLE_SOURCES: SecuritySource[] = [
  {
    id: 'nist-nvd',
    name: 'NIST National Vulnerability Database (NVD)',
    url: 'https://nvd.nist.gov/',
    data_access: 'REST API (JSON v2.0 REST endpoints, search queries)',
    provides: 'Comprehensive official CVE entries, CVSS severity metrics, CWE structural weaknesses, and system CPE alignments.',
    reliability: 'Extremely High',
    update_frequency: 'Refreshed daily as new vulnerabilities are cataloged.'
  },
  {
    id: 'cisa-kev',
    name: 'CISA Known Exploited Vulnerabilities (KEV)',
    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    data_access: 'Schedules JSON / CSV / XML direct link feed integrations',
    provides: 'Curated list of critical vulnerabilities actively being exploited in the wild with required remediation deadlines.',
    reliability: 'Extremely High',
    update_frequency: 'Updated in real-time as CISA identifies public thread actors exploiting vectors.'
  },
  {
    id: 'mitre-attack',
    name: 'MITRE ATT&CK Matrix',
    url: 'https://attack.mitre.org/',
    data_access: 'STIX / TAXII API endpoints or structured JSON documents',
    provides: 'Global knowledge base of adversary tactics, techniques, and procedures (TTPs) based on real-world observations.',
    reliability: 'Extremely High',
    update_frequency: 'Released in structured major versions quarterly.'
  },
  {
    id: 'github-advisory',
    name: 'GitHub Advisory Database',
    url: 'https://github.com/advisories',
    data_access: 'GraphQL API endpoint, repository security advisories',
    provides: 'Curated software package vulnerabilities, dependency graphs security reviews, and secure patch versions for packages.',
    reliability: 'High',
    update_frequency: 'Continuous community updates, real-time imports from NVD + GitHub reviews.'
  }
];

export const MOCK_CVE_FEED: CVEFeedItem[] = [
  {
    id: 'CVE-2024-3094',
    title: 'XZ Utils Backdoor RCE Vulnerability',
    severity: 'CRITICAL',
    cwe: 'CWE-506 (Embedded Malicious Code)',
    published_date: '2024-03-29',
    source: 'CISA KEV & NIST NVD',
    description: 'Malicious code was discovered in the upstream tarballs of xz-utils. The backdoor intercepts SSH connection keys on Linux servers, enabling unauthenticated remote code execution.'
  },
  {
    id: 'CVE-2023-46604',
    title: 'Apache ActiveMQ Remote Code Execution',
    severity: 'CRITICAL',
    cwe: 'CWE-502 (Insecure Deserialization)',
    published_date: '2023-10-27',
    source: 'CISA KEV & NIST NVD',
    description: 'The OpenWire protocol marshaling engine enables remote attackers to run arbitrary shell commands on servers by providing custom class entries in serialized streams.'
  },
  {
    id: 'CVE-2024-21626',
    title: 'runc Container Breakout / Escape',
    severity: 'CRITICAL',
    cwe: 'CWE-22 (Path Traversal)',
    published_date: '2024-01-31',
    source: 'GitHub Advisory & NIST',
    description: 'A file descriptor leak inside runc lets attackers escape Docker container namespace boundaries, securing write-access on host-machine file systems.'
  },
  {
    id: 'CVE-2023-4863',
    title: 'libwebp Heap Buffer Overflow Out-of-Bounds Write',
    severity: 'CRITICAL',
    cwe: 'CWE-787 (Out-of-bounds Write)',
    published_date: '2023-09-12',
    source: 'CISA KEV & GitHub Advisory',
    description: 'A heap buffer overflow in the WebP image decoder library affects major web browsers. Attackers can trigger this via malicious WebP images to execute arbitrary payloads.'
  },
  {
    id: 'CVE-2024-4040',
    title: 'CrushFTP VFS Sandbox Bypass Path Traversal',
    severity: 'CRITICAL',
    cwe: 'CWE-22 (Path Traversal)',
    published_date: '2024-04-19',
    source: 'CISA KEV',
    description: 'A Path Traversal vulnerability inside CrushFTP lets unauthenticated attackers escape the VFS sandbox structure and download administrative passwords or server configuration files.'
  },
  {
    id: 'CVE-2023-3824',
    title: 'PHP Buffer Overflow and RCE in XML Parsing',
    severity: 'CRITICAL',
    cwe: 'CWE-122 (Heap-based Buffer Overflow)',
    published_date: '2023-08-04',
    source: 'NIST NVD',
    description: 'A heap buffer overflow inside the XML structure loader leads to remote code execution during XML metadata conversions in web apps running specific older PHP versions.'
  },
  {
    id: 'CVE-2024-1082',
    title: 'Kubernetes API Server IDOR Privilege Escalation',
    severity: 'HIGH',
    cwe: 'CWE-639 (Insecure Direct Object Reference)',
    published_date: '2024-02-15',
    source: 'MITRE ATT&CK & GitHub Advisory',
    description: 'Flaw in Kubernetes API server permissions checking. Regular cluster users can submit path manipulations to inspect private secret assets across alternative namespaces.'
  }
];
