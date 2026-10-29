export interface Vulnerability {
  id: string;
  category: 'web-api' | 'server-os' | 'cloud-security';
  name: string;
  cwe_id: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  technical_explanation: string;
  environment: string;
  vulnerable_code_snippet: string;
  vulnerable_code_lang: string;
  payload_example: string;
  remediation: string;
  remediation_code_snippet: string;
  remediation_code_lang: string;
  exploit_steps: string[];
  payloads?: {
    title: string;
    type: string;
    payload: string;
    description: string;
  }[];
  mitre_attack_tactic?: string;
  mitre_attack_technique?: string;
}

export interface SecuritySource {
  id: string;
  name: string;
  url: string;
  data_access: string;
  provides: string;
  reliability: 'Extremely High' | 'High';
  update_frequency: string;
}

export interface TargetWebsite {
  id: string;
  name: string;
  group: string;
  url: string;
  inputs: string[]; // e.g. ["X-Forwarded-For Header", "Query term param"]
  outcomes: string[]; // e.g. ["Blind SQL leak triggered", "302 Redirect bypass"]
  vulnerabilitiesFound: string[]; // matching Vulnerability.id values
  notes: string;
  updatedAt: string;
}

export interface ReusableProfile {
  id: string;
  name: string;
  inputs: string[];
  outcomes: string[];
}

export interface CVEFeedItem {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cwe: string;
  published_date: string;
  source: string;
  description: string;
}

export interface RealWorldCase {
  id: string;
  title: string;
  category: string;
  targetEnvironmentType: string; // e.g. "Cloud Kubernetes API Proxy", "Enterprise SAP SOAP Gateway"
  attackSurface: 'API Endpoint' | 'HTTP Headers' | 'File Upload Router' | 'JSON Request Body' | 'URL Parameter';
  vulnerabilityIdRef: string; // matches Vulnerability id
  
  // High-value automation parameters
  automationSnippet: {
    requestPath: string; // e.g. "/api/v1/proxy?url="
    httpMethod: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
    payloadHeaders: { [key: string]: string };
    payloadBodyTemplate: string; // Dynamic JSON structure template with placeholders
    triggerPayload: string; // The raw exploit payload
  };

  // Automated Response Verification Rule
  verificationPattern: {
    expectedHttpStatusCode: number;
    matchRegexPattern: string; // e.g. "aws_access_key_id|root:x:"
    successIndicatorDescription: string;
  };

  caseSynopsis: string; // detailed real-world backstory, logs
  mitigationTested: string;
  insightNotesForAutomationEngine: string; // patterns for future automatic tools
}

export interface ImportedCVECase {
  case_id: string;
  identity_metadata: {
    vendor: string;
    product: string;
    vulnerability_name: string;
    date_cataloged: string;
  };
  vector_attributes: {
    associated_cwes: string[];
    ransomware_association: boolean;
  };
  mitre_attck_mapping: {
    mapped_tactics: string[];
    mapped_techniques: string[];
  };
  chronological_attack_scenario: {
    summary_narrative: string;
    execution_flow: string[];
  };
  indicator_signatures: {
    remediation_action: string;
    detection_heuristics: string[];
  };
  data_provenance: {
    source_references: string[];
  };
}


