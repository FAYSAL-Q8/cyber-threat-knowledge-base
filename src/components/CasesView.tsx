import React, { useState, useMemo } from 'react';
import { 
  FileText, Shield, Key, AlertTriangle, Cpu, Terminal, Sparkles, CheckCircle2,
  Bookmark, Award, Plus, Trash2, Edit3, Save, Search, RefreshCw, Layers, FileCode, Check, Send, X, Upload
} from 'lucide-react';
import { Vulnerability, RealWorldCase, ImportedCVECase } from '../types';
import { SEEDED_CVE_CASES } from '../data/cveScenariosData';

interface CasesViewProps {
  vulnerabilitiesList: Vulnerability[];
}

export const mapCVECaseToRealWorldCase = (cve: ImportedCVECase): RealWorldCase => {
  const primaryCwe = cve.vector_attributes.associated_cwes[0] || 'CWE-Unknown';
  return {
    id: cve.case_id,
    title: `${cve.case_id}: ${cve.identity_metadata.vulnerability_name}`,
    category: cve.identity_metadata.vendor,
    targetEnvironmentType: `${cve.identity_metadata.product} (${cve.identity_metadata.vendor})`,
    attackSurface: cve.identity_metadata.vulnerability_name.toLowerCase().includes('header') 
      ? 'HTTP Headers' 
      : cve.identity_metadata.vulnerability_name.toLowerCase().includes('upload') 
        ? 'File Upload Router' 
        : cve.identity_metadata.vulnerability_name.toLowerCase().includes('sql') 
          ? 'JSON Request Body' 
          : 'API Endpoint',
    vulnerabilityIdRef: primaryCwe.toLowerCase(),
    automationSnippet: {
      requestPath: cve.data_provenance.source_references[0] || `/api/v1/cve/${cve.case_id}`,
      httpMethod: cve.identity_metadata.vulnerability_name.toLowerCase().includes('bypass') ? 'POST' : 'GET',
      payloadHeaders: {
        'Accept': 'application/json',
        'X-CVE-Reference': cve.case_id
      },
      payloadBodyTemplate: JSON.stringify({
        summary: cve.chronological_attack_scenario.summary_narrative,
        ransomwareRisk: cve.vector_attributes.ransomware_association
      }, null, 2),
      triggerPayload: cve.chronological_attack_scenario.execution_flow.join('\n')
    },
    verificationPattern: {
      expectedHttpStatusCode: 200,
      matchRegexPattern: cve.indicator_signatures.detection_heuristics[0] || 'success',
      successIndicatorDescription: cve.indicator_signatures.detection_heuristics.join(' | ')
    },
    caseSynopsis: `${cve.chronological_attack_scenario.summary_narrative}\n\nExecution Flow:\n${cve.chronological_attack_scenario.execution_flow.map(step => `- ${step}`).join('\n')}`,
    mitigationTested: cve.indicator_signatures.remediation_action,
    insightNotesForAutomationEngine: `MITRE Tactics: ${cve.mitre_attck_mapping.mapped_tactics.join(', ')}\nMITRE Techniques: ${cve.mitre_attck_mapping.mapped_techniques.join(', ')}\nAssociated CWEs: ${cve.vector_attributes.associated_cwes.join(', ')}`
  };
};

// Highly comprehensive seeded real-world scenario cases
const INITIAL_CASES: RealWorldCase[] = [
  {
    id: 'case_k8s_ssrf_token_leak',
    title: 'Kubernetes Internal VPC Credential Extraction',
    category: 'Cloud Infrastructure SSRF',
    targetEnvironmentType: 'AWS EKS Cluster Metadata v1 Service Instance',
    attackSurface: 'URL Parameter',
    vulnerabilityIdRef: 'ssrf',
    automationSnippet: {
      requestPath: '/api/v1/document-compiler/fetch?source_uri=',
      httpMethod: 'GET',
      payloadHeaders: {
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json'
      },
      payloadBodyTemplate: '{"import_job_name": "worker_run_#ID#"}',
      triggerPayload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/default-node-role'
    },
    verificationPattern: {
      expectedHttpStatusCode: 200,
      matchRegexPattern: '"AccessKeyId"\\s*:\\s*"ASIA[A-Z0-9]+"',
      successIndicatorDescription: 'Detection of temporary AWS Access Credentials matching standard IAM EKS Service roles.'
    },
    caseSynopsis: 'An enterprise PDF generation cluster accepted unvalidated URL vectors from external user requests. Rather than routing to static assets, the backend resolved the link-local routing scope 169.254.169.254 to pull node credentials. Exploit allowed lateral compromise of secondary S3 buckets.',
    mitigationTested: 'Configured instance metadata service metadata options to require IMDSv2 token validation, and implemented host-based iptables restrictions denying application pods access to metadata IP scopes.',
    insightNotesForAutomationEngine: 'Attack pattern indicates high effectiveness when target URL query handlers do not resolve canonical DNS mappings prior to fetching. Automated tools must test link-local aliases (e.g. 2852039166 in decimal) to check firewall filter coverage.'
  },
  {
    id: 'case_bola_gateway_invoice_harvest',
    title: 'Bulk Invoice Harvesting on Billing Gateway',
    category: 'Broken Object Level Authorization',
    targetEnvironmentType: 'Fintech Microservices Invoice Dispatcher',
    attackSurface: 'API Endpoint',
    vulnerabilityIdRef: 'bola',
    automationSnippet: {
      requestPath: '/api/v2/invoices/inv_#TARGET_ID#',
      httpMethod: 'GET',
      payloadHeaders: {
        'Authorization': 'Bearer <REPLACE_USER_JWT_TOKEN>',
        'X-Tenant-Identifier': 'tenant_6542'
      },
      payloadBodyTemplate: '{}',
      triggerPayload: '/api/v2/invoices/inv_9981023'
    },
    verificationPattern: {
      expectedHttpStatusCode: 200,
      matchRegexPattern: '"invoice_amount"|"client_vat_id"',
      successIndicatorDescription: 'Vibrant text responses reflecting invoice payloads belonging to cross-tenant users without error flags.'
    },
    caseSynopsis: 'An authorized client logged into the billing engine easily requested invoices belonging to competitive corporations by modifying sequential uuid arrays and id markers. The backend authenticated the session token but failed to map current tenant authorization schemas onto the resource keys queried.',
    mitigationTested: 'Enforced fine-grained query access filters that bind the authenticated database session userId directly on the raw Postgres lookup constraint criteria.',
    insightNotesForAutomationEngine: 'BOLA attacks demonstrate a high success rate on REST APIs utilizing linear integer indexing values. Automation scripts must record standard object structure identifiers, compute target increments, and fire concurrent test sets to identify access breaches.'
  },
  {
    id: 'case_sqli_authorization_bypass',
    title: 'Pre-Authentication SQLite Superuser Bypass',
    category: 'Database Input Command Injection',
    targetEnvironmentType: 'Nginx-cached Node Express Authentication Router',
    attackSurface: 'JSON Request Body',
    vulnerabilityIdRef: 'sqli',
    automationSnippet: {
      requestPath: '/api/auth/register-gateway',
      httpMethod: 'POST',
      payloadHeaders: {
        'Content-Type': 'application/json',
        'X-Forwarded-For': '127.0.0.1'
      },
      payloadBodyTemplate: '{"user_email": "admin@local.corp", "security_pass": "#TRIGGER_PAYLOAD#"}',
      triggerPayload: "' OR 1=1; --"
    },
    verificationPattern: {
      expectedHttpStatusCode: 200,
      matchRegexPattern: '"auth_session_cookie"|"privilege_level"\\s*:\\s*"superuser"',
      successIndicatorDescription: 'Server issues a valid administrative JWT cookie token bypass, skipping standard bcrypt evaluation entirely.'
    },
    caseSynopsis: 'A public legacy enrollment route utilized direct user input query concatenation inside SQL transactions causing blind authentication bypass. Penetration tests demonstrated that arbitrary login profiles with superuser context could be instantiated cleanly.',
    mitigationTested: 'Replaced legacy raw queries with pre-compiled parameterized queries using a modern Knex.js driver wrapper model on SQL transaction sequences.',
    insightNotesForAutomationEngine: 'Automation tools must monitor authentication cookies and token structures. When a SQL sequence bypass triggers, the response size generally shifts dramatically because the server appends several records. Test of boolean true condition and false condition sizes proves bypass logic.'
  },
  {
    id: 'case_lfi_system_etc_passwd',
    title: 'Local File Inclusion on Core Log Reader',
    category: 'Kernel IO Directory Traversal',
    targetEnvironmentType: 'Alpine Linux Docker Node.js Log Daemon',
    attackSurface: 'HTTP Headers',
    vulnerabilityIdRef: 'lfi',
    automationSnippet: {
      requestPath: '/api/telemetry/log-stream',
      httpMethod: 'GET',
      payloadHeaders: {
        'X-Log-File-Source': '../../../../../../etc/passwd\u0000',
        'User-Agent': 'Security-Patrol-Scanner'
      },
      payloadBodyTemplate: '{}',
      triggerPayload: '../../../../etc/passwd'
    },
    verificationPattern: {
      expectedHttpStatusCode: 200,
      matchRegexPattern: 'root:x:0:0:',
      successIndicatorDescription: 'Successful extraction of system wide user mapping database entries, proving file-system read capability.'
    },
    caseSynopsis: 'Logging components used to display internal network configurations received dynamic target file variables, opening vulnerability paths to extract active operating system accounts. Attackers verified bypass capabilities across container barriers.',
    mitigationTested: 'Enforced canonical path resolution, replacing arbitrary string handling parameters with predefined key options mappings checking system limits strictly.',
    insightNotesForAutomationEngine: 'Automated test logic of path-traversal must systematically prepend nested recursive depth parent nodes ("/../../") combined with URL-encoded parameters (%2e%2e%2f) to trigger defensive parsing anomalies.'
  }
];

export default function CasesView({ vulnerabilitiesList }: CasesViewProps) {
  const [cases, setCases] = useState<RealWorldCase[]>(() => {
    const saved = localStorage.getItem('vulnerabilities_cases_database');
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch (e) {
        // fallback to seeded list
      }
    }
    const mappedCves = SEEDED_CVE_CASES.map(mapCVECaseToRealWorldCase);
    return [...mappedCves, ...INITIAL_CASES];
  });

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFilterCategory, setSelectedFilterCategory] = useState('ALL');
  const [currentPage, setCurrentPage] = useState(1);
  const ITEMS_PER_PAGE = 20;

  // Accordion state
  const [expandedCaseIds, setExpandedCaseIds] = useState<Set<string>>(new Set());

  const toggleExpand = (id: string) => {
    const nextSet = new Set(expandedCaseIds);
    if (nextSet.has(id)) {
      nextSet.delete(id);
    } else {
      nextSet.add(id);
    }
    setExpandedCaseIds(nextSet);
  };

  // Live JSON Uploader/Importer States
  const [isImportingConsoleOpen, setIsImportingConsoleOpen] = useState(false);
  const [rawJsonInputText, setRawJsonInputText] = useState('');
  const [importErrorLog, setImportErrorLog] = useState('');

  // Creation and edit forms
  const [isAddingNew, setIsAddingNew] = useState(false);
  const [editingCaseId, setEditingCaseId] = useState<string | null>(null);

  // Form Fields
  const [formTitle, setFormTitle] = useState('');
  const [formCategory, setFormCategory] = useState('');
  const [formTargetEnv, setFormTargetEnv] = useState('');
  const [formAttackSurface, setFormAttackSurface] = useState<'API Endpoint' | 'HTTP Headers' | 'File Upload Router' | 'JSON Request Body' | 'URL Parameter'>('API Endpoint');
  const [formVulnIdRef, setFormVulnIdRef] = useState('sqli');
  const [formRequestPath, setFormRequestPath] = useState('');
  const [formHttpMethod, setFormHttpMethod] = useState<'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH'>('GET');
  const [formHeadersJson, setFormHeadersJson] = useState('{\n  "Content-Type": "application/json"\n}');
  const [formBodyTemplate, setFormBodyTemplate] = useState('{\n  "query": "#TRIGGER_PAYLOAD#"\n}');
  const [formTriggerPayload, setFormTriggerPayload] = useState('');
  const [formExpectedStatus, setFormExpectedStatus] = useState<number>(200);
  const [formRegexPattern, setFormRegexPattern] = useState('');
  const [formSuccessDesc, setFormSuccessDesc] = useState('');
  const [formSynopsis, setFormSynopsis] = useState('');
  const [formMitigation, setFormMitigation] = useState('');
  const [formAutomationInsight, setFormAutomationInsight] = useState('');

  // Active AI Automation Compiler states
  const [compiledReport, setCompiledReport] = useState<string>('');
  const [isCompilingInsights, setIsCompilingInsights] = useState(false);

  // Sync databases helper
  const syncCases = (updated: RealWorldCase[]) => {
    setCases(updated);
    localStorage.setItem('vulnerabilities_cases_database', JSON.stringify(updated));
  };

  const clearForm = () => {
    setFormTitle('');
    setFormCategory('');
    setFormTargetEnv('');
    setFormAttackSurface('API Endpoint');
    setFormVulnIdRef(vulnerabilitiesList[0]?.id || 'sqli');
    setFormRequestPath('');
    setFormHttpMethod('GET');
    setFormHeadersJson('{\n  "Content-Type": "application/json"\n}');
    setFormBodyTemplate('{\n  "query": "#TRIGGER_PAYLOAD#"\n}');
    setFormTriggerPayload('');
    setFormExpectedStatus(200);
    setFormRegexPattern('');
    setFormSuccessDesc('');
    setFormSynopsis('');
    setFormMitigation('');
    setFormAutomationInsight('');
  };

  const handleSaveCase = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formTitle.trim() || !formTargetEnv.trim()) return;

    let headersObj = {};
    try {
      headersObj = JSON.parse(formHeadersJson);
    } catch (err) {
      alert("Warning: Headers JSON structure is invalid. Saving with default.");
    }

    const compiledCase: RealWorldCase = {
      id: editingCaseId || `case_custom_scenario_${Date.now()}`,
      title: formTitle.trim(),
      category: formCategory.trim() || 'General Exploitation Logic',
      targetEnvironmentType: formTargetEnv.trim(),
      attackSurface: formAttackSurface,
      vulnerabilityIdRef: formVulnIdRef,
      automationSnippet: {
        requestPath: formRequestPath.trim(),
        httpMethod: formHttpMethod,
        payloadHeaders: headersObj,
        payloadBodyTemplate: formBodyTemplate,
        triggerPayload: formTriggerPayload.trim()
      },
      verificationPattern: {
        expectedHttpStatusCode: Number(formExpectedStatus),
        matchRegexPattern: formRegexPattern.trim(),
        successIndicatorDescription: formSuccessDesc.trim() || 'Matches response payload telemetry'
      },
      caseSynopsis: formSynopsis.trim(),
      mitigationTested: formMitigation.trim() || 'Standard enterprise security patch applied',
      insightNotesForAutomationEngine: formAutomationInsight.trim() || 'No automation instructions logged'
    };

    if (editingCaseId) {
      const updated = cases.map(c => c.id === editingCaseId ? compiledCase : c);
      syncCases(updated);
      setEditingCaseId(null);
    } else {
      syncCases([compiledCase, ...cases]);
    }

    setIsAddingNew(false);
    clearForm();
  };

  const handleStartEdit = (item: RealWorldCase) => {
    setEditingCaseId(item.id);
    setFormTitle(item.title);
    setFormCategory(item.category);
    setFormTargetEnv(item.targetEnvironmentType);
    setFormAttackSurface(item.attackSurface);
    setFormVulnIdRef(item.vulnerabilityIdRef);
    setFormRequestPath(item.automationSnippet.requestPath);
    setFormHttpMethod(item.automationSnippet.httpMethod);
    setFormHeadersJson(JSON.stringify(item.automationSnippet.payloadHeaders, null, 2));
    setFormBodyTemplate(item.automationSnippet.payloadBodyTemplate);
    setFormTriggerPayload(item.automationSnippet.triggerPayload);
    setFormExpectedStatus(item.verificationPattern.expectedHttpStatusCode);
    setFormRegexPattern(item.verificationPattern.matchRegexPattern);
    setFormSuccessDesc(item.verificationPattern.successIndicatorDescription);
    setFormSynopsis(item.caseSynopsis);
    setFormMitigation(item.mitigationTested);
    setFormAutomationInsight(item.insightNotesForAutomationEngine);
    setIsAddingNew(true);
  };

  const handleDeleteCase = (id: string) => {
    if (window.confirm("Confirm delete this real-world scenario case?")) {
      const updated = cases.filter(c => c.id !== id);
      syncCases(updated);
    }
  };

  const handleResetToDefault = () => {
    if (window.confirm("Reset scenarios database back to default seed list?")) {
      const mappedCves = SEEDED_CVE_CASES.map(mapCVECaseToRealWorldCase);
      syncCases([...mappedCves, ...INITIAL_CASES]);
    }
  };

  const handleImportJSONText = () => {
    if (!rawJsonInputText.trim()) {
      setImportErrorLog("Payload box cannot be empty.");
      return;
    }
    try {
      const cleanedText = rawJsonInputText.trim();
      const parsed = JSON.parse(cleanedText);
      const arrayToImport = Array.isArray(parsed) ? parsed : [parsed];
      const newMappedCases: RealWorldCase[] = [];

      for (const item of arrayToImport) {
        if (item.case_id && item.identity_metadata) {
          // Standard CVE structure
          newMappedCases.push(mapCVECaseToRealWorldCase(item as any));
        } else if (item.id && item.title && item.automationSnippet) {
          // Standard RealWorldCase structure
          newMappedCases.push(item as RealWorldCase);
        } else {
          throw new Error("Unrecognized object format. Must have either (case_id + identity_metadata) or (id + title + automationSnippet) keys.");
        }
      }

      if (newMappedCases.length === 0) {
        throw new Error("No importable items found.");
      }

      // Merge handling duplicates by ID
      const casesMap = new Map<string, RealWorldCase>(cases.map(c => [c.id, c]));
      newMappedCases.forEach(c => casesMap.set(c.id, c));
      
      syncCases(Array.from(casesMap.values()));
      setRawJsonInputText('');
      setImportErrorLog('');
      setIsImportingConsoleOpen(false);
      alert(`Successfully imported and persistent-synced ${newMappedCases.length} scenario profile(s). Existing scenarios with same ID have been updated.`);
    } catch (err: any) {
      setImportErrorLog(`Import failed: ${err.message}`);
    }
  };

  // Compile automation patterns on the fly from current registered systems
  const compileAutomationInsightsMatrix = () => {
    setIsCompilingInsights(true);
    setTimeout(() => {
      // Analyze current cases to extract target insights, patterns, endpoints & headers
      const totals = cases.length;
      const apiEndpointsCount = cases.filter(c => c.attackSurface === 'API Endpoint').length;
      const headersCount = cases.filter(c => c.attackSurface === 'HTTP Headers').length;
      const jsonBodyCount = cases.filter(c => c.attackSurface === 'JSON Request Body').length;
      
      const distinctTargets = Array.from(new Set(cases.map(c => c.targetEnvironmentType)));
      const methodDist = cases.map(c => c.automationSnippet.httpMethod);
      const getCount = methodDist.filter(m => m === 'GET').length;
      const postCount = methodDist.filter(m => m === 'POST').length;

      const report = `================================================================================
CRITICAL EXPLOITATION INSIGHT MATRIX & PORTFOLIO PATTERN REPORT
GENERATED ON: ${new Date().toISOString()} | TELEMETRY NODES ANALYZED: ${totals}
================================================================================

1. ATTACK SURFACE BREAKDOWN FOR PENTESTING SYSTEM ARCHITECT:
   - Total Scenarios Logged: ${totals}
   - Dedicated API Endpoints Tested: ${apiEndpointsCount} (${Math.round((apiEndpointsCount/totals)*100)}%)
   - Header Injections Active: ${headersCount} (${Math.round((headersCount/totals)*100)}%)
   - JSON Body Parameter Vectors: ${jsonBodyCount} (${Math.round((jsonBodyCount/totals)*100)}%)
   
2. NETWORK ORCHESTRATION PROFILE SUMMARY:
   - Dynamic Target Environments: [${distinctTargets.join(', ')}]
   - HTTP Endpoint Distribution: GET: ${getCount} requests | POST: ${postCount} requests

3. AUTOMATED FUZZING PATTERNS & REGEX REPOSITORIES:
${cases.map((c, i) => `   [PATTERN #${i+1}] ${c.title}
   -> Target: ${c.requestPath} (${c.automationSnippet.httpMethod})
   -> Payload: "${c.automationSnippet.triggerPayload}"
   -> Verification regex: /${c.verificationPattern.matchRegexPattern}/g
   -> Automation Insight: ${c.insightNotesForAutomationEngine}
`).join('\n')}

4. MACHINE-LEARNING PATTERN SUITE FOR FUTURE COGNITIVE AGENTS:
   - Rule Alpha: API parameters using sequential sequences ("#TARGET_ID#") must trigger rapid automated cluster fuzz cycles.
   - Rule Beta: For Web SSRF scenarios, automate payload transformations leveraging octal ip vectors next to local link network queries.
   - Rule Gamma: Enforce automated regular expression tests monitoring session cookies changes. Response delta limits higher than 25% prove configuration leak.

================================================================================
REPORT COMPILED SUCCESSFULLY. REGISTERED PATTERNS READY TO SPILL ON ENGINE CORE.
================================================================================`;

      setCompiledReport(report);
      setIsCompilingInsights(false);
    }, 1100);
  };

  // Filter and Sort cases based on keyword and CVE chronological order
  const filteredCases = useMemo(() => {
    return cases
      .filter(c => {
        const query = searchQuery.toLowerCase();
        const matchText = 
          c.id.toLowerCase().includes(query) ||
          c.title.toLowerCase().includes(query) ||
          c.category.toLowerCase().includes(query) ||
          c.targetEnvironmentType.toLowerCase().includes(query) ||
          c.caseSynopsis.toLowerCase().includes(query) ||
          c.insightNotesForAutomationEngine.toLowerCase().includes(query);

        if (selectedFilterCategory === 'ALL') return matchText;
        return matchText && c.category === selectedFilterCategory;
      })
      .sort((a, b) => {
        const cveRegex = /CVE-(\d{4})-(\d+)/i;
        const matchA = a.id.match(cveRegex);
        const matchB = b.id.match(cveRegex);

        if (matchA && matchB) {
          const yearA = parseInt(matchA[1], 10);
          const yearB = parseInt(matchB[1], 10);
          if (yearA !== yearB) return yearB - yearA; // Newest year first
          const numA = parseInt(matchA[2], 10);
          const numB = parseInt(matchB[2], 10);
          return numB - numA; // Newest sequence number first
        }
        
        // If one is CVE and other isn't, CVE comes first
        if (matchA) return -1;
        if (matchB) return 1;

        // Sort custom scenarios by timestamp (newest first)
        const tsRegex = /case_custom_scenario_(\d+)/;
        const tsA = a.id.match(tsRegex);
        const tsB = b.id.match(tsRegex);
        if (tsA && tsB) return parseInt(tsB[1], 10) - parseInt(tsA[1], 10);
        if (tsA) return -1;
        if (tsB) return 1;

        return b.id.localeCompare(a.id);
      });
  }, [cases, searchQuery, selectedFilterCategory]);

  const totalPages = Math.ceil(filteredCases.length / ITEMS_PER_PAGE);
  const paginatedCases = filteredCases.slice((currentPage - 1) * ITEMS_PER_PAGE, currentPage * ITEMS_PER_PAGE);

  const categoriesList = ['ALL', ...Array.from(new Set(cases.map(c => c.category)))];

  return (
    <div className="max-w-7xl mx-auto px-4 py-4 animate-fade-in font-sans flex flex-col gap-8">
      
      {/* CASE PAGE BANNERS */}
      <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-white/10 pb-5 gap-4 select-none">
        <div>
          <div className="flex items-center gap-2 text-[#CCFF00] font-mono text-[10px] uppercase tracking-wider mb-2">
            <Bookmark className="w-3.5 h-3.5" />
            <span>Real-world Threat Incidents & Verification Scenarios</span>
          </div>
          <h1 className="text-2xl font-black text-white uppercase tracking-tight font-display">
            Incidents Case Database
          </h1>
          <p className="text-xs text-zinc-400 mt-1 select-text">
            Build and organize concrete exploit scenarios with precise request paths, header matrices, trigger payloads, and regex matches for automation insights.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button 
            type="button" 
            onClick={() => {
              setIsImportingConsoleOpen(!isImportingConsoleOpen);
              if (isAddingNew) setIsAddingNew(false);
            }}
            className={`px-4 py-3 border font-mono text-xs uppercase tracking-wider transition-all duration-150 cursor-pointer rounded-xl flex items-center gap-2 ${
              isImportingConsoleOpen
                ? 'bg-purple-900/30 border-[#CCFF00] text-[#CCFF00]'
                : 'bg-zinc-950 border-white/10 hover:border-[#CCFF00]/50 hover:bg-zinc-900 text-zinc-350 hover:text-white'
            }`}
            title="Import Raw JSON payloads of scenarios"
          >
            <Upload className="w-4 h-4" />
            <span>Import JSON</span>
          </button>

          <button 
            type="button" 
            onClick={handleResetToDefault}
            className="px-3.5 py-3 bg-zinc-950 border border-white/10 hover:border-red-500/50 hover:bg-zinc-900 text-zinc-450 hover:text-red-400 font-mono text-xs uppercase tracking-wider transition-all duration-150 cursor-pointer rounded-xl"
            title="Reset to core seeded cases"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          
          <button
            onClick={() => {
              clearForm();
              setEditingCaseId(null);
              setIsAddingNew(!isAddingNew);
              if (isImportingConsoleOpen) setIsImportingConsoleOpen(false);
            }}
            className="px-4 py-3 bg-[#CCFF00] hover:bg-[#b0db00] text-black font-semibold text-xs font-mono uppercase tracking-wider transition-all duration-150 cursor-pointer flex items-center gap-2 rounded-xl"
          >
            {isAddingNew && !editingCaseId ? (
              <>
                <X className="w-3.5 h-3.5" />
                Close Creator
              </>
            ) : (
              <>
                <Plus className="w-3.5 h-3.5 stroke-[3]" />
                Log Scenario Case
              </>
            )}
          </button>
        </div>
      </div>

      {/* BULK PAYLOAD IMPORT TERMINAL */}
      {isImportingConsoleOpen && (
        <div className="bg-zinc-950/95 border-2 border-purple-500/20 p-6 rounded-2xl flex flex-col gap-4 animate-fade-in shadow-2xl select-text">
          <div className="flex justify-between items-center border-b border-white/5 pb-3 select-none">
            <h3 className="font-mono text-xs uppercase font-bold text-[#CCFF00] flex items-center gap-2">
              <Upload className="w-4 h-4" />
              [Bulk Cases Payload Importer Terminal]
            </h3>
            <button
              type="button"
              onClick={() => {
                setIsImportingConsoleOpen(false);
                setRawJsonInputText('');
                setImportErrorLog('');
              }}
              className="text-zinc-500 hover:text-white font-mono text-[10px] uppercase cursor-pointer"
            >
              [Close Terminal]
            </button>
          </div>

          <p className="text-xs text-zinc-400 font-sans max-w-4xl">
            Input a raw JSON array or single object in either your <strong>Identity Metadata CVE format</strong> or our native <strong>RealWorldCase structure</strong>. This compiler will auto-detect and sync them securely with your active cases database persistent context.
          </p>

          <div className="flex flex-col gap-2">
            <label className="text-[10px] font-mono uppercase text-zinc-500">Or drag & drop/select a file:</label>
            <input 
              type="file" 
              accept=".json" 
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) {
                  const reader = new FileReader();
                  reader.onload = (event) => {
                    setRawJsonInputText(event.target?.result as string);
                  };
                  reader.readAsText(file);
                }
              }}
              className="text-xs text-zinc-400 file:bg-zinc-800 file:text-white file:border-none file:px-2 file:py-1 file:rounded"
            />
            <textarea
              rows={8}
              required
              placeholder='Paste raw JSON here... e.g. [{"case_id": "...", ...}]'
              value={rawJsonInputText}
              onChange={e => setRawJsonInputText(e.target.value)}
              className="w-full bg-black border border-white/10 text-xs p-4 text-zinc-300 font-mono focus:outline-none focus:border-[#CCFF00] rounded-xl selection:bg-[#CCFF00] selection:text-black"
            />
          </div>

          {importErrorLog && (
            <div className="bg-red-950/20 border border-red-500/50 text-red-500 text-xs p-3 font-mono rounded-lg">
              ✕ {importErrorLog}
            </div>
          )}

          <div className="flex justify-between items-center select-none pt-2">
            <div className="text-[10px] font-mono text-zinc-500">
              * Supports multi-record structures and automatic type-conversion mapping.
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => {
                  setRawJsonInputText(JSON.stringify(SEEDED_CVE_CASES[0], null, 2));
                  setImportErrorLog('');
                }}
                className="px-3.5 py-2 hover:bg-zinc-900 border border-white/10 text-zinc-400 hover:text-white text-[10px] font-mono uppercase rounded-lg transition-all cursor-pointer"
              >
                Insert Example
              </button>
              <button
                type="button"
                onClick={handleImportJSONText}
                className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white font-bold text-xs font-mono uppercase tracking-wider rounded-lg transition-all flex items-center gap-2 cursor-pointer"
              >
                <Check className="w-3.5 h-3.5" />
                Parse & Live-Sync Cases
              </button>
            </div>
          </div>
        </div>
      )}

      {/* DETAILED INCIDENT LOGGER FORM */}

      {isAddingNew && (
        <form onSubmit={handleSaveCase} className="bg-black/90 border-2 border-[#CCFF00]/30 p-6 rounded-2xl flex flex-col gap-6 animate-fade-in shadow-2xl">
          <div className="flex justify-between items-center border-b border-white/5 pb-3 select-none">
            <h3 className="font-mono text-xs uppercase font-bold text-[#CCFF00] flex items-center gap-2">
              <Award className="w-4 h-4" />
              {editingCaseId ? `[Updating Case Detail Profile]` : '[Registering Professional Real Exploitation Scenario]'}
            </h3>
            <button
              type="button"
              onClick={() => {
                setIsAddingNew(false);
                setEditingCaseId(null);
                clearForm();
              }}
              className="text-zinc-500 hover:text-white font-mono text-[10px] uppercase"
            >
              [Cancel]
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase text-zinc-400">Incident Scenario Title *</label>
              <input
                type="text"
                required
                placeholder="e.g. JWT Token Leak via Host Registry"
                value={formTitle}
                onChange={e => setFormTitle(e.target.value)}
                className="bg-zinc-950 border border-white/10 text-xs px-3.5 py-2.5 text-white focus:outline-none focus:border-[#CCFF00] rounded-lg font-mono uppercase"
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase text-zinc-400">Backstory Category Group *</label>
              <input
                type="text"
                required
                placeholder="e.g. API Access Controls, SSRF"
                value={formCategory}
                onChange={e => setFormCategory(e.target.value)}
                className="bg-zinc-950 border border-white/10 text-xs px-3.5 py-2.5 text-white focus:outline-none focus:border-[#CCFF00] rounded-lg font-mono"
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase text-zinc-400">Target System Environment Type *</label>
              <input
                type="text"
                required
                placeholder="e.g. AWS Linux Node / Docker Sandbox"
                value={formTargetEnv}
                onChange={e => setFormTargetEnv(e.target.value)}
                className="bg-zinc-950 border border-white/10 text-xs px-3.5 py-2.5 text-white focus:outline-none focus:border-[#CCFF00] rounded-lg"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase text-zinc-400">Attacking Vector Area *</label>
              <select
                value={formAttackSurface}
                onChange={e => setFormAttackSurface(e.target.value as any)}
                className="bg-zinc-950 border border-white/10 text-xs px-3.5 py-2.5 text-white focus:outline-none focus:border-[#CCFF00] rounded-lg"
              >
                <option value="API Endpoint">API Endpoint</option>
                <option value="HTTP Headers">HTTP Headers</option>
                <option value="File Upload Router">File Upload Router</option>
                <option value="JSON Request Body">JSON Request Body</option>
                <option value="URL Parameter">URL Parameter</option>
              </select>
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase text-zinc-400">Match Catalog Defect *</label>
              <select
                value={formVulnIdRef}
                onChange={e => setFormVulnIdRef(e.target.value)}
                className="bg-zinc-950 border border-white/10 text-xs px-3.5 py-2.5 text-white focus:outline-none focus:border-[#CCFF00] rounded-lg font-mono uppercase"
              >
                {vulnerabilitiesList.slice(0, 80).map(v => (
                  <option key={v.id} value={v.id}>
                    {v.cwe_id} - {v.name.slice(0, 42)}... ({v.severity})
                  </option>
                ))}
              </select>
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase text-zinc-400">Destination Test Path *</label>
              <input
                type="text"
                required
                placeholder="e.g. /api/v1/auth/login"
                value={formRequestPath}
                onChange={e => setFormRequestPath(e.target.value)}
                className="bg-zinc-950 border border-white/10 text-xs px-3.5 py-2.5 text-white focus:outline-none focus:border-[#CCFF00] rounded-lg font-mono"
              />
            </div>
          </div>

          <div className="bg-zinc-950 p-4 border border-white/10 rounded-xl flex flex-col gap-4">
            <span className="text-[10px] font-mono text-[#CCFF00] uppercase font-bold tracking-wider">[PENTESTING AUTOMATION TELEMETRY CODES]</span>
            
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="flex flex-col gap-1">
                <span className="text-[9px] font-mono text-zinc-450 uppercase">HTTP Method</span>
                <select
                  value={formHttpMethod}
                  onChange={e => setFormHttpMethod(e.target.value as any)}
                  className="bg-black border border-white/10 text-xs py-2 px-3 text-zinc-350"
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                  <option value="PATCH">PATCH</option>
                </select>
              </div>

              <div className="flex flex-col gap-1 md:col-span-1">
                <span className="text-[9px] font-mono text-zinc-450 uppercase">Active Trigger Payload</span>
                <input
                  type="text"
                  placeholder="e.g. admin' or 1=1--"
                  value={formTriggerPayload}
                  onChange={e => setFormTriggerPayload(e.target.value)}
                  className="bg-black border border-white/10 text-xs py-2 px-3 text-zinc-350 font-mono"
                />
              </div>

              <div className="flex flex-col gap-1">
                <span className="text-[9px] font-mono text-zinc-450 uppercase">Expected HTTP Code Response</span>
                <input
                  type="number"
                  placeholder="200"
                  value={formExpectedStatus}
                  onChange={e => setFormExpectedStatus(Number(e.target.value))}
                  className="bg-black border border-white/10 text-xs py-2 px-3 text-zinc-350 font-mono"
                />
              </div>

              <div className="flex flex-col gap-1">
                <span className="text-[9px] font-mono text-zinc-450 uppercase">Analysis Success Match Regex</span>
                <input
                  type="text"
                  placeholder="e.g. root:x:0|access_token"
                  value={formRegexPattern}
                  onChange={e => setFormRegexPattern(e.target.value)}
                  className="bg-black border border-white/10 text-xs py-2 px-3 text-zinc-350 font-mono"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="flex flex-col gap-1">
                <span className="text-[9px] font-mono text-zinc-450 uppercase">Automation Headers JSON</span>
                <textarea
                  rows={3}
                  value={formHeadersJson}
                  onChange={e => setFormHeadersJson(e.target.value)}
                  className="bg-black border border-white/10 text-xs p-2 text-zinc-400 font-mono"
                />
              </div>

              <div className="flex flex-col gap-1">
                <span className="text-[9px] font-mono text-zinc-450 uppercase">Automation Request Template JSON / URL</span>
                <textarea
                  rows={3}
                  value={formBodyTemplate}
                  onChange={e => setFormBodyTemplate(e.target.value)}
                  className="bg-black border border-white/10 text-xs p-2 text-zinc-400 font-mono"
                />
              </div>
            </div>

            <div className="flex flex-col gap-1">
              <span className="text-[9px] font-mono text-zinc-500 uppercase">Automation Verification Payload Verdict Description</span>
              <input
                type="text"
                placeholder="Briefly state how to evaluate success e.g. Valid token parsed successfully inside response stream..."
                value={formSuccessDesc}
                onChange={e => setFormSuccessDesc(e.target.value)}
                className="bg-black border border-white/10 text-xs py-2 px-3 text-zinc-350 font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase text-zinc-400">Incident Backstory & Synopsis</label>
              <textarea
                rows={3}
                placeholder="Log backstory on target weakness, incident data, and telemetry logs..."
                value={formSynopsis}
                onChange={e => setFormSynopsis(e.target.value)}
                className="bg-zinc-950 border border-white/10 text-xs p-3 text-zinc-300"
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase text-zinc-400">Remediation Tested & Proven</label>
              <textarea
                rows={3}
                placeholder="Log architectural mitigations or WAF rules tested..."
                value={formMitigation}
                onChange={e => setFormMitigation(e.target.value)}
                className="bg-zinc-950 border border-white/10 text-xs p-3 text-zinc-300"
              />
            </div>

            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase text-zinc-400">Automation Engine Insight Notes</label>
              <textarea
                rows={3}
                placeholder="Provide directions for future automation engine: patterns, sizes, and behaviors log..."
                value={formAutomationInsight}
                onChange={e => setFormAutomationInsight(e.target.value)}
                className="bg-zinc-950 border border-white/10 text-xs p-3 text-zinc-300"
              />
            </div>
          </div>

          <div className="flex justify-end gap-3 border-t border-white/5 pt-4">
            <button
              type="button"
              onClick={() => {
                setIsAddingNew(false);
                setEditingCaseId(null);
                clearForm();
              }}
              className="px-4 py-2.5 bg-zinc-900 border border-white/15 text-zinc-400 hover:text-white text-xs font-mono uppercase transition-colors rounded-lg cursor-pointer"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-5 py-2.5 bg-[#CCFF00] hover:bg-[#b0db00] text-black font-bold text-xs font-mono uppercase tracking-wider transition-all rounded-lg cursor-pointer flex items-center gap-2"
            >
              <Save className="w-3.5 h-3.5" />
              {editingCaseId ? 'Update Scenario Case' : 'Save Scenario Incident'}
            </button>
          </div>
        </form>
      )}

      {/* FILTER SEARCH SPLIT HEADER */}
      <div className="flex justify-between items-center bg-zinc-900 text-zinc-400 p-3 mb-4 rounded-xl text-xs font-mono">
        <div>Showing {filteredCases.length} Scenarios</div>
      </div>
      <div className="flex flex-col md:flex-row items-center gap-4 bg-zinc-950 p-4 border border-white/10 rounded-2xl select-none">
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-3 w-4 h-4 text-zinc-500" />
          <input
            type="text"
            placeholder="Search Backstories, Attack Surface, Verification Regular Expressions..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full bg-black border border-white/10 text-[11px] py-2 px-9 text-white placeholder-zinc-550 rounded-xl focus:outline-none focus:border-[#CCFF00] transition-colors font-mono uppercase"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto shrink-0 justify-between sm:justify-start">
          <div className="flex items-center gap-1">
            <Layers className="w-3.5 h-3.5 text-zinc-400" />
            <span className="text-[10px] font-mono uppercase text-zinc-500">Category Filter:</span>
          </div>

          <div className="flex gap-1.5 overflow-x-auto">
            {categoriesList.slice(0, 5).map(cat => (
              <button
                key={cat}
                onClick={() => {
                  setSelectedFilterCategory(cat);
                  setCurrentPage(1);
                }}
                className={`px-3 py-1.5 rounded-lg border text-[10px] font-bold font-mono uppercase transition-colors cursor-pointer select-none ${
                  selectedFilterCategory === cat 
                    ? 'bg-[#CCFF00] border-[#CCFF00] text-black' 
                    : 'bg-black border-white/10 text-zinc-400 hover:text-white'
                }`}
              >
                {cat === 'ALL' ? '[ALL MATRICES]' : cat}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* INTUITIVE PENTEST AUTOMATION CODES PANEL */}
      <div className="bg-black border-2 border-white/5 p-6 rounded-2xl flex flex-col gap-4 shadow-xl select-text">
        <div className="flex items-center justify-between border-b border-white/5 pb-3">
          <div className="flex items-center gap-2">
            <Cpu className="w-5 h-5 text-[#CCFF00]" />
            <h3 className="font-mono text-xs uppercase font-bold text-white tracking-widest">
              [PENTEST AUTOMATION PATTERNS CORE]
            </h3>
          </div>
          <button
            onClick={compileAutomationInsightsMatrix}
            disabled={isCompilingInsights}
            className="px-3 py-2 bg-zinc-900 border border-white/10 hover:border-[#CCFF00] hover:text-[#CCFF00] text-zinc-350 text-[10px] font-mono tracking-wider uppercase transition-colors cursor-pointer flex items-center gap-1.5"
          >
            {isCompilingInsights ? (
              <>
                <RefreshCw className="w-3 h-3 animate-spin text-[#CCFF00]" />
                <span>Scanning Patterns...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-3.5 h-3.5 text-[#CCFF00]" />
                <span>Construct Automation Insights Matrix</span>
              </>
            )}
          </button>
        </div>

        <p className="text-[11px] text-zinc-400 font-sans max-w-4xl">
          We designed this portal to extract patterns of payloads and indicators of compromise. By cataloging precise target paths, HTTP methods, headers, and response regular expressions, future automated scanners can seamlessly mount customized payload suites onto newly identified targets without writing scripts from scratch.
        </p>

        {compiledReport && (
          <div className="mt-2 bg-zinc-950 border border-[#CCFF00]/15 p-4 rounded-xl flex flex-col gap-3">
            <div className="flex justify-between items-center text-[10.5px] font-mono uppercase select-none pb-2 border-b border-white/5">
              <span className="text-[#CCFF00]">✓ AUTOMATION PATTERN SPECS SYNTHESIZED</span>
              <button 
                onClick={() => setCompiledReport('')}
                className="text-zinc-500 hover:text-white text-[9.5px]"
              >
                [Clear Terminal]
              </button>
            </div>
            <pre className="text-[9.5px] text-zinc-300 font-mono overflow-x-auto whitespace-pre p-3 bg-black rounded border border-white/5 selection:bg-[#CCFF00] selection:text-black">
              {compiledReport}
            </pre>
            <div className="flex justify-end select-none">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(compiledReport);
                  alert("Automation specifications matrix report copied to clipboard!");
                }}
                className="px-3 py-1.5 bg-[#CCFF00] hover:bg-[#b0db00] text-black text-[9.5px] font-mono uppercase font-bold tracking-wider"
              >
                Copy Specs to Clipboard
              </button>
            </div>
          </div>
        )}
      </div>

      {/* DETAILED SCENARIO INCIDENTS CARD GRID */}
      {paginatedCases.length > 0 ? ( <React.Fragment>
        <div className="grid grid-cols-1 gap-6">
          {paginatedCases.map(item => {
            return (
              <div 
                key={item.id}
                className="bg-purple-950/5 border border-white/10 hover:border-[#CCFF00]/40 transition-all rounded-2xl p-6 flex flex-col gap-4 shadow-xl select-text"
              >
                
              {/* Header detail row */}
                <div className="flex flex-col sm:flex-row justify-between sm:items-start border-b border-white/5 pb-4 gap-3">
                  <div className="flex-1">
                    <div className="flex flex-wrap items-center gap-1.5 mb-1.5 select-none">
                      <span className="px-2 py-0.5 bg-zinc-900 border border-white/5 text-[#CCFF00] font-mono text-[9px] uppercase font-semibold rounded">
                        {item.category}
                      </span>
                      <span className="px-2 py-0.5 bg-zinc-950 border border-white/10 text-zinc-400 font-mono text-[9.5px] uppercase rounded">
                        Env: {item.targetEnvironmentType}
                      </span>
                    </div>

                    <h3 className="text-base font-bold text-white uppercase tracking-tight font-display font-medium">
                      {item.title}
                    </h3>
                  </div>

                  <div className="flex items-center gap-1.5 self-end sm:self-start select-none">
                    <button
                      onClick={() => toggleExpand(item.id)}
                      className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 dark:bg-zinc-600 dark:hover:bg-zinc-500 text-white text-[10px] uppercase font-mono rounded cursor-pointer"
                    >
                      {expandedCaseIds.has(item.id) ? 'Hide Details' : 'Show Details'}
                    </button>
                    <button
                      onClick={() => handleStartEdit(item)}
                      className="p-1.5 bg-black border border-white/5 hover:border-[#CCFF00] hover:bg-zinc-900 text-zinc-400 hover:text-[#CCFF00] transition-all rounded cursor-pointer"
                      title="Edit Scenario Context"
                    >
                      <Edit3 className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => handleDeleteCase(item.id)}
                      className="p-1.5 bg-black border border-white/5 hover:border-red-500/50 hover:bg-zinc-900 text-zinc-450 hover:text-red-400 transition-all rounded cursor-pointer"
                      title="Remove Incident Profile"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Automation detail matrix block */}
                {expandedCaseIds.has(item.id) && (
                  <div className="flex flex-col gap-5 pt-4">
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 bg-zinc-50 dark:bg-zinc-900 p-5 border border-zinc-200 dark:border-zinc-700 rounded-xl">
                      
                      {/* Part 1: Automated query structure */}
                      <div className="flex flex-col gap-2">
                        <span className="text-[10px] font-mono uppercase text-[#CCFF00] tracking-wider border-b border-white/5 pb-1 flex items-center gap-1.5">
                          <Terminal className="w-3.5 h-3.5" />
                          1. Trigger Fuzz Config
                        </span>
                        <div className="flex flex-col gap-2 text-[10px] font-mono text-zinc-300">
                          <div>
                            <span className="text-zinc-550">Method / Route:</span>
                            <span className="text-white ml-1.5 bg-zinc-900 px-1 py-0.5 font-bold">{item.automationSnippet.httpMethod}</span>
                            <code className="text-[#CCFF00]/80 ml-1.5 break-all">{item.automationSnippet.requestPath}</code>
                          </div>
                          <div className="flex flex-col gap-1 mt-1">
                            <span className="text-zinc-550">Active Payload:</span>
                            <code className="text-zinc-100 select-all break-all underline decoration-[#CCFF00]/30 font-bold bg-zinc-950 p-2 mt-1 whitespace-pre-wrap block text-[9.5px] leading-relaxed max-h-72 overflow-y-auto">
                              {item.automationSnippet.triggerPayload}
                            </code>
                          </div>
                        </div>
                      </div>

                      {/* Part 2: Dynamic headers & body payload template */}
                      <div className="flex flex-col gap-2">
                        <span className="text-[10px] font-mono uppercase text-zinc-400 tracking-wider border-b border-white/5 pb-1 flex items-center gap-1.5">
                          <FileCode className="w-3.5 h-3.5" />
                          2. Template Headers & Payload
                        </span>
                        <div className="flex flex-col gap-1 font-mono text-[9.5px]">
                          <div className="break-all select-all text-zinc-400">
                            <span className="text-zinc-650">Headers:</span> {JSON.stringify(item.automationSnippet.payloadHeaders || {})}
                          </div>
                          <div className="break-all select-all text-zinc-400">
                            <span className="text-zinc-650">Body Template:</span> {item.automationSnippet.payloadBodyTemplate || "{}"}
                          </div>
                        </div>
                      </div>

                      {/* Part 3: Automated response verification and indicator pattern */}
                      <div className="flex flex-col gap-2">
                        <span className="text-[10px] font-mono uppercase text-amber-400 tracking-wider border-b border-white/5 pb-1 flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          3. Proof Pattern Verification
                        </span>
                        <div className="flex flex-col gap-1 text-[10px] font-mono text-zinc-300">
                          <div>
                            <span className="text-zinc-550">Comp. Status Code:</span>
                            <span className="text-amber-400 ml-1.5 font-bold">== {item.verificationPattern.expectedHttpStatusCode}</span>
                          </div>
                          <div>
                            <span className="text-zinc-550">Response Match Regex:</span>
                            <code className="text-white ml-2 bg-[#CCFF00]/10 border border-[#CCFF00]/20 px-1.5 py-0.5 rounded text-[9.5px] select-all">/{item.verificationPattern.matchRegexPattern}/g</code>
                          </div>
                          <div className="text-[9.5px] text-zinc-500 italic lowercase mt-1">
                            * {item.verificationPattern.successIndicatorDescription}
                          </div>
                        </div>
                      </div>

                    </div>

                    {/* Backstory, mitigation, and automation insight logs */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-5 text-[11px] leading-relaxed">
                      
                      {/* Case backstory synopsis */}
                      <div className="bg-zinc-950/40 p-4 border border-white/5 rounded-xl">
                        <strong className="text-zinc-500 font-bold font-mono text-[9px] uppercase tracking-wider block mb-1.5">
                          [Case Scenario Backstory]
                        </strong>
                        <div className="text-zinc-300 font-sans whitespace-pre-wrap">
                          {item.caseSynopsis}
                        </div>
                      </div>

                      {/* Mitigation proven section */}
                      <div className="bg-zinc-950/40 p-4 border border-white/5 rounded-xl">
                        <strong className="text-zinc-500 font-bold font-mono text-[9px] uppercase tracking-wider block mb-1.5">
                          [Mitigations Tested & Secured]
                        </strong>
                        <div className="text-zinc-350 font-sans border-l-2 border-[#CCFF00]/40 pl-3 whitespace-pre-wrap">
                          {item.mitigationTested}
                        </div>
                      </div>

                      {/* Future automated fuzzer engine integration notes */}
                      <div className="bg-[#CCFF00]/5 p-4 border border-[#CCFF00]/10 rounded-xl">
                        <strong className="text-[#CCFF00] font-bold font-mono text-[9.5px] uppercase tracking-widest block mb-1.5">
                          💡 Automation Engine Insights
                        </strong>
                        <div className="text-zinc-300 font-mono text-[10px] whitespace-pre-wrap">
                          {item.insightNotesForAutomationEngine}
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                <div className="text-[9px] font-mono text-zinc-650 uppercase flex justify-between items-center select-none pt-2 border-t border-white/5">
                  <span>Unique Ref Key: {item.id}</span>
                  <span>Payload Attack Surface Target: {item.attackSurface}</span>
                </div>

              </div>
            );
          })}
        </div>
        {totalPages > 1 && (
          <div className="flex justify-center items-center gap-4 mt-6 p-4 bg-zinc-950 rounded-xl border border-white/10">
            <button 
              disabled={currentPage === 1}
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              className="px-3 py-1 bg-zinc-800 rounded disabled:opacity-50 text-zinc-400 font-mono text-xs cursor-pointer hover:bg-zinc-700 transition"
            >
              Prev
            </button>
            
            <span className="text-zinc-500 text-xs font-mono">
              Page {currentPage} of {totalPages}
            </span>
            
            <button 
              disabled={currentPage === totalPages}
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              className="px-3 py-1 bg-zinc-800 rounded disabled:opacity-50 text-zinc-400 font-mono text-xs cursor-pointer hover:bg-zinc-700 transition"
            >
              Next
            </button>
          </div>
        )}
        </React.Fragment>
      ) : (
        <div className="py-12 border border-white/10 rounded-2xl bg-zinc-950/50 flex flex-col items-center justify-center gap-3 text-center">
          <AlertTriangle className="w-10 h-10 text-zinc-650" />
          <div>
            <h3 className="font-mono text-xs uppercase font-bold text-zinc-400">No Scenario Cases Found</h3>
            <p className="text-[10.5px] text-zinc-500 mt-1 max-w-sm font-sans">
              No registered exploit backstories match your filter criteria. Log a custom incident above.
            </p>
          </div>
          {selectedFilterCategory !== 'ALL' && (
            <button
              onClick={() => setSelectedFilterCategory('ALL')}
              className="text-[10px] font-mono text-[#CCFF00] hover:underline"
            >
              Reset category filters
            </button>
          )}
        </div>
      )}

    </div>
  );
}
