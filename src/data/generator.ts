import { Vulnerability } from '../types';

// Diverse categories, severities, envs, techniques to sample procedurally
const CATEGORIES: ('web-api' | 'server-os' | 'cloud-security')[] = ['web-api', 'server-os', 'cloud-security'];
const SEVERITIES: ('Critical' | 'High' | 'Medium' | 'Low')[] = ['Critical', 'High', 'Medium', 'Low'];

const INTEGRATION_MODULES = [
  'Billing', 'Authentication', 'Invoice Processing', 'User Profile', 'Cloud Store Storage',
  'Metadata Proxy', 'Container Daemon', 'Cluster Controller', 'Database Sync Router',
  'Webhook Web-Notifier', 'Search Auto-indexing', 'Prometheus Scrape Endpoint',
  'Payment Dispatcher', 'PDF Generator Engine', 'Backup Scheduler Service',
  'AI Embedding Vectorizer', 'GraphQL Query Router', 'WebSocket Notification Sync',
  'ElasticSearch Client Connection', 'OAuth Partner Handshake'
];

const CWE_POOL = [
  { cwe: 'CWE-89', name: 'SQL Injection (SQLi)', category: 'web-api' as const, severity: 'Critical' as const, env: 'Relational Database Gateway' },
  { cwe: 'CWE-79', name: 'Cross-Site Scripting (XSS)', category: 'web-api' as const, severity: 'High' as const, env: 'Client Interface Rendering Engine' },
  { cwe: 'CWE-918', name: 'Server-Side Request Forgery (SSRF)', category: 'cloud-security' as const, severity: 'High' as const, env: 'Internal VPC Proxy & Hypervisors' },
  { cwe: 'CWE-22', name: 'Directory Path Traversal / LFI', category: 'server-os' as const, severity: 'High' as const, env: 'Local File System Kernel IO' },
  { cwe: 'CWE-287', name: 'Improper Authentication Protocol', category: 'web-api' as const, severity: 'Critical' as const, env: 'Identity Session Core Broker' },
  { cwe: 'CWE-502', name: 'Insecure Deserialization of Stream', category: 'server-os' as const, severity: 'Critical' as const, env: 'Application Middleware State Broker' },
  { cwe: 'CWE-611', name: 'XML External Entity Reference (XXE)', category: 'web-api' as const, severity: 'High' as const, env: 'Enterprise XML / SOAP Core Engine' },
  { cwe: 'CWE-862', name: 'Missing Authorization Rules (BOLA)', category: 'web-api' as const, severity: 'High' as const, env: 'API Endpoint Access Controller' },
  { cwe: 'CWE-78', name: 'OS Script Command Injection', category: 'server-os' as const, severity: 'Critical' as const, env: 'Operating System Shell Integration' },
  { cwe: 'CWE-94', name: 'Dynamic Code Execution Injection', category: 'server-os' as const, severity: 'Critical' as const, env: 'Runtime Template Compilation Engine' },
  { cwe: 'CWE-200', name: 'Unauthorized Information Disclosure', category: 'web-api' as const, severity: 'Medium' as const, env: 'Detailed Event Logging / API Responses' },
  { cwe: 'CWE-311', name: 'Missing Integrity Protection (Cleartext)', category: 'cloud-security' as const, severity: 'High' as const, env: 'Public S3 Bucket / Tenant Store' },
  { cwe: 'CWE-1333', name: 'Inefficient Regex Complexity (ReDoS)', category: 'server-os' as const, severity: 'Medium' as const, env: 'Input Parser Thread Scheduler' },
  { cwe: 'CWE-400', name: 'Uncontrolled Resource Load Exhaustion', category: 'server-os' as const, severity: 'Medium' as const, env: 'Host Resource Memory Pool' },
  { cwe: 'CWE-352', name: 'Cross-Site Request Forgery (CSRF)', category: 'web-api' as const, severity: 'Medium' as const, env: 'Cookie Authentication Router' },
  { cwe: 'CWE-444', name: 'Inconsistent HTTP Request Parsing', category: 'server-os' as const, severity: 'High' as const, env: 'Reverse Proxy & Load Balancer Layers' },
  { cwe: 'CWE-1039', name: 'AI LLM Framework Prompt Hijack', category: 'web-api' as const, severity: 'High' as const, env: 'AI Inference Orchestrator' }
];

export function generateExtendedThreatIntelligence(baseline: Vulnerability[], targetCount: number = 512): Vulnerability[] {
  // If baseline is already large enough, return as is
  if (baseline.length >= targetCount) return baseline;

  const results = [...baseline];
  const existingIds = new Set(baseline.map(b => b.id));

  // Counter variable to pad IDs sequentially
  let counter = baseline.length + 1;

  while (results.length < targetCount) {
    const cweMeta = CWE_POOL[counter % CWE_POOL.length];
    const module = INTEGRATION_MODULES[counter % INTEGRATION_MODULES.length];
    const itemSeverity = counter % 7 === 0 ? 'Critical' : (counter % 3 === 0 ? 'High' : (counter % 2 === 0 ? 'Medium' : 'Low'));
    
    // Generate distinct ID
    const uniqueId = `procedural_vuln_${cweMeta.cwe.replace('-', '_').toLowerCase()}_${module.toLowerCase().replace(/[^a-z0-9]/g, '_')}_${counter}`;
    if (existingIds.has(uniqueId)) {
      counter++;
      continue;
    }

    const vulnName = `${cweMeta.name} on ${module} Module`;
    const technicalExplanation = `Security telemetry audit discovered a valid path mapping to ${cweMeta.cwe} inside the ${module} component. Typically, developers interacting with nested payloads fail to validate input constraints or perform fine-grained authorization checks prior to dispatching state actions. This leads to direct logical compromises, local privilege escalations, or unauthorized extraction of customer vectors.`;
    
    const environment = `${cweMeta.env} [Inst. #${100 + (counter % 899)}]`;
    
    // Generate specialized snippets dynamically based on the CWE type
    let vulnerable_code_snippet = '';
    let vulnerable_code_lang = 'typescript';
    let remediation_code_snippet = '';
    let remediation_code_lang = 'typescript';
    let payload_example = '';
    let remediation = '';
    
    if (cweMeta.cwe === 'CWE-89') {
      vulnerable_code_snippet = `// VULNERABLE Dynamic concatenation of query parameter
const rawInput = req.query.filter;
const sql = "SELECT * FROM metadata_registry WHERE tag = '" + rawInput + "'";
const records = await db.raw(sql);`;
      remediation_code_snippet = `// SECURED Parameterized parameterized driver query
const cleanInput = req.query.filter;
const records = await db.query("SELECT * FROM metadata_registry WHERE tag = ?", [cleanInput]);`;
      payload_example = `active' UNION SELECT null, secret_key, null, null FROM cloud_creds --`;
      remediation = 'Implement strongly bound SQL parameterized descriptors or leverage a validated ORM framework with built-in auto-escaping.';
    } else if (cweMeta.cwe === 'CWE-918') {
      vulnerable_code_snippet = `// VULNERABLE Blind forwarding of custom fetch URL
const targetUrl = req.body.url;
const externalData = await axios.get(targetUrl);`;
      remediation_code_snippet = `// SECURED Canonical DNS blacklist check and schema restriction
const targetUrl = new URL(req.body.url);
if (['169.254.169.254', '127.0.0.1', 'localhost'].includes(targetUrl.hostname)) {
  throw new Error("Internal route unauthorized");
}
const externalData = await axios.get(targetUrl.href);`;
      payload_example = `http://169.254.169.254/latest/meta-data/iam/security-credentials`;
      remediation = 'Whitelist permitted destination host domains. Restrict API clients to HTTP schemas and deny localhost/link-local address scopes.';
    } else if (cweMeta.cwe === 'CWE-22') {
      vulnerable_code_snippet = `// VULNERABLE Trusting file requests
const requestedFile = req.query.filename;
const content = fs.readFileSync('/var/log/app/' + requestedFile);`;
      remediation_code_snippet = `// SECURED Base path resolution validation and sanitization
const basePath = '/var/log/app/';
const safePath = path.resolve(basePath, req.query.filename);
if (!safePath.startsWith(basePath)) {
  throw new Error("Traversal disallowed");
}
const content = fs.readFileSync(safePath);`;
      payload_example = `../../../../etc/passwd`;
      remediation = 'Always resolve the fully qualified target path and verify that it starts with the canonical base directory before performing IO.';
    } else {
      // Default Generic Cyber Case
      vulnerable_code_snippet = `// VULNERABLE Direct input execution
const inputCode = req.header('X-Compute-Payload');
const calculationVal = eval(inputCode);`;
      remediation_code_snippet = `// SECURED Safe parsing using dedicated dynamic parser JSON schema
const calculationVal = JSON.parse(req.header('X-Compute-Payload'));`;
      payload_example = `process.exit(1) // crash command`;
      remediation = 'Eliminate use of unrestricted dynamic code executors like eval(), Function(), or custom interpreters.';
    }

    const exploit_steps = [
      `Intercept incoming requests destined to the '${module}' component.`,
      `Locate user parameters linked directly to physical system operations or network requests.`,
      `Inject tailored payload vector '${payload_example}' into variable parameters.`,
      'Observe backend logging deviations, HTTP metadata anomalies, or unauthorized responses.'
    ];

    results.push({
      id: uniqueId,
      category: cweMeta.category,
      name: vulnName,
      cwe_id: cweMeta.cwe,
      severity: itemSeverity,
      environment: environment,
      technical_explanation: technicalExplanation,
      vulnerable_code_snippet,
      vulnerable_code_lang,
      payload_example,
      remediation,
      remediation_code_snippet,
      remediation_code_lang,
      exploit_steps,
      payloads: [
        {
          title: `Diagnostic Vector Challenge`,
          type: 'Basic Payload',
          payload: payload_example,
          description: `Bypasses validation layers inside the dynamic ${module} parser by using specialized characters.`
        }
      ]
    });

    counter++;
  }

  // Double check that we hit targetCount exactly
  return results.slice(0, targetCount);
}
