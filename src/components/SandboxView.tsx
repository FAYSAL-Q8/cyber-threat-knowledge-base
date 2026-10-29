import React, { useState } from 'react';
import { 
  Database, 
  Layers, 
  GitMerge, 
  ArrowRight, 
  Plus, 
  RefreshCw, 
  CheckCircle, 
  XCircle 
} from 'lucide-react';
import { Vulnerability } from '../types';

interface SandboxViewProps {
  vulnerabilitiesList: Vulnerability[];
  setVulnerabilitiesList: React.Dispatch<React.SetStateAction<Vulnerability[]>>;
  setSelectedVulnerabilityId: (id: string) => void;
  setActiveTab: (tab: 'catalog' | 'sandbox' | 'sources' | 'agent-rag') => void;
}

export default function SandboxView({
  vulnerabilitiesList,
  setVulnerabilitiesList,
  setSelectedVulnerabilityId,
  setActiveTab
}: SandboxViewProps) {
  const [newVulnName, setNewVulnName] = useState('');
  const [newVulnCategory, setNewVulnCategory] = useState<'web-api' | 'server-os' | 'cloud-security'>('web-api');
  const [newVulnExplanation, setNewVulnExplanation] = useState('');
  const [newVulnPile, setNewVulnPile] = useState('');
  const [newVulnRemediation, setNewVulnRemediation] = useState('');
  const [newVulnSeverity, setNewVulnSeverity] = useState<'Critical' | 'High' | 'Medium' | 'Low'>('Medium');

  const [sandboxChecking, setSandboxChecking] = useState(false);
  const [sandboxResult, setSandboxResult] = useState<{
    status: 'error' | 'success' | null;
    message: string;
    matchedWith?: string;
    similarityScore?: number;
    proposedAction?: string;
  }>({ status: null, message: '' });

  const handleAddNewVulnerability = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newVulnName.trim() || !newVulnExplanation.trim()) {
      alert("PLEASE COMPLETE WORKSPACE SCHEMA FIELDS: Title and Explanation are required.");
      return;
    }

    setSandboxChecking(true);
    setSandboxResult({ status: null, message: '' });

    // Simulate Cosine Similarity algorithms
    setTimeout(() => {
      const userText = (newVulnName + " " + newVulnExplanation).toLowerCase();
      
      let highestSimilarity = 0;
      let matchedVuln: Vulnerability | null = null;

      vulnerabilitiesList.forEach(existing => {
        const terms = (existing.name + " " + existing.technical_explanation).toLowerCase().split(/\W+/).filter(t => t.length > 3);
        const userTerms = userText.split(/\W+/).filter(t => t.length > 3);
        
        let intersection = 0;
        const uniqueUserTerms = Array.from(new Set(userTerms));
        const uniqueExistTerms = Array.from(new Set(terms));

        uniqueUserTerms.forEach(t => {
          if (uniqueExistTerms.includes(t)) {
            intersection++;
          }
        });

        const score = intersection / Math.sqrt(uniqueUserTerms.length * uniqueExistTerms.length || 1);
        if (score > highestSimilarity) {
          highestSimilarity = score;
          matchedVuln = existing;
        }
      });

      const formattedScore = Math.min(0.5 + highestSimilarity * 0.9, 0.98);

      // Threshold is 82% semantic equivalence. If true, block and output detail context claims.
      if (formattedScore > 0.82 && matchedVuln) {
        setSandboxResult({
          status: 'error',
          message: `REDUNDANCY BARRIER INTERRUPT: Cosine index evaluates to ${Math.round(formattedScore * 100)}% structural duplication. Our indices already possess matching documentation mapping this exact security vulnerability behavior in detail.`,
          matchedWith: matchedVuln.name,
          similarityScore: Math.round(formattedScore * 100),
          proposedAction: `Please append this custom payload variant to key folder: "${matchedVuln.name}" instead of seeding clean duplicate trees.`
        });
        setSandboxChecking(false);
      } else {
        const slug = newVulnName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
        const newEntry: Vulnerability = {
          id: slug || `custom-${Date.now()}`,
          category: newVulnCategory,
          name: newVulnName,
          cwe_id: `CWE-${Math.floor(Math.random() * 800) + 20}`,
          severity: newVulnSeverity,
          environment: newVulnCategory === 'web-api' ? 'Web API Endpoint' : newVulnCategory === 'server-os' ? 'Server OS Shell' : 'Cloud Tenant Container',
          technical_explanation: newVulnExplanation,
          vulnerable_code_snippet: newVulnPile ? newVulnPile : `// User Custom Vulnerable Showcase Code\n// Fully dynamic instance`,
          vulnerable_code_lang: 'javascript',
          payload_example: `Custom vector payload: ${newVulnName}`,
          remediation: newVulnRemediation ? newVulnRemediation : 'Inspect dynamic bounds, escape target parameters, and prevent execution path interpolation.',
          remediation_code_snippet: `// Restrict runtime context and escape parameters\n// Ensure container namespaces isolations`,
          remediation_code_lang: 'javascript',
          exploit_steps: ['Probe endpoint structures.', 'Pass variable strings to target parameter keys.', 'Analyze returned stack trace errors.']
        };

        setVulnerabilitiesList(prev => [newEntry, ...prev]);
        setSandboxResult({
          status: 'success',
          message: `INGESTION VERIFIED: Vector duplication threshold evaluates to ${Math.round(formattedScore * 100)}% Similarity (Below the 82% system limit). Vulnerability has been successfully structured and indexed into our live directory database registry.`,
          similarityScore: Math.round(formattedScore * 100)
        });

        // Reset fields
        setNewVulnName('');
        setNewVulnExplanation('');
        setNewVulnPile('');
        setNewVulnRemediation('');
        setSelectedVulnerabilityId(newEntry.id);
        setSandboxChecking(false);
      }
    }, 1200);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
      
      {/* DB SCHEMATICS / SPECIFICATION SIDEBAR */}
      <div className="lg:col-span-12 xl:col-span-5 flex flex-col gap-6">
        
        {/* PARADIGM OVERVIEW */}
        <div className="bg-black border border-white/10 p-6 flex flex-col gap-4">
          <h3 className="font-mono text-xs uppercase tracking-widest text-[#CCFF00] flex items-center gap-2 border-b border-white/5 pb-3 font-bold">
            <Database className="w-4 h-4" />
            [Paradigm Layout: Dual-Vector Store]
          </h3>
          <p className="text-zinc-405 text-xs leading-relaxed font-sans text-zinc-400">
            To achieve extremadamente fast search query speeds while enforcing zero redundant duplication, we use Cloud Firestore to record document properties coupled with Gemini embedding vectors capturing semantic concepts.
          </p>

          {/* ASCII STRUCTURAL TREE DIAGRAM */}
          <div className="bg-[#121212] border border-white/10 p-5 font-mono text-[10.5px] leading-5 text-zinc-400">
            <div className="text-white font-black text-xs border-b border-white/5 pb-2 mb-2 uppercase tracking-wide flex items-center gap-1.5 font-mono">
              <Layers className="w-3.5 h-3.5 text-[#CCFF00]" />
              Structured Collection Tree
            </div>
            
            <div className="flex items-center gap-2 text-white font-mono font-bold mt-1.5">
              <span>📁</span>
              <span>/categories</span>
              <span className="text-zinc-600">-- {`{category_id}`}</span>
            </div>
            <div className="pl-6 border-l border-white/12 flex flex-col gap-0.5 text-zinc-500">
              <div>├── <strong className="text-zinc-350">title</strong>: "Broken Access Vector"</div>
              <div>└── <strong className="text-zinc-350">description</strong>: "Uncontrolled access barriers..."</div>
            </div>

            <div className="flex items-center gap-2 text-white font-mono font-bold mt-3">
              <span>📁</span>
              <span>/vulnerabilities</span>
              <span className="text-zinc-600">-- {`{vuln_slug_id}`}</span>
            </div>
            <div className="pl-6 border-l border-white/12 flex flex-col gap-0.5 text-zinc-500">
              <div>├── <strong className="text-zinc-350">categoryRef</strong>: DocumentReference{"<categories/web-api>"}</div>
              <div>├── <strong className="text-zinc-350">name</strong>: "SQL Injection Attacks"</div>
              <div>├── <strong className="text-zinc-350">cwe_id</strong>: "CWE-89"</div>
              <div>└── <strong className="text-[#CCFF00] font-semibold">embedding</strong>: <strong className="text-white font-normal">Vector{"<float32> [768-D]"}</strong></div>
            </div>
          </div>

          {/* PROCESS CHART FLOW visualizer */}
          <div className="flex flex-col gap-2mt-2 font-mono text-xs">
            <h4 className="text-[10px] tracking-widest text-zinc-500 uppercase flex items-center gap-1.5">
              <GitMerge className="w-3.5 h-3.5 text-[#CCFF00]" />
              Redundancy Execution Trace
            </h4>
            
            <div className="p-4 bg-[#121212] border border-white/5 rounded-xl flex flex-col gap-3">
              <div className="flex items-center justify-between gap-2">
                <div className="bg-black border border-white/10 rounded-lg px-2.5 py-1.5 text-[9.5px] uppercase font-mono text-zinc-350 text-center w-1/2">
                  1. Form Input Buffer
                </div>
                <ArrowRight className="w-4 h-4 text-zinc-600 flex-shrink-0" />
                <div className="bg-black border border-white/10 rounded-lg px-2.5 py-1.5 text-[9.5px] uppercase font-mono text-[#CCFF00] text-center w-1/2">
                  2. Embed Model API
                </div>
              </div>
              
              <div className="border-t border-white/5 my-1"></div>
              
              <div className="flex items-center justify-between gap-3 text-[10px]">
                <div className="border border-red-500/10 bg-red-955/2 rounded-lg p-2 font-bold tracking-wider text-red-400 font-mono text-center w-1/2 select-none">
                  COSINE MATCH &gt; 82%?
                </div>
                <span className="text-zinc-600 text-[18px]">→</span>
                <div className="border border-[#CCFF00]/10 bg-zinc-955 rounded-lg p-2 font-bold tracking-wider text-[#CCFF00] text-center w-1/2 font-mono">
                  BLOCK DUPE / SEED
                </div>
              </div>
              <p className="text-[9.5px] text-zinc-500 leading-relaxed uppercase">
                Using cosine proximity maps stops users from seeding descriptive synonyms (e.g. &quot;inject code into dynamic query strings&quot; maps to &quot;SQL Injection&quot; and is safely merged).
              </p>
            </div>
          </div>

        </div>

        {/* EDUCATIONAL CODE */}
        <div className="bg-black border border-white/10 p-5 font-mono text-[10.5px]">
          <div className="text-zinc-500 uppercase border-b border-white/5 pb-2.5 mb-2.5 tracking-widest text-[9.5px] flex items-center justify-between">
            <span>Proposed Node.js API Seeder</span>
            <span className="text-[9px] bg-zinc-950 text-[#CCFF00] border border-zinc-900 px-1.5 py-0.2">System</span>
          </div>
          <pre className="text-zinc-400 overflow-x-auto p-3 bg-zinc-955 leading-relaxed text-[11px] font-mono select-text">
{`const { GoogleGenAI } = require("@google/genai");
const { getFirestore } = require("firebase-admin/firestore");

const ai = new GoogleGenAI();
const db = getFirestore();

async function checkAndAddWeakness(name, explanation) {
  // Generate embeddings for similarity sweep
  const res = await ai.models.embedContent({
    model: "text-embedding-004",
    contents: explanation
  });
  const vector = res.embedding.values;

  // Query database space mapping values...
}`}
          </pre>
        </div>

      </div>

      {/* FORM INPUT COMPONENT */}
      <div className="lg:col-span-12 xl:col-span-7 bg-black border border-white/10 p-6 sm:p-8 flex flex-col gap-6">
        <div>
          <h3 className="text-xl font-black tracking-tight text-white uppercase border-b border-white/5 pb-2.5 mb-2 font-display flex items-center gap-2">
            <Plus className="w-5 h-5 text-[#CCFF00]" />
            Knowledge Ingestion & Vector Guard
          </h3>
          <p className="text-zinc-450 text-xs font-mono uppercase tracking-wider text-zinc-500 leading-normal">
            Submit novel vulnerability blueprints. The pipeline generates mock text embeddings and compares them with pre-existing modules in real-time.
          </p>
        </div>

        <form onSubmit={handleAddNewVulnerability} className="flex flex-col gap-5 text-xs">
          
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            
            <div className="flex flex-col gap-2">
              <label className="font-mono text-[10px] uppercase tracking-widest text-zinc-400 font-bold">
                Vulnerability Title
              </label>
              <input
                type="text"
                required
                placeholder="e.g. Server-Side Template Injection"
                value={newVulnName}
                onChange={(e) => setNewVulnName(e.target.value)}
                className="bg-zinc-955 border border-white/10 p-3 text-white focus:outline-none focus:border-[#CCFF00] font-mono uppercase text-xs"
              />
            </div>

            <div className="flex flex-col gap-2">
              <label className="font-mono text-[10px] uppercase tracking-widest text-zinc-400 font-bold">
                Classification Space
              </label>
              <select
                value={newVulnCategory}
                onChange={(e) => setNewVulnCategory(e.target.value as any)}
                className="bg-zinc-955 border border-white/10 p-3 text-zinc-300 focus:outline-none focus:border-[#CCFF00] font-mono text-xs uppercase cursor-pointer"
              >
                <option value="web-api">WEB API APPLICATION LAYER</option>
                <option value="server-os">SERVER HARDWARE/OS SHELL</option>
                <option value="cloud-security">CLOUD CONTAINER INTEGRATION</option>
              </select>
            </div>

          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            
            <div className="flex flex-col gap-2 border-r border-white/5 pr-4">
              <label className="font-mono text-[10px] uppercase tracking-widest text-zinc-400 font-bold">
                Severity Range
              </label>
              <select
                value={newVulnSeverity}
                onChange={(e) => setNewVulnSeverity(e.target.value as any)}
                className="bg-zinc-955 border border-white/10 p-3 text-zinc-300 focus:outline-none focus:border-[#CCFF00] font-mono text-xs uppercase cursor-pointer"
              >
                <option value="Critical">CRITICAL (Direct RCE / Full System Takeover)</option>
                <option value="High">HIGH (Subnetwork Penetration / Escapes)</option>
                <option value="Medium font-bold">MEDIUM (Information Leak / Spoofing)</option>
                <option value="Low">LOW (Verbose configuration outputs)</option>
              </select>
            </div>

            {/* QUICK PRE-SET SIMULATOR DEMOS */}
            <div className="flex flex-col gap-1.5">
              <span className="font-mono text-[10px] uppercase tracking-widest text-zinc-500 font-bold">[Inject Preset Duplication Demos]</span>
              
              <div className="grid grid-cols-1 gap-1 font-mono text-[9px] mt-1">
                <button
                  type="button"
                  onClick={() => {
                    setNewVulnName("SQL Execution Query Strings injection");
                    setNewVulnExplanation("Allows attackers to inject custom malicious query strings into inputs escaping normal SQL parameters wrappers causing database context leaks.");
                  }}
                  className="bg-zinc-955 hover:bg-zinc-900 border border-white/5 hover:border-[#CCFF00] p-1.5 px-3 text-left transition-all text-[#CCFF00] uppercase"
                >
                  [Preset: SQLi Duplicate Demo]
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setNewVulnName("Cross-Site Web Elements Code Execution (XSS)");
                    setNewVulnExplanation("Injects malicious client script context inside targeted browser render outputs to retrieve session credentials cookie tokens.");
                  }}
                  className="bg-zinc-955 hover:bg-zinc-900 border border-white/5 hover:border-[#CCFF00] p-1.5 px-3 text-left transition-all text-[#CCFF00] uppercase"
                >
                  [Preset: XSS Duplicate Demo]
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setNewVulnName("Server-Side Template Engine Injection (SSTI)");
                    setNewVulnExplanation("Abuses raw template expressions inside backend compiler layers such as Jinja2 or Twig causing raw code executions in core host containers.");
                  }}
                  className="bg-zinc-955 hover:bg-zinc-900 border border-white/5 hover:border-[#CCFF00] p-1.5 px-3 text-left transition-all text-[#CCFF00] uppercase"
                >
                  [Preset: SSTI Unique Model]
                </button>
              </div>
            </div>

          </div>

          <div className="flex flex-col gap-2">
            <label className="font-mono text-[10px] uppercase tracking-widest text-zinc-400 font-bold">
              Technical Core Explanation (Processed for embeddings cosine matching)
            </label>
            <textarea
              required
              rows={3}
              placeholder="Provide a granular description of the security vulnerability..."
              value={newVulnExplanation}
              onChange={(e) => setNewVulnExplanation(e.target.value)}
              className="bg-zinc-955 border border-white/10 p-3 text-white focus:outline-none focus:border-[#CCFF00] font-sans text-xs placeholder-zinc-700 leading-relaxed resize-none"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="flex flex-col gap-2">
              <label className="font-mono text-[10px] uppercase tracking-widest text-[#CCFF00] font-bold">
                Demonstration Vulnerable Snippet (Optional)
              </label>
              <textarea
                rows={3}
                placeholder="e.g. app.post('/auth', (req, res) => { ... })"
                value={newVulnPile}
                onChange={(e) => setNewVulnPile(e.target.value)}
                className="bg-black border border-white/10 p-3 text-red-400 font-mono text-[11px] focus:outline-none focus:border-red-500 leading-normal resize-none"
              />
            </div>
            <div className="flex flex-col gap-2">
              <label className="font-mono text-[10px] uppercase tracking-widest text-[#CCFF00] font-bold">
                Secure Remediation Snippet (Optional)
              </label>
              <textarea
                rows={3}
                placeholder="e.g. Ensure parameters wrappers are used..."
                value={newVulnRemediation}
                onChange={(e) => setNewVulnRemediation(e.target.value)}
                className="bg-black border border-white/10 p-3 text-emerald-400 font-mono text-[11px] focus:outline-none focus:border-emerald-500 leading-normal resize-none"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={sandboxChecking}
            className="bg-[#CCFF00] hover:bg-[#b5e000] text-black font-black uppercase text-xs tracking-widest py-3.5 mt-2 transition-all cursor-pointer flex items-center justify-center gap-2 select-none"
          >
            {sandboxChecking ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-black" />
                Inference embedding calculation in process...
              </>
            ) : (
              <>
                [Verify Novelty & Index to Database Registry]
              </>
            )}
          </button>

        </form>

        {/* LOG TERMINAL INTERCONNECT */}
        {sandboxChecking && (
          <div className="bg-black border border-white/10 p-4 font-mono text-[10.5px] text-zinc-500 leading-6">
            <div className="text-white font-mono font-bold tracking-wider mb-1 uppercase flex items-center gap-1.5 border-b border-white/5 pb-1 select-none">
              <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#CCFF00]" />
              Embedding Trace Logs
            </div>
            <p className="text-zinc-400">├─ [TRACE] Captured text stream from workspace form buffers: &quot;{newVulnName}&quot;</p>
            <p className="text-zinc-400">├─ [TRACE] Request API model &quot;text-embedding-004&quot; coordinates.</p>
            <p className="text-zinc-400">├─ [TRACE] Embedding array loaded successfully.</p>
            <p className="text-[#CCFF00]">└─ [TRACE] Cosine index query comparison sweeping directory...</p>
          </div>
        )}

        {/* RESULT PRESENTATIONS */}
        {sandboxResult.status && (
          <div className={`p-5 border ${
            sandboxResult.status === 'success' 
              ? 'bg-[#CCFF00]/5 border-[#CCFF00]/20 text-white' 
              : 'border-red-500/10 bg-red-955/2 text-white'
          }`}>
            <div className="flex items-center gap-2.5 font-mono font-bold text-xs uppercase tracking-wider mb-2 select-none">
              {sandboxResult.status === 'success' ? (
                <CheckCircle className="w-4 h-4 text-[#CCFF00]" />
              ) : (
                <XCircle className="w-4 h-4 text-red-500" />
              )}
              <span className={sandboxResult.status === 'success' ? 'text-[#CCFF00]' : 'text-red-400'}>
                {sandboxResult.status === 'success' ? 'Ingestion Inbound Success' : 'Pipeline Collision Rejected'}
              </span>
            </div>

            <p className="text-xs text-zinc-300 leading-relaxed mb-4 filter drop-shadow select-text">
              {sandboxResult.message}
            </p>

            {sandboxResult.matchedWith && (
              <div className="bg-black border border-zinc-900 p-4 font-mono text-[11px] flex flex-col gap-2">
                <div className="flex justify-between items-center text-[10px] text-zinc-600 font-bold">
                  <span>MAX COSINE SIMILARITY COEFFICIENT:</span>
                  <span className="text-red-400 font-bold">{sandboxResult.similarityScore}%</span>
                </div>
                <div className="flex justify-between items-center text-zinc-350">
                  <span>Duplicate target mapping entry:</span>
                  <strong className="text-white bg-zinc-950 py-0.5 px-1.5 select-all">{sandboxResult.matchedWith}</strong>
                </div>
                {sandboxResult.proposedAction && (
                  <div className="border-t border-white/5 pt-2 mt-1 text-[10px] text-zinc-500 leading-normal">
                    <strong className="text-red-400 font-normal">Suggested Resolution:</strong> {sandboxResult.proposedAction}
                  </div>
                )}
              </div>
            )}

            {sandboxResult.status === 'success' && (
              <div className="bg-black border border-zinc-900 p-4 font-mono text-[11.5px] flex justify-between items-center">
                <span className="text-[10px] text-zinc-500 font-bold">HIGHEST DETECTED COLLISION METRIC:</span>
                <span className="text-[#CCFF00] font-bold font-mono">{sandboxResult.similarityScore}% (Below 82% Collision Limit. Safe)</span>
              </div>
            )}

            {sandboxResult.status === 'success' && (
              <div className="mt-4 text-right">
                <button
                  type="button"
                  onClick={() => {
                    setActiveTab('catalog');
                  }}
                  className="bg-white text-black font-mono font-bold tracking-wider text-[10px] uppercase py-2 px-4 hover:bg-[#CCFF00] transition-colors select-none"
                >
                  View Live Catalog Entry →
                </button>
              </div>
            )}

          </div>
        )}

      </div>

    </div>
  );
}
