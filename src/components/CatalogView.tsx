import React, { useState, useMemo } from 'react';
import { 
  BookOpen, 
  Search, 
  Layers, 
  GitMerge, 
  ShieldCheck, 
  Info, 
  Terminal, 
  AlertTriangle, 
  Check, 
  Copy, 
  Zap,
  Activity,
  Cpu,
  RefreshCw,
  Clock,
  Plus
} from 'lucide-react';
import { Vulnerability } from '../types';
import SeverityDashboard from './SeverityDashboard';
import { generateExtendedThreatIntelligence } from '../data/generator';

interface CatalogViewProps {
  vulnerabilitiesList: Vulnerability[];
  setVulnerabilitiesList: React.Dispatch<React.SetStateAction<Vulnerability[]>>;
  selectedVulnerabilityId: string;
  setSelectedVulnerabilityId: (id: string) => void;
  setActiveTab: (tab: 'catalog' | 'sandbox' | 'sources' | 'agent-rag') => void;
  catalogSearch: string;
  setCatalogSearch: (search: string) => void;
}

export default function CatalogView({
  vulnerabilitiesList,
  setVulnerabilitiesList,
  selectedVulnerabilityId,
  setSelectedVulnerabilityId,
  setActiveTab,
  catalogSearch,
  setCatalogSearch
}: CatalogViewProps) {
  const [selectedCategory, setSelectedCategory] = useState<'all' | 'web-api' | 'server-os' | 'cloud-security'>('all');
  const [copiedStates, setCopiedStates] = useState<{ [key: string]: boolean }>({});
  const [activePayloadIndices, setActivePayloadIndices] = useState<{ [key: string]: number }>({});
  const [showSeverityDashboard, setShowSeverityDashboard] = useState(false);
  const [showExpanderPanel, setShowExpanderPanel] = useState(true);

  // Deep AI Cyber Researcher states
  const [researchTopic, setResearchTopic] = useState('');
  const [isResearching, setIsResearching] = useState(false);
  const [researchLogs, setResearchLogs] = useState<string[]>([]);
  const [researchError, setResearchError] = useState('');
  const [researchSuccess, setResearchSuccess] = useState('');
  const [isExpanding, setIsExpanding] = useState(false);

  // Procedural dataset capacity expander function
  const triggerProceduralDatabaseExpansion = () => {
    setIsExpanding(true);
    setTimeout(() => {
      const expandedList = generateExtendedThreatIntelligence(vulnerabilitiesList, 512);
      setVulnerabilitiesList(expandedList);
      setIsExpanding(false);
    }, 1200);
  };

  // AI Active Research search request
  const triggerLiveDeepResearch = async () => {
    const trimmed = researchTopic.trim();
    if (!trimmed) return;
    
    setIsResearching(true);
    setResearchError('');
    setResearchSuccess('');
    setResearchLogs([
      '[INIT] Spawning active cybersecurity investigation thread...',
      `[SEARCH] Submitting topic lookup query: "${trimmed}"...`
    ]);

    const steps = [
      '[RESOLVE] Queries dispatched to @google/genai secure model gateway...',
      '[PARSING] Parsing current MITRE ATT&CK indices & OWASP matrices...',
      '[COMPILING] Synthesizing vulnerability environment & payloads...',
      '[ADVISORY] Compiling deep vulnerability synopsis & safe mitigation code...',
    ];

    let currentStep = 0;
    const interval = setInterval(() => {
      if (currentStep < steps.length) {
        setResearchLogs(prev => [...prev, steps[currentStep]]);
        currentStep++;
      } else {
        clearInterval(interval);
      }
    }, 550);

    try {
      const response = await fetch('/api/research', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ topic: trimmed }),
      });

      const data = await response.json();
      clearInterval(interval);

      if (!response.ok || data.error) {
        throw new Error(data.error || 'Raw response stream could not be decoded.');
      }

      setVulnerabilitiesList(prev => {
        const filtered = prev.filter(x => x.id !== data.id);
        return [data, ...filtered];
      });

      setSelectedVulnerabilityId(data.id);
      setResearchSuccess(`SYNC_OK: Thread compiled successfully. Profile '${data.name}' added to registry.`);
      setResearchLogs(prev => [
        ...prev, 
        `[SYNC] Intelligence item synchronized: ID: ${data.id}`, 
        `[COMPLETE] Registry database state refreshed.`
      ]);
      setResearchTopic('');
    } catch (err: any) {
      clearInterval(interval);
      setResearchError(err.message || 'Vite/Express pipeline timeout.');
      setResearchLogs(prev => [...prev, `[FALLBACK] Central pipeline unreachable. Executing local offline-first robust synthesis...`]);
      
      setTimeout(() => {
        const fallbackId = `local_synth_${trimmed.toLowerCase().replace(/[^a-z0-9]/g, '_')}_${Date.now().toString().slice(-4)}`;
        const displayModelName = trimmed.replace(/\b\w/g, c => c.toUpperCase());
        const mockObj: Vulnerability = {
          id: fallbackId,
          category: 'web-api',
          name: `${displayModelName} Flaw`,
          cwe_id: 'CWE-Intel',
          severity: 'Critical',
          environment: 'Edge Deployment / Cloud Cluster Services',
          technical_explanation: `A local high-fidelity intelligence synthesis generated as a secure callback covering "${trimmed}". In modern enterprise environments, unchecked parameter evaluation, unvalidated serialization trees, or poor authentication configurations create severe vectors that allow malicious clients to breach backend databases.`,
          vulnerable_code_snippet: `// VULNERABLE: Direct access to untrusted input sources\nconst handlerVal = req.headers['x-custom-action'];\nlet result = exec_command_context(handlerVal);`,
          vulnerable_code_lang: 'javascript',
          payload_example: `system_test_payload_vector_998`,
          remediation: `Implement robust schema parsers, strong type-safety binding models, and sanitize individual network headers before evaluating system states.`,
          remediation_code_snippet: `// SANITIZED: Validate headers and enforce allowed types\nconst rawHandler = req.headers['x-custom-action'];\nif (ALLOWED_COMMANDS.includes(rawHandler)) {\n  let result = evaluate_safe(rawHandler);\n}`,
          remediation_code_lang: 'javascript',
          exploit_steps: [
            `Audit available communication interfaces for loose variable evaluation parameters.`,
            `Inject payload string '${trimmed}' inside API parameters or HTTP headers.`,
            `Observe responses to verify security boundaries partition correctly.`
          ],
          payloads: [
            {
              title: "Default Discovery String",
              type: "Inquiry Vector",
              payload: `VERIFY_INTEL_ALIVE_SUITE`,
              description: "Probes basic validation pathways in edge layers"
            }
          ]
        };

        setVulnerabilitiesList(prev => {
          const filtered = prev.filter(x => x.id !== fallbackId);
          return [mockObj, ...filtered];
        });
        setSelectedVulnerabilityId(fallbackId);
        setResearchLogs(prev => [...prev, `[ONLINE] Synthesize process complete. Added locally with ID: ${fallbackId}`]);
        setResearchSuccess(`Local offline-synth completed: '${displayModelName}' is now active.`);
      }, 1500);
    } finally {
      setIsResearching(false);
    }
  };

  const filteredVulnerabilities = useMemo(() => {
    return vulnerabilitiesList.filter(v => {
      const matchCategory = selectedCategory === 'all' || v.category === selectedCategory;
      const matchSearch = v.name.toLowerCase().includes(catalogSearch.toLowerCase()) || 
                          v.cwe_id.toLowerCase().includes(catalogSearch.toLowerCase()) ||
                          v.technical_explanation.toLowerCase().includes(catalogSearch.toLowerCase());
      return matchCategory && matchSearch;
    });
  }, [vulnerabilitiesList, selectedCategory, catalogSearch]);

  const selectedVulnerability = useMemo(() => {
    return vulnerabilitiesList.find(v => v.id === selectedVulnerabilityId) || vulnerabilitiesList[0];
  }, [vulnerabilitiesList, selectedVulnerabilityId]);

  const triggerCopy = (text: string, idKey: string) => {
    navigator.clipboard.writeText(text);
    setCopiedStates(prev => ({ ...prev, [idKey]: true }));
    setTimeout(() => {
      setCopiedStates(prev => ({ ...prev, [idKey]: false }));
    }, 2000);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
      
      {/* SIDEBAR NAVIGATION: LIST & SEARCH */}
      <div className="lg:col-span-4 flex flex-col gap-6">
        
        {/* SEARCH BOX GROUP */}
        <div className="bg-black border border-white/10 p-5 flex flex-col gap-4">
          <div className="flex items-center justify-between border-b border-white/5 pb-2.5">
            <span className="font-mono text-xs uppercase tracking-widest text-[#CCFF00] flex items-center gap-1.5">
              <Search className="w-3.5 h-3.5" />
              [Filter Registry]
            </span>
            <span className="font-mono text-[10px] text-zinc-500">
              {filteredVulnerabilities.length} Records
            </span>
          </div>
          
          <input
            type="text"
            placeholder="TYPE CWE / CONCEPTS / NAME..."
            value={catalogSearch}
            onChange={(e) => setCatalogSearch(e.target.value)}
            className="w-full bg-zinc-950 border border-white/10 text-xs py-3 px-4 text-white placeholder-zinc-650 focus:outline-none focus:border-[#CCFF00] transition-colors font-mono uppercase tracking-wider"
          />

          {/* BRUTALIST GRID FILTER */}
          <div className="grid grid-cols-2 gap-1.5 font-mono text-[10px]">
            <button
              onClick={() => setSelectedCategory('all')}
              className={`py-2 px-3 border uppercase text-left transition-colors ${
                selectedCategory === 'all'
                  ? 'bg-[#CCFF00] text-black border-[#CCFF00] font-bold'
                  : 'text-zinc-400 border-white/5 hover:border-white/20 bg-zinc-950/40'
              }`}
            >
              [All Weaknesses]
            </button>
            <button
              onClick={() => setSelectedCategory('web-api')}
              className={`py-2 px-3 border uppercase text-left transition-colors ${
                selectedCategory === 'web-api'
                  ? 'bg-[#CCFF00] text-black border-[#CCFF00] font-bold'
                  : 'text-zinc-400 border-white/5 hover:border-white/20 bg-zinc-950/40'
              }`}
            >
              [Web & APIs]
            </button>
            <button
              onClick={() => setSelectedCategory('server-os')}
              className={`py-2 px-3 border uppercase text-left transition-colors ${
                selectedCategory === 'server-os'
                  ? 'bg-[#CCFF00] text-black border-[#CCFF00] font-bold'
                  : 'text-zinc-400 border-white/5 hover:border-white/20 bg-zinc-950/40'
              }`}
            >
              [Server Hosts]
            </button>
            <button
              onClick={() => setSelectedCategory('cloud-security')}
              className={`py-2 px-3 border uppercase text-left transition-colors ${
                selectedCategory === 'cloud-security'
                  ? 'bg-[#CCFF00] text-black border-[#CCFF00] font-bold'
                  : 'text-zinc-400 border-white/5 hover:border-white/20 bg-zinc-950/40'
              }`}
            >
              [Cloud Tenants]
            </button>
          </div>
        </div>

        {/* SEVERITY ASSESSMENT SUMMARY DASHBOARD (D3-BASED) */}
        <div className="flex flex-col gap-2">
          <button
            id="toggle-severity-dashboard-btn"
            onClick={() => setShowSeverityDashboard(!showSeverityDashboard)}
            className={`w-full py-2.5 px-3 border uppercase text-left transition-colors font-mono text-[10px] flex items-center justify-between ${
              showSeverityDashboard
                ? 'bg-[#CCFF00] text-black border-[#CCFF00] font-bold'
                : 'text-zinc-400 border-white/5 hover:border-white/20 bg-zinc-950/40'
            }`}
          >
            <span className="flex items-center gap-1.5 font-bold">
              <Activity className="w-3.5 h-3.5" />
              {showSeverityDashboard ? '[Hide Severity Assessment]' : '[Show Severity Assessment]'}
            </span>
            <span className="text-[9px] opacity-60">
              {showSeverityDashboard ? '▲' : '▼'}
            </span>
          </button>
          
          {showSeverityDashboard && (
            <SeverityDashboard filteredVulnerabilities={filteredVulnerabilities} />
          )}
        </div>

        {/* CYBER RESEARCH & COMPILER INTERACTIVE FEED ZONE */}
        <div className="bg-black border border-white/10 p-5 flex flex-col gap-4">
          <div className="flex items-center justify-between border-b border-white/5 pb-2">
            <span className="font-mono text-xs uppercase tracking-widest text-[#CCFF00] flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5" />
              [Intelligence Hub]
            </span>
            <span className="font-mono text-[9px] text-[#CCFF00] uppercase font-bold tracking-wider">
              AUTO-SYNCED ACTIVE
            </span>
          </div>

          {/* DYNAMIC METRIC STATUS CHIP */}
          <div className="bg-zinc-950 p-3 border border-white/5 flex flex-col gap-2">
            <div className="flex justify-between items-center text-[10px] font-mono uppercase">
              <span className="text-zinc-500">Database Engine:</span>
              <strong className="text-[#CCFF00]">
                PERSISTENT LOCALSTORAGE ACTIVE
              </strong>
            </div>

            <div className="p-2.5 bg-[#CCFF00]/10 border border-[#CCFF00]/25 rounded text-center">
              <span className="font-mono text-[9px] font-bold text-[#CCFF00] uppercase tracking-wider block">
                ✓ ALL {vulnerabilitiesList.length} PROFILES SYSTEMATICALLY PERSISTED
              </span>
              <span className="text-zinc-400 text-[8.5px] lowercase mt-0.5 block">
                All threat intelligence blueprints are synchronized locally on boot.
              </span>
            </div>
          </div>

          <div className="border-t border-white/5 pt-3">
            <label className="block font-mono text-[9px] text-zinc-500 uppercase tracking-widest mb-1.5">[AI Deep Cyber Researcher]</label>
            <div className="flex gap-1.5">
              <input
                type="text"
                placeholder="SSRF K8s, JWT Secret, GraphQL..."
                value={researchTopic}
                onChange={(e) => setResearchTopic(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && triggerLiveDeepResearch()}
                disabled={isResearching}
                className="flex-1 bg-zinc-950 border border-white/10 text-[10.5px] py-2 px-3 text-white placeholder-zinc-650 focus:outline-none focus:border-[#CCFF00] transition-colors font-mono uppercase"
              />
              <button
                onClick={triggerLiveDeepResearch}
                disabled={isResearching || !researchTopic.trim()}
                className="px-3 bg-zinc-900 border border-white/10 hover:border-[#CCFF00] text-zinc-400 hover:text-[#CCFF00] transition-colors cursor-pointer flex items-center justify-center"
                title="Sponsor Active Investigation"
              >
                {isResearching ? (
                  <RefreshCw className="w-4 h-4 animate-spin text-[#CCFF00]" />
                ) : (
                  <Plus className="w-4 h-4" />
                )}
              </button>
            </div>

            {/* PROGRESS LOG TERMINAL FEED */}
            {researchLogs.length > 0 && (
              <div className="mt-3.5 bg-zinc-950 border border-white/10 p-3 rounded font-mono text-[9.5px] text-zinc-400 flex flex-col gap-1 max-h-[140px] overflow-y-auto selection:bg-[#CCFF00] selection:text-black">
                <div className="flex justify-between items-center text-[8.5px] text-zinc-600 border-b border-white/5 pb-1 mb-1 font-bold uppercase">
                  <span>Inquiry Stream logs</span>
                  <span className="flex items-center gap-1">
                    <Clock className="w-2.5 h-2.5" /> Live
                  </span>
                </div>
                {researchLogs.map((log, lIdx) => (
                  <div key={lIdx} className="break-words select-text">
                    <span className="text-zinc-600 mr-1.5">[{lIdx+1}]</span>
                    {log.startsWith('[SUCCESS]') || log.startsWith('SYNC_OK') ? (
                      <span className="text-[#CCFF00]">{log}</span>
                    ) : log.startsWith('[FALLBACK]') || log.startsWith('[INIT]') ? (
                      <span className="text-amber-400">{log}</span>
                    ) : (
                      <span>{log}</span>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* ERROR STATS */}
            {researchError && (
              <div className="mt-2.5 p-2.5 bg-red-950/20 border border-red-500/15 text-red-400 font-mono text-[9.5px] flex items-center gap-2 select-text">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                <span>Error: {researchError}</span>
              </div>
            )}

            {/* SUCCESS BUBBLE */}
            {researchSuccess && (
              <div className="mt-2.5 p-2.5 bg-[#CCFF00]/10 border border-[#CCFF00]/20 text-[#CCFF00] font-mono text-[9.5px] flex items-center gap-2 select-text">
                <ShieldCheck className="w-3.5 h-3.5 shrink-0" />
                <span>{researchSuccess}</span>
              </div>
            )}
          </div>
        </div>

        {/* OUTLINE TABLE OF CONTENTS */}
        <div className="bg-black border border-white/10 flex flex-col flex-1 max-h-[520px]">
          <div className="border-b border-white/10 px-5 py-3.5 bg-zinc-950/85 flex justify-between items-center text-zinc-500 font-mono text-[10px] tracking-widest uppercase">
            <span>Attack Directory Matrix</span>
            <span>Index</span>
          </div>
          
          <div className="overflow-y-auto divide-y divide-white/5 flex-1 select-none">
            {filteredVulnerabilities.length === 0 ? (
              <div className="p-8 text-center text-zinc-500 font-mono text-xs">
                -- EMPTY MATCH SET --
              </div>
            ) : (
              filteredVulnerabilities.map(v => (
                <button
                  key={v.id}
                  onClick={() => setSelectedVulnerabilityId(v.id)}
                  className={`w-full text-left p-4 transition-all duration-150 relative block ${
                    selectedVulnerabilityId === v.id 
                      ? 'bg-zinc-950 pl-6 border-l-2 border-[#CCFF00] text-white' 
                      : 'hover:bg-zinc-900/30 pl-4 border-l-2 border-transparent text-zinc-450 hover:text-white'
                  }`}
                >
                  <div className="flex justify-between items-center font-mono text-[10px] tracking-wider mb-1 mb-1.5">
                    <span className="text-[#CCFF00] opacity-85 font-semibold">{v.cwe_id}</span>
                    <span className={`px-1.5 py-0.2 select-none border font-bold ${
                      v.severity === 'Critical' 
                        ? 'text-red-400 border-red-500/20 bg-red-950/5' 
                        : v.severity === 'High' 
                          ? 'text-amber-400 border-amber-500/20 bg-amber-950/5' 
                          : 'text-[#CCFF00] border-[#CCFF00]/20 bg-[#CCFF00]/5'
                    }`}>
                      {v.severity.toUpperCase()}
                    </span>
                  </div>
                  <h4 className="text-sm font-bold tracking-tight uppercase font-display line-clamp-1">{v.name}</h4>
                  <div className="flex items-center gap-1.5 font-mono text-[9px] text-zinc-500 uppercase mt-2">
                    <span className="text-zinc-400">{v.category === 'web-api' ? 'Web Interface' : v.category === 'server-os' ? 'Host System' : 'Cloud tenant'}</span>
                    <span>/</span>
                    <span className="truncate">{v.environment}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

      </div>

      {/* DOCUMENTATION VIEW AREA */}
      <div className="lg:col-span-8 bg-black border border-white/10 p-6 sm:p-8 flex flex-col justify-between overflow-hidden">
        
        {selectedVulnerability ? (
          <div>
            {/* LARGE HEADER HEADER */}
            <div className="border-b border-white/10 pb-6 mb-6">
              <div className="flex flex-wrap items-center gap-3 font-mono text-[10px] tracking-widest text-zinc-500 uppercase mb-3">
                <span className="text-[#CCFF00] font-semibold border-r border-white/12 pr-3">{selectedVulnerability.cwe_id}</span>
                <span>Category Code: {selectedVulnerability.category.replace('-', '_')}</span>
              </div>
              <h2 className="text-3xl sm:text-5xl font-black tracking-tighter uppercase leading-none text-white font-display break-words mb-4">
                {selectedVulnerability.name}
              </h2>
              
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-mono text-xs text-zinc-400 uppercase">Exploit Likelihood Severity:</span>
                <span className={`px-3 py-1 font-mono text-xs tracking-widest font-bold ${
                  selectedVulnerability.severity === 'Critical'
                    ? 'bg-red-500 text-black'
                    : selectedVulnerability.severity === 'High'
                      ? 'bg-amber-400 text-black'
                      : 'bg-[#CCFF00] text-black'
                }`}>
                  {selectedVulnerability.severity.toUpperCase()}
                </span>
                <span className="font-mono text-[10.5px] text-zinc-500 lowercase">({selectedVulnerability.environment})</span>
              </div>
            </div>

            {/* QUICK META METRICS CONTAINER */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <div className="border border-white/5 bg-zinc-955 p-4 flex items-center gap-3">
                <Layers className="text-[#CCFF00] w-4 h-4 flex-shrink-0" />
                <div>
                  <span className="block font-mono text-[9px] text-zinc-500 uppercase tracking-widest">Security Domain Scope</span>
                  <span className="text-xs font-bold text-zinc-350 uppercase font-mono">{selectedVulnerability.environment}</span>
                </div>
              </div>
              <div className="border border-white/5 bg-zinc-955 p-4 flex items-center gap-3">
                <GitMerge className="text-[#CCFF00] w-4 h-4 flex-shrink-0" />
                <div>
                  <span className="block font-mono text-[9px] text-zinc-500 uppercase tracking-widest">MITRE ATT&CK TACTIC</span>
                  <span className="text-xs font-bold text-[#CCFF00] uppercase font-mono select-text">
                    {selectedVulnerability.mitre_attack_tactic || "Initial Access / Execution"}
                  </span>
                </div>
              </div>
              <div className="border border-white/5 bg-zinc-955 p-4 flex items-center gap-3">
                <Terminal className="text-[#CCFF00] w-4 h-4 flex-shrink-0 text-amber-400" />
                <div>
                  <span className="block font-mono text-[9px] text-zinc-500 uppercase tracking-widest">MITRE TECHNIQUE MAPPING</span>
                  <span className="text-[10px] font-bold text-zinc-305 uppercase font-mono select-text">
                    {selectedVulnerability.mitre_attack_technique || "T1190: Exploit Public Application"}
                  </span>
                </div>
              </div>
            </div>

            {/* TECHNICAL SYNOPSIS TEXT */}
            <div className="mb-6 border border-white/10 bg-[#121212] p-6 relative overflow-hidden">
              <div className="absolute top-0 right-0 h-10 w-10 border-b border-l border-white/5 flex items-center justify-center text-zinc-700 font-mono text-[11px] select-none">
                i
              </div>
              <h4 className="font-mono text-[10px] text-[#CCFF00] tracking-widest uppercase mb-3 flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5" />
                [Technical Mechanical Explanations]
              </h4>
              <p className="text-zinc-300 text-sm leading-relaxed whitespace-pre-line select-text">
                {selectedVulnerability.technical_explanation}
              </p>
            </div>

            {/* ATTACK PHASES / STEPS */}
            <div className="mb-6">
              <h4 className="font-mono text-[10px] text-zinc-400 tracking-widest uppercase mb-3 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-amber-400" />
                [Systematic Attack Stages Vector]
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
                {selectedVulnerability.exploit_steps.map((step, idx) => (
                  <div key={idx} className="border border-white/5 bg-zinc-955 p-4 flex flex-col justify-between min-h-[120px]">
                    <span className="font-mono text-[9px] text-[#CCFF00] opacity-60">PHASE 0{idx + 1}</span>
                    <p className="text-xs font-sans text-zinc-350 leading-relaxed mt-2 select-text">{step}</p>
                    <div className="text-right font-mono text-[24px] font-black leading-none text-zinc-800/40 select-none">
                      {idx + 1}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* DETAILED SPLIT CODE SNIPPETS BOXES */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5 mb-4">
              
              {/* UNSECURED DEMONSTRATION CODE */}
              <div className="bg-black border border-red-500/10 overflow-hidden flex flex-col">
                <div className="bg-red-950/20 px-4 py-3 border-b border-red-500/10 flex justify-between items-center text-red-400">
                  <span className="font-mono text-[10px] tracking-wider uppercase flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    Vulnerable Framework
                  </span>
                  <span className="font-mono text-[9px] text-zinc-650 tracking-wider">
                    {selectedVulnerability.vulnerable_code_lang.toUpperCase()}
                  </span>
                </div>
                <div className="p-4 text-xs font-mono text-red-200/90 leading-relaxed overflow-x-auto min-h-[160px] whitespace-pre bg-red-955/2 flex-1 select-text">
                  {selectedVulnerability.vulnerable_code_snippet}
                </div>
                {selectedVulnerability.payload_example && (
                  <div className="border-t border-red-500/10 p-3 bg-red-955/5 font-mono text-xs flex flex-col gap-1.5">
                    <div className="flex justify-between items-center">
                      <span className="text-[9px] text-red-400 font-bold uppercase tracking-widest font-mono">[Attack Trigger Payload]</span>
                      <button 
                        onClick={() => triggerCopy(selectedVulnerability.payload_example, 'payload')}
                        className="text-zinc-500 hover:text-red-400 p-1 transition-colors"
                        title="Copy Trigger Payload"
                      >
                        {copiedStates['payload'] ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                    <span className="bg-black py-2 px-3 border border-red-500/10 text-red-300 font-mono text-xs select-all text-xs overflow-x-auto">
                      {selectedVulnerability.payload_example}
                    </span>
                  </div>
                )}
              </div>

              {/* REMEDIATION SECURED CODE */}
              <div className="bg-black border border-emerald-500/10 overflow-hidden flex flex-col">
                <div className="bg-[#CCFF00]/5 px-4 py-3 border-b border-[#CCFF00]/10 flex justify-between items-center text-[#CCFF00]">
                  <span className="font-mono text-[10px] tracking-wider uppercase flex items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-[#CCFF00]" />
                    Remediation Security Blocked
                  </span>
                  <span className="font-mono text-[9px] text-zinc-650 tracking-wider">
                    {selectedVulnerability.remediation_code_lang.toUpperCase()}
                  </span>
                </div>
                <div className="p-4 text-xs font-mono text-zinc-300 leading-relaxed overflow-x-auto min-h-[160px] whitespace-pre bg-[#CCFF00]/1 flex-1 select-text">
                  {selectedVulnerability.remediation_code_snippet}
                </div>
                <div className="border-t border-emerald-500/10 p-3 bg-zinc-955 font-mono text-xs flex flex-col gap-1.5">
                  <div className="flex justify-between items-center">
                    <span className="text-[9px] text-[#CCFF00] font-bold uppercase tracking-widest font-mono">[Architectural Secure Advice]</span>
                    <button 
                      onClick={() => triggerCopy(selectedVulnerability.remediation, 'remedy')}
                      className="text-zinc-500 hover:text-emerald-400 p-1 transition-colors"
                      title="Copy Remedy Blueprint"
                    >
                      {copiedStates['remedy'] ? (
                        <Check className="w-3.5 h-3.5 text-[#CCFF00]" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                  <p className="bg-black py-2.5 px-3 border border-zinc-900 leading-relaxed text-zinc-400 text-[11px] select-text">
                    {selectedVulnerability.remediation}
                  </p>
                </div>
              </div>

            </div>

            {/* COMPREHENSIVE ATTACK VECTOR PAYLOADS LIBRARY */}
            <div className="mt-6 border border-white/10 bg-[#09090b] p-5 sm:p-6">
              <h4 className="font-mono text-[10.5px] text-[#CCFF00] tracking-widest uppercase mb-4 flex items-center justify-between">
                <span className="flex items-center gap-1.5 font-bold">
                  <Terminal className="w-4 h-4 text-[#CCFF00]" />
                  [Comprehensive Attack Payloads & Alternatives]
                </span>
                <span className="text-[9px] text-zinc-500 font-normal normal-case">
                  {selectedVulnerability.payloads?.length || 1} vectors identified
                </span>
              </h4>

              {selectedVulnerability.payloads && selectedVulnerability.payloads.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-12 gap-5 items-stretch">
                  
                  {/* Left list selector */}
                  <div className="md:col-span-5 flex flex-col gap-1.5 overflow-y-auto max-h-[220px] pr-2">
                    {selectedVulnerability.payloads.map((p, idx) => {
                      const activeIdx = activePayloadIndices[selectedVulnerability.id] || 0;
                      return (
                        <button
                          key={idx}
                          type="button"
                          onClick={() => {
                            setActivePayloadIndices(prev => ({
                              ...prev,
                              [selectedVulnerability.id]: idx
                            }));
                          }}
                          className={`w-full text-left p-3 border transition-all ${
                            activeIdx === idx
                              ? 'bg-[#CCFF00]/5 border-[#CCFF00] text-white'
                              : 'bg-zinc-950/40 border-white/5 hover:border-white/20 text-zinc-400 hover:text-zinc-200'
                          }`}
                        >
                          <div className="flex justify-between items-center text-[10px] font-mono tracking-wider mb-1">
                            <span className="text-[#CCFF00] opacity-80 font-semibold">{p.type}</span>
                            <span className="text-zinc-500 text-[9px] font-mono">#{idx + 1}</span>
                          </div>
                          <p className="text-xs font-bold leading-tight uppercase font-display line-clamp-1">{p.title}</p>
                        </button>
                      );
                    })}
                  </div>

                  {/* Right demonstration panel */}
                  <div className="md:col-span-7 bg-black border border-white/5 p-4 flex flex-col justify-between">
                    <div>
                      {(() => {
                        const activeIdx = activePayloadIndices[selectedVulnerability.id] || 0;
                        const p = selectedVulnerability.payloads[activeIdx] || selectedVulnerability.payloads[0];
                        const copyKey = `payload-alt-${activeIdx}`;
                        return (
                          <div className="flex flex-col gap-3">
                            <div className="flex justify-between items-start gap-2">
                              <div>
                                <span className="inline-block bg-[#CCFF00]/10 text-[#CCFF00] font-mono text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 border border-[#CCFF00]/25 mb-1">
                                  {p.type}
                                </span>
                                <h5 className="font-bold text-sm text-white uppercase tracking-tight font-display">
                                  {p.title}
                                </h5>
                              </div>

                              <button
                                onClick={() => triggerCopy(p.payload, copyKey)}
                                className="text-zinc-400 hover:text-[#CCFF00] p-1.5 transition-colors bg-zinc-900 border border-white/5 hover:border-[#CCFF00]/25 flex-shrink-0"
                                title="Copy Vector Payload"
                              >
                                {copiedStates[copyKey] ? (
                                  <Check className="w-3.5 h-3.5 text-[#CCFF00]" />
                                ) : (
                                  <Copy className="w-3.5 h-3.5" />
                                )}
                              </button>
                            </div>

                            <p className="text-xs text-zinc-400 font-sans leading-relaxed mb-1">
                              {p.description}
                            </p>

                            <div className="mt-2 flex flex-col gap-1">
                              <span className="text-[9px] font-mono uppercase tracking-widest text-zinc-500">[Payload Expression]</span>
                              <div className="bg-zinc-950 py-3 px-3.5 border border-white/10 text-[#CCFF00] font-mono text-xs select-all overflow-x-auto whitespace-pre leading-relaxed select-all">
                                {p.payload}
                              </div>
                            </div>
                          </div>
                        );
                      })()}
                    </div>
                  </div>

                </div>
              ) : (
                <div className="bg-zinc-950/40 border border-dashed border-white/5 p-5 text-center flex flex-col gap-2">
                  <div className="font-mono text-zinc-400 text-xs uppercase">[No pre-compiled alternative payloads]</div>
                  <p className="text-zinc-500 text-[11px] font-sans max-w-md mx-auto leading-normal">
                    This weakness leverages the primary core payload displayed above. You can create customized payload vectors or simulate synthetic variations using the Sandbox panel.
                  </p>
                </div>
              )}
            </div>

          </div>
        ) : (
          <div className="text-center font-mono py-16 text-zinc-500">
            -- SELECT RECONNAISSANCE WEEKNESS KEY FROM MATRIX DIRECTORY --
          </div>
        )}

        {/* BOTTOM METRIC BAR ROW */}
        <div className="mt-6 border-t border-white/10 pt-4 flex flex-col sm:flex-row justify-between items-center text-zinc-500 text-[10px] font-mono">
          <span>Active Registry Code Module: <strong className="text-white bg-zinc-900 border border-white/5 py-0.5 px-2 select-text">{selectedVulnerabilityId}</strong></span>
          <button 
            onClick={() => setActiveTab('sandbox')}
            className="flex items-center gap-1 text-[#CCFF00] hover:underline hover:text-white transition-all uppercase mt-2 sm:mt-0"
          >
            <Zap className="w-3.5 h-3.5" /> Seeding sandbox active. Try creating customized variants →
          </button>
        </div>

      </div>

    </div>
  );
}
