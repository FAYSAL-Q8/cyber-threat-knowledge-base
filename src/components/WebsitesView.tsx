import React, { useState } from 'react';
import { 
  Globe, Plus, Trash2, Edit3, HelpCircle, Layers, Check, 
  Search, ExternalLink, Anchor, Clipboard, AlertCircle, Save, X, RotateCcw
} from 'lucide-react';
import { Vulnerability, TargetWebsite, ReusableProfile } from '../types';

interface WebsitesViewProps {
  vulnerabilitiesList: Vulnerability[];
}

// Pre-populate some initial vulnerable websites/environments for testing
const INITIAL_WEBSITES: TargetWebsite[] = [
  {
    id: 'site-1',
    name: 'Apollo Alpha Portal',
    group: 'Staging / QA Labs',
    url: 'https://staging.apollo-labs.internal/login',
    inputs: ['X-Forwarded-For Header', 'Authorization Bearer Token'],
    outcomes: ['302 Redirect Bypass to host node metrics', 'Information leak on backend serialization'],
    vulnerabilitiesFound: ['sqli', 'csrf'],
    notes: 'Configured on isolated Kubernetes QA cluster. Needs immediate patch revision.',
    updatedAt: '2026-05-29'
  },
  {
    id: 'site-2',
    name: 'Corporate Payroll Dispatcher',
    group: 'Financial Infrastructure',
    url: 'https://payroll-external.corp.secure/api/v1/dispatch',
    inputs: ['JSON Query payload parameters', 'Session Cookie auth'],
    outcomes: ['BOLA / IDOR sensitive details exposure', 'Double billing request replay vulnerability'],
    vulnerabilitiesFound: ['bola', 'dos'],
    notes: 'High urgency audit ticket assigned during external Red Team engagement.',
    updatedAt: '2026-05-30'
  },
  {
    id: 'site-3',
    name: 'AI Agent Storage Cluster',
    group: 'Production Backends',
    url: 'https://storage-agent.prod.ai-gateway.io/v2/embeddings',
    inputs: ['Custom file payload upload', 'User IP forwarding headers'],
    outcomes: ['SSRF container local metadata exposure', 'Local path traversal reading credentials'],
    vulnerabilitiesFound: ['ssrf', 'lfi'],
    notes: 'Protected with dynamic authorization but suffers from blind SSRF on the document indexing routine.',
    updatedAt: '2026-05-30'
  }
];

// Pre-seeded reusable configuration templates (Inputs and outcomes) for easy reuse
const DEFAULT_REUSABLE_PROFILES: ReusableProfile[] = [
  {
    id: 'profile-sqli',
    name: 'Typical SQL Injection Spec',
    inputs: ['"Query string parameters"', '"POST payload inputs"', '"X-Search-Context HTTP header"'],
    outcomes: ['"Standard SELECT database records leak"', '"Blind boolean database query delay trigger"']
  },
  {
    id: 'profile-session',
    name: 'Session Authorization Bypass',
    inputs: ['"Bearer Token JSON structures"', '"Custom Base64 cookie hashes"'],
    outcomes: ['"Session hijacking via token replay"', '"Bypass authentication to access administrator console"']
  },
  {
    id: 'profile-ssrf-metadata',
    name: 'Metadata Endpoint SSRF Probe',
    inputs: ['"Target URL link parameter"', '"X-Forwarded-Host custom overrides"'],
    outcomes: ['"Extraction of GCP / AWS local token descriptors"', '"Internal network scan finding open port endpoints"']
  },
  {
    id: 'profile-traversal',
    name: 'Local Directory Traversal Check',
    inputs: ['"File location paths URL"', '"Language locale lookup argument"'],
    outcomes: ['"Local File Inclusion of sensitive OS config files"', '"Null-byte injection bypassing suffix extensions"']
  }
];

export default function WebsitesView({ vulnerabilitiesList }: WebsitesViewProps) {
  const [websites, setWebsites] = useState<TargetWebsite[]>(INITIAL_WEBSITES);
  const [profiles, setProfiles] = useState<ReusableProfile[]>(DEFAULT_REUSABLE_PROFILES);
  
  // Filtering & Search states
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedGroupFilter, setSelectedGroupFilter] = useState('ALL');

  // New Website form states
  const [isAddingNew, setIsAddingNew] = useState(false);
  const [editingSiteId, setEditingSiteId] = useState<string | null>(null);

  // Form Fields
  const [formName, setFormName] = useState('');
  const [formGroup, setFormGroup] = useState('');
  const [formUrl, setFormUrl] = useState('');
  const [formNotes, setFormNotes] = useState('');
  const [formInputs, setFormInputs] = useState<string[]>([]);
  const [formOutcomes, setFormOutcomes] = useState<string[]>([]);
  const [formVulnerabilities, setFormVulnerabilities] = useState<string[]>([]);

  // Temporary item inputs for adding to arrays
  const [tempInput, setTempInput] = useState('');
  const [tempOutcome, setTempOutcome] = useState('');

  // Reusable profiles creator
  const [isCreatingProfile, setIsCreatingProfile] = useState(false);
  const [profileName, setProfileName] = useState('');
  const [profileInputs, setProfileInputs] = useState<string[]>([]);
  const [profileOutcomes, setProfileOutcomes] = useState<string[]>([]);
  const [tempProfInput, setTempProfInput] = useState('');
  const [tempProfOutcome, setTempProfOutcome] = useState('');

  // Get distinct group list for filter
  const groupOptions = ['ALL', ...Array.from(new Set(websites.map(w => w.group).filter(Boolean)))];

  // Helper mapping vulnerability ID to full Vulnerability name
  const getVulnName = (id: string): string => {
    const found = vulnerabilitiesList.find(v => v.id === id);
    return found ? `${found.name} (${found.cwe_id})` : id.toUpperCase();
  };

  // Helper mapping vulnerability ID to severity color
  const getVulnSeverityBadge = (id: string) => {
    const found = vulnerabilitiesList.find(v => v.id === id);
    const severity = found ? found.severity : 'Medium';
    if (severity === 'Critical') return 'bg-red-950/40 text-red-400 border border-red-500/30';
    if (severity === 'High') return 'bg-orange-950/40 text-orange-400 border border-orange-500/20';
    if (severity === 'Medium') return 'bg-amber-950/40 text-amber-400 border border-amber-500/25';
    return 'bg-zinc-900 border border-white/10 text-zinc-400';
  };

  // Profile reuse selector callback
  const applyProfileToForm = (profile: ReusableProfile) => {
    setFormInputs(prev => Array.from(new Set([...prev, ...profile.inputs])));
    setFormOutcomes(prev => Array.from(new Set([...prev, ...profile.outcomes])));
  };

  // Add Item to dynamic arrays
  const addFormInput = () => {
    if (tempInput.trim()) {
      setFormInputs(prev => Array.from(new Set([...prev, tempInput.trim()])));
      setTempInput('');
    }
  };

  const addFormOutcome = () => {
    if (tempOutcome.trim()) {
      setFormOutcomes(prev => Array.from(new Set([...prev, tempOutcome.trim()])));
      setTempOutcome('');
    }
  };

  // Vulnerability selection list tracker
  const toggleFormVulnerability = (id: string) => {
    setFormVulnerabilities(prev => 
      prev.includes(id) ? prev.filter(v => v !== id) : [...prev, id]
    );
  };

  // Save Website handler
  const saveWebsite = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formName.trim() || !formUrl.trim()) return;

    const groupVal = formGroup.trim() || 'Uncategorized';

    if (editingSiteId) {
      // Edit mode
      setWebsites(prev => prev.map(site => {
        if (site.id === editingSiteId) {
          return {
            ...site,
            name: formName.trim(),
            group: groupVal,
            url: formUrl.trim(),
            notes: formNotes.trim(),
            inputs: formInputs,
            outcomes: formOutcomes,
            vulnerabilitiesFound: formVulnerabilities,
            updatedAt: new Date().toISOString().split('T')[0]
          };
        }
        return site;
      }));
      setEditingSiteId(null);
    } else {
      // Create mode
      const newSite: TargetWebsite = {
        id: `site_custom_${Date.now()}`,
        name: formName.trim(),
        group: groupVal,
        url: formUrl.trim(),
        notes: formNotes.trim(),
        inputs: formInputs.length > 0 ? formInputs : ['Standard GET parameter values'],
        outcomes: formOutcomes.length > 0 ? formOutcomes : ['Telemetry audit verify'],
        vulnerabilitiesFound: formVulnerabilities,
        updatedAt: new Date().toISOString().split('T')[0]
      };
      setWebsites(prev => [newSite, ...prev]);
      setIsAddingNew(false);
    }

    // Reset standard state
    clearForm();
  };

  const startEdit = (site: TargetWebsite) => {
    setEditingSiteId(site.id);
    setFormName(site.name);
    setFormGroup(site.group);
    setFormUrl(site.url);
    setFormNotes(site.notes);
    setFormInputs(site.inputs);
    setFormOutcomes(site.outcomes);
    setFormVulnerabilities(site.vulnerabilitiesFound);
    setIsAddingNew(true);
  };

  const clearForm = () => {
    setFormName('');
    setFormGroup('');
    setFormUrl('');
    setFormNotes('');
    setFormInputs([]);
    setFormOutcomes([]);
    setFormVulnerabilities([]);
    setTempInput('');
    setTempOutcome('');
  };

  const deleteSite = (id: string) => {
    if (window.confirm('Confirm delete this vulnerable website profile?')) {
      setWebsites(prev => prev.filter(site => site.id !== id));
    }
  };

  // Reusable profile addition code
  const saveProfile = () => {
    if (!profileName.trim()) return;
    const newProf: ReusableProfile = {
      id: `profile_custom_${Date.now()}`,
      name: profileName.trim(),
      inputs: profileInputs.length > 0 ? profileInputs : ['Default Header Token Parameters'],
      outcomes: profileOutcomes.length > 0 ? profileOutcomes : ['Information leak or session hijacking']
    };
    setProfiles(prev => [newProf, ...prev]);
    setProfileName('');
    setProfileInputs([]);
    setProfileOutcomes([]);
    setIsCreatingProfile(false);
  };

  const addProfileInput = () => {
    if (tempProfInput.trim()) {
      setProfileInputs(prev => Array.from(new Set([...prev, tempProfInput.trim()])));
      setTempProfInput('');
    }
  };

  const addProfileOutcome = () => {
    if (tempProfOutcome.trim()) {
      setProfileOutcomes(prev => Array.from(new Set([...prev, tempProfOutcome.trim()])));
      setTempProfOutcome('');
    }
  };

  // Filter sites on search & group filter
  const filteredWebsites = websites.filter(site => {
    const matchesSearch = 
      site.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      site.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
      site.notes.toLowerCase().includes(searchQuery.toLowerCase());
    
    if (selectedGroupFilter === 'ALL') return matchesSearch;
    return matchesSearch && site.group === selectedGroupFilter;
  });

  return (
    <div className="max-w-7xl mx-auto px-4 py-4 animate-fade-in font-sans flex flex-col gap-8">
      
      {/* SECTION BANNER HERO */}
      <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-white/10 pb-5 gap-4">
        <div>
          <div className="flex items-center gap-2 text-[#CCFF00] font-mono text-[10px] uppercase tracking-wider mb-2">
            <Globe className="w-3.5 h-3.5" />
            <span>Target Vulnerable Hosts Ledger</span>
          </div>
          <h1 className="text-2xl font-black text-white uppercase tracking-tight font-display">
            Vulnerable Websites Directory
          </h1>
          <p className="text-xs text-zinc-400 mt-1 select-text">
            Log targets, cluster vulnerabilities found, and reuse predefined input matrices or outcomes.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              clearForm();
              setEditingSiteId(null);
              setIsAddingNew(!isAddingNew);
            }}
            className="px-4 py-3 bg-[#CCFF00] hover:bg-[#b0db00] text-black font-semibold text-xs font-mono uppercase tracking-wider transition-all duration-150 cursor-pointer flex items-center gap-2 rounded-xl"
          >
            {isAddingNew && !editingSiteId ? (
              <>
                <X className="w-3.5 h-3.5" />
                Close Creator
              </>
            ) : (
              <>
                <Plus className="w-3.5 h-3.5 stroke-[3]" />
                Add Website Target
              </>
            )}
          </button>
        </div>
      </div>

      {/* COMPACT INPUT FORM FOR CREATION OR EDIT */}
      {isAddingNew && (
        <form onSubmit={saveWebsite} className="bg-black/90 border-2 border-[#CCFF00]/30 p-6 rounded-2xl flex flex-col gap-6 animate-fade-in shadow-2xl">
          <div className="flex justify-between items-center border-b border-white/5 pb-3">
            <h3 className="font-mono text-xs uppercase font-bold text-[#CCFF00] flex items-center gap-2">
              <Anchor className="w-4 h-4" />
              {editingSiteId ? `[EDIT Target: ${formName}]` : '[REGISTER NEW VULNERABLE SYSTEM CLIENT]'}
            </h3>
            <button
              type="button"
              onClick={() => {
                setIsAddingNew(false);
                setEditingSiteId(null);
                clearForm();
              }}
              className="text-zinc-400 hover:text-white font-mono text-[10px] uppercase"
            >
              [Cancel]
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {/* Field 1: Name */}
            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase text-zinc-400">Target Display Identifier *</label>
              <input
                type="text"
                required
                placeholder="e.g. Apollo Portal Beta"
                value={formName}
                onChange={e => setFormName(e.target.value)}
                className="bg-zinc-950 border border-white/10 text-xs px-3.5 py-2.5 text-white focus:outline-none focus:border-[#CCFF00] rounded-lg"
              />
            </div>

            {/* Field 2: Group (For grouping websites) */}
            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase text-zinc-400">Cyber Group Allocation</label>
              <input
                type="text"
                placeholder="e.g. Staging / QA Labs OR Finance Hub"
                value={formGroup}
                onChange={e => setFormGroup(e.target.value)}
                className="bg-zinc-950 border border-white/10 text-xs px-3.5 py-2.5 text-white focus:outline-none focus:border-[#CCFF00] rounded-lg"
                list="group-presets"
              />
              <datalist id="group-presets">
                {websites.map((w, idx) => w.group && <option key={idx} value={w.group} />)}
              </datalist>
            </div>

            {/* Field 3: URL */}
            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] font-mono uppercase text-zinc-400">Target Host Endpoint URL *</label>
              <input
                type="url"
                required
                placeholder="https://staging.domain.internal/endpoint"
                value={formUrl}
                onChange={e => setFormUrl(e.target.value)}
                className="bg-zinc-950 border border-white/10 text-xs px-3.5 py-2.5 text-white focus:outline-none focus:border-[#CCFF00] rounded-lg font-mono"
              />
            </div>
          </div>

          {/* TEMPLATE REUSABILITY PANEL */}
          <div className="border border-white/10 bg-zinc-950/80 p-4 rounded-xl flex flex-col gap-3">
            <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2 border-b border-white/5 pb-2">
              <div>
                <h4 className="text-[10px] font-mono text-[#CCFF00] uppercase tracking-wider font-bold">
                  ✓ Reusable Parameter Profiles
                </h4>
                <p className="text-[9.5px] text-zinc-500 mt-0.5">
                  Inputs and outcomes can be similar to other targets. Click a profile template to append presets instantly.
                </p>
              </div>

              <button
                type="button"
                onClick={() => setIsCreatingProfile(!isCreatingProfile)}
                className="text-[9px] font-mono text-zinc-350 hover:text-[#CCFF00] uppercase border border-white/10 px-2 py-1 bg-black hover:bg-zinc-900"
              >
                {isCreatingProfile ? '[Close Template Editor]' : '[+ Save New Template]'}
              </button>
            </div>

            {/* PROFILE LIST */}
            <div className="flex flex-wrap gap-2">
              {profiles.map(prof => (
                <button
                  key={prof.id}
                  type="button"
                  onClick={() => applyProfileToForm(prof)}
                  className="px-2.5 py-1.5 bg-black hover:bg-zinc-900 border border-white/10 hover:border-[#CCFF00]/40 rounded text-[10px] text-zinc-300 font-mono transition-all text-left flex flex-col gap-0.5 cursor-pointer"
                  title="Click to apply these inputs & outcomes to form"
                >
                  <strong className="text-white text-[9px] text-[#CCFF00]/80">{prof.name}</strong>
                  <span className="text-zinc-500 text-[8.5px] truncate max-w-[190px]">
                    In: {prof.inputs.length} | Out: {prof.outcomes.length}
                  </span>
                </button>
              ))}
            </div>

            {/* CREATE REUSABLE PROFILE ON THE FLY */}
            {isCreatingProfile && (
              <div className="mt-2 bg-black border border-[#CCFF00]/15 p-4 rounded-md flex flex-col gap-3">
                <span className="text-[9.5px] font-mono font-bold text-[#CCFF00] uppercase block">
                  New Template Definition
                </span>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="flex flex-col gap-1">
                    <span className="text-[8.5px] font-mono text-zinc-500">Template Title</span>
                    <input
                      type="text"
                      placeholder="e.g. CSRF Token Param Suite"
                      value={profileName}
                      onChange={e => setProfileName(e.target.value)}
                      className="bg-zinc-950 border border-white/10 text-xs py-1 px-2.5 text-zinc-300"
                    />
                  </div>

                  <div className="flex flex-col gap-1">
                    <span className="text-[8.5px] font-mono text-zinc-500">Input parameter preset</span>
                    <div className="flex gap-1">
                      <input
                        type="text"
                        placeholder="e.g. CSRFToken Cookie Header"
                        value={tempProfInput}
                        onChange={e => setTempProfInput(e.target.value)}
                        className="bg-zinc-950 border border-white/10 text-xs py-1 px-2.5 text-zinc-300 flex-1"
                      />
                      <button
                        type="button"
                        onClick={addProfileInput}
                        className="bg-zinc-800 text-white text-xs px-2"
                      >
                        +
                      </button>
                    </div>
                    {profileInputs.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {profileInputs.map((pi, idx) => (
                          <span key={idx} className="text-[8px] bg-zinc-900 border border-zinc-800 text-zinc-400 px-1 py-0.5 truncate max-w-[120px]">{pi}</span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="flex flex-col gap-1">
                    <span className="text-[8.5px] font-mono text-zinc-500">System outcome expectation</span>
                    <div className="flex gap-1">
                      <input
                        type="text"
                        placeholder="e.g. Actions executed on behalf of client"
                        value={tempProfOutcome}
                        onChange={e => setTempProfOutcome(e.target.value)}
                        className="bg-zinc-950 border border-white/10 text-xs py-1 px-2.5 text-zinc-300 flex-1"
                      />
                      <button
                        type="button"
                        onClick={addProfileOutcome}
                        className="bg-zinc-800 text-white text-xs px-2"
                      >
                        +
                      </button>
                    </div>
                    {profileOutcomes.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {profileOutcomes.map((po, idx) => (
                          <span key={idx} className="text-[8px] bg-zinc-900 border border-zinc-800 text-[#CCFF00] px-1 py-0.5 truncate max-w-[120px]">{po}</span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setIsCreatingProfile(false)}
                    className="text-[9px] font-mono text-zinc-400 bg-zinc-900 border border-zinc-800 px-2 py-1"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={saveProfile}
                    className="text-[9px] font-mono text-black bg-[#CCFF00] px-3 py-1 font-bold"
                  >
                    Save Preset Template
                  </button>
                </div>
              </div>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Left: Inputs & Outcomes arrays on current form */}
            <div className="flex flex-col gap-4">
              {/* INPUTS SUB FORM */}
              <div className="border border-white/10 p-4 bg-zinc-950 rounded-xl flex flex-col gap-2">
                <span className="text-[10px] font-mono uppercase text-[#CCFF00]">
                  Target Testing Inputs / Parameters
                </span>
                
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="e.g. Bearer JWT authorization parameter"
                    value={tempInput}
                    onChange={e => setTempInput(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && (e.preventDefault(), addFormInput())}
                    className="bg-zinc-900 border border-white/10 text-xs px-3.5 py-2 text-white flex-1"
                  />
                  <button
                    type="button"
                    onClick={addFormInput}
                    className="px-3.5 bg-zinc-800 hover:bg-zinc-750 text-white font-mono text-xs uppercase cursor-pointer"
                  >
                    + Bind Input
                  </button>
                </div>

                {formInputs.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {formInputs.map((itm, idx) => (
                      <span 
                        key={idx} 
                        className="text-[10px] bg-zinc-900 text-zinc-300 border border-white/5 py-1 px-2.5 rounded flex items-center gap-1.5 select-text"
                      >
                        {itm}
                        <button 
                          type="button" 
                          onClick={() => setFormInputs(prev => prev.filter((_, i) => i !== idx))}
                          className="text-red-500 hover:text-red-400 font-bold ml-1"
                        >
                          ×
                        </button>
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-[9.5px] text-zinc-500 italic">No custom web variables registered. Preset template defaults will represent.</span>
                )}
              </div>

              {/* OUTCOMES SUB FORM */}
              <div className="border border-white/10 p-4 bg-zinc-950 rounded-xl flex flex-col gap-2">
                <span className="text-[10px] font-mono uppercase text-[#CCFF00]">
                  Discovered Vulnerable System Outcomes
                </span>
                
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="e.g. Remote code orchestration triggered on cluster"
                    value={tempOutcome}
                    onChange={e => setTempOutcome(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && (e.preventDefault(), addFormOutcome())}
                    className="bg-zinc-900 border border-white/10 text-xs px-3.5 py-2 text-white flex-1"
                  />
                  <button
                    type="button"
                    onClick={addFormOutcome}
                    className="px-3.5 bg-zinc-800 hover:bg-zinc-750 text-white font-mono text-xs uppercase cursor-pointer"
                  >
                    + Bind Outcome
                  </button>
                </div>

                {formOutcomes.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {formOutcomes.map((itm, idx) => (
                      <span 
                        key={idx} 
                        className="text-[10px] bg-zinc-900 text-[#CCFF00]/80 border border-white/5 py-1 px-2.5 rounded flex items-center gap-1.5 select-text"
                      >
                        {itm}
                        <button 
                          type="button" 
                          onClick={() => setFormOutcomes(prev => prev.filter((_, i) => i !== idx))}
                          className="text-red-500 hover:text-red-400 font-bold ml-1"
                        >
                          ×
                        </button>
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-[9.5px] text-zinc-500 italic">No outcome matrices configured yet. Apply a template preset above.</span>
                )}
              </div>
            </div>

            {/* Right: Select Associated Vulnerabilities */}
            <div className="border border-white/10 p-4 bg-zinc-950 rounded-xl flex flex-col gap-3">
              <div className="flex justify-between items-center border-b border-white/5 pb-1.5">
                <span className="text-[10px] font-mono uppercase text-[#CCFF00]">
                  Link Founded Cyber Vulnerabilities ({formVulnerabilities.length} Selected)
                </span>
                <span className="text-[9px] text-zinc-500">
                  Matches Attack Catalog Entries
                </span>
              </div>

              {/* FILTERING SCROLL ZONE FOR VULNS */}
              <div className="flex flex-col gap-1 max-h-[190px] overflow-y-auto pr-1">
                {vulnerabilitiesList.slice(0, 48).map(v => {
                  const isChecked = formVulnerabilities.includes(v.id);
                  return (
                    <button
                      key={v.id}
                      type="button"
                      onClick={() => toggleFormVulnerability(v.id)}
                      className={`w-full flex items-center justify-between p-2 text-left font-mono text-[10px] uppercase border transition-all ${
                        isChecked 
                          ? 'bg-[#CCFF00]/10 border-[#CCFF00]/30 text-white' 
                          : 'bg-black border-white/5 text-zinc-400 hover:text-white hover:border-zinc-700'
                      }`}
                    >
                      <div className="flex items-center gap-2 truncate">
                        <div className={`w-3.5 h-3.5 border flex items-center justify-center ${isChecked ? 'border-[#CCFF00] bg-[#CCFF00] text-black' : 'border-zinc-650'}`}>
                          {isChecked && <Check className="w-2.5 h-2.5 stroke-[3]" />}
                        </div>
                        <span className="truncate">{v.name}</span>
                      </div>
                      <span className="text-[8.5px] text-zinc-500 shrink-0 select-none">
                        [{v.cwe_id}]
                      </span>
                    </button>
                  );
                })}
                {vulnerabilitiesList.length > 48 && (
                  <div className="text-center py-1 text-[8.5px] text-zinc-650 italic">
                    +{vulnerabilitiesList.length - 48} more profiles available in catalog registry
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] font-mono uppercase text-zinc-400">Security Notes & Environment Details</label>
            <textarea
              rows={3}
              placeholder="Record configuration nuances, IP schedules, or testing constraints..."
              value={formNotes}
              onChange={e => setFormNotes(e.target.value)}
              className="bg-zinc-950 border border-white/10 text-xs p-3 text-white focus:outline-none focus:border-[#CCFF00] rounded-lg"
            />
          </div>

          <div className="flex justify-end gap-3 border-t border-white/5 pt-4">
            <button
              type="button"
              onClick={() => {
                setIsAddingNew(false);
                setEditingSiteId(null);
                clearForm();
              }}
              className="px-4 py-2.5 bg-zinc-900 border border-white/15 text-zinc-400 hover:text-white text-xs font-mono uppercase transition-colors rounded-lg cursor-pointer animate-fade-in"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-5 py-2.5 bg-[#CCFF00] hover:bg-[#b0db00] text-black font-bold text-xs font-mono uppercase tracking-wider transition-all rounded-lg cursor-pointer flex items-center gap-2"
            >
              <Save className="w-3.5 h-3.5" />
              {editingSiteId ? 'Commit Changes' : 'Save New Site Profile'}
            </button>
          </div>
        </form>
      )}

      {/* SEARCH AND FILTER SEGMENTS BAR */}
      <div className="flex flex-col md:flex-row items-center gap-4 bg-zinc-950 p-4 border border-white/10 rounded-2xl select-none">
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-3 w-4 h-4 text-zinc-500" />
          <input
            type="text"
            placeholder="Search Target Website Registries, URLs, Notes..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-black border border-white/10 text-[11px] py-2 px-9 text-white placeholder-zinc-550 rounded-xl focus:outline-none focus:border-[#CCFF00] transition-colors font-mono uppercase"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto shrink-0 justify-between sm:justify-start">
          <div className="flex items-center gap-1">
            <Layers className="w-3.5 h-3.5 text-zinc-400" />
            <span className="text-[10px] font-mono uppercase text-zinc-500">Group Filter:</span>
          </div>

          <div className="flex gap-1.5 overflow-x-auto">
            {groupOptions.slice(0, 6).map(grp => (
              <button
                key={grp}
                onClick={() => setSelectedGroupFilter(grp)}
                className={`px-3 py-1.5 rounded-lg border text-[10px] font-bold font-mono uppercase transition-colors cursor-pointer select-none ${
                  selectedGroupFilter === grp 
                    ? 'bg-[#CCFF00] border-[#CCFF00] text-black' 
                    : 'bg-black border-white/10 text-zinc-400 hover:text-white'
                }`}
              >
                {grp === 'ALL' ? '[ALL GROUPS]' : grp}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* DYNAMIC LISTING DISPLAY */}
      {filteredWebsites.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-start">
          {filteredWebsites.map(site => (
            <div 
              key={site.id}
              className="bg-zinc-950 border border-white/10 rounded-2xl hover:border-[#CCFF00]/40 transition-all p-6 flex flex-col gap-4 shadow-xl select-text"
            >
              
              {/* Card Header segment */}
              <div className="flex justify-between items-start border-b border-white/5 pb-3">
                <div>
                  <span className="px-2 py-0.5 bg-zinc-900 border border-white/10 text-[#CCFF00] font-mono text-[9px] uppercase font-semibold rounded mr-2 inline-block mb-1.5">
                    {site.group || 'Uncategorized'}
                  </span>
                  <h3 className="text-base font-bold text-white uppercase tracking-tight font-display">
                    {site.name}
                  </h3>
                  <a 
                    href={site.url}
                    target="_blank" 
                    referrerPolicy="no-referrer"
                    rel="noopener noreferrer" 
                    className="text-[10.5px] text-zinc-400 hover:text-[#CCFF00] font-mono transition-colors flex items-center gap-1.5 mt-1 hover:underline break-all"
                  >
                    <span>{site.url}</span>
                    <ExternalLink className="w-3 h-3 text-zinc-600 shrink-0" />
                  </a>
                </div>

                <div className="flex items-center gap-1 select-none">
                  <button
                    onClick={() => startEdit(site)}
                    className="p-1.5 bg-black border border-white/5 hover:border-[#CCFF00] hover:bg-zinc-900 text-zinc-400 hover:text-[#CCFF00] transition-all rounded cursor-pointer"
                    title="Edit System Parameters"
                  >
                    <Edit3 className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => deleteSite(site.id)}
                    className="p-1.5 bg-black border border-white/5 hover:border-red-500/50 hover:bg-zinc-900 text-zinc-450 hover:text-red-400 transition-all rounded cursor-pointer"
                    title="Remove Listing"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* INPUTS / VARIABLES MATRIX ROW */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 bg-black/60 p-4 border border-white/5 rounded-xl">
                
                {/* Inputs listing column */}
                <div className="flex flex-col gap-1.5">
                  <span className="text-[10px] font-mono uppercase text-zinc-400 tracking-wider flex items-center gap-1 border-b border-white/5 pb-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 block shrink-0" />
                    Input Matrices:
                  </span>
                  <div className="flex flex-col gap-1">
                    {site.inputs.map((inp, i) => (
                      <span key={i} className="text-[10px] text-zinc-300 font-mono pl-2 border-l border-zinc-700 break-words">
                        {inp}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Outcomes listing column */}
                <div className="flex flex-col gap-1.5">
                  <span className="text-[10px] font-mono uppercase text-[#CCFF00] tracking-wider flex items-center gap-1 border-b border-white/5 pb-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#CCFF00] block shrink-0" />
                    Outcomes Logged:
                  </span>
                  <div className="flex flex-col gap-1">
                    {site.outcomes.map((out, i) => (
                      <span key={i} className="text-[10px] text-[#CCFF00]/90 font-mono pl-2 border-l border-[#CCFF00]/30 break-words">
                        {out}
                      </span>
                    ))}
                  </div>
                </div>

              </div>

              {/* ASSOCIATED VULNERABILITIES DETECTED */}
              <div className="flex flex-col gap-1.5">
                <span className="text-[10px] font-mono uppercase text-zinc-400 tracking-wider">
                  Associated Cyber Flaws Identified:
                </span>
                
                {site.vulnerabilitiesFound.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {site.vulnerabilitiesFound.map(vId => (
                      <span 
                        key={vId}
                        className={`px-2 py-1 rounded text-[9.5px] font-mono uppercase font-semibold ${getVulnSeverityBadge(vId)}`}
                      >
                        {getVulnName(vId)}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-[9.5px] text-zinc-500 italic font-mono uppercase leading-none">
                    No linked catalog items validated as present under telemetry.
                  </span>
                )}
              </div>

              {/* AUDIT NOTE SECTION */}
              {site.notes && (
                <div className="text-[11px] text-zinc-400 leading-relaxed italic bg-zinc-950/80 p-3 border-l-2 border-zinc-700">
                  <strong className="text-zinc-500 font-bold font-mono text-[9px] uppercase block mb-0.5">Telemetry Notes:</strong>
                  {site.notes}
                </div>
              )}

              {/* UPDATED DATE ROW */}
              <div className="text-[9px] font-mono text-zinc-600 uppercase flex justify-between items-center select-none pt-2 border-t border-white/5">
                <span>Ref status: Checked</span>
                <span>Last updated at: {site.updatedAt}</span>
              </div>

            </div>
          ))}
        </div>
      ) : (
        <div className="py-12 border border-white/10 rounded-2xl bg-zinc-950/50 flex flex-col items-center justify-center gap-3 text-center">
          <HelpCircle className="w-10 h-10 text-zinc-650" />
          <div>
            <h3 className="font-mono text-xs uppercase font-bold text-zinc-400">No Target Websites Matches Found</h3>
            <p className="text-[10.5px] text-zinc-500 mt-1 max-w-sm font-sans">
              No registered target websites match your filter keywords. Click the Add Website target button to initiate.
            </p>
          </div>
          {selectedGroupFilter !== 'ALL' && (
            <button
              onClick={() => setSelectedGroupFilter('ALL')}
              className="text-[10px] font-mono text-[#CCFF00] hover:underline"
            >
              Reset group filter
            </button>
          )}
        </div>
      )}

      {/* EXTRA TELEMETRY SPECIFICATIONS BOX */}
      <div className="p-4 bg-zinc-950/40 border border-zinc-900 rounded-xl text-zinc-500 text-[11px] leading-relaxed select-text flex gap-3 text-left">
        <AlertCircle className="w-5 h-5 text-[#CCFF00] shrink-0 mt-0.5 animate-pulse" />
        <div>
          <p className="font-bold text-zinc-400 mb-0.5 uppercase font-mono text-[10px]">[REUSABILITY & REPLICA CONTROLS SPECIFICATION]</p>
          Every logged cyber target website profiles store customized inputs and outcomes. Outwards-directed security managers can use pre-seeded profiles to test several endpoint routes simultaneously, resolving target weaknesses quickly without manual duplication.
        </div>
      </div>

    </div>
  );
}
