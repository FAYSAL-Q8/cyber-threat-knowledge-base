import React, { useState, useMemo } from 'react';
import { 
  Globe, 
  ExternalLink, 
  TrendingUp, 
  Search, 
  ArrowRight 
} from 'lucide-react';
import { RELIABLE_SOURCES, MOCK_CVE_FEED } from '../data/sources';
import { Vulnerability } from '../types';

interface SourcesViewProps {
  vulnerabilitiesList: Vulnerability[];
  setSelectedVulnerabilityId: (id: string) => void;
  setActiveTab: (tab: 'catalog' | 'sandbox' | 'sources' | 'agent-rag') => void;
  setCatalogSearch: (search: string) => void;
}

export default function SourcesView({
  vulnerabilitiesList,
  setSelectedVulnerabilityId,
  setActiveTab,
  setCatalogSearch
}: SourcesViewProps) {
  const [cveSearch, setCveSearch] = useState('');
  const [cveSeverityFilter, setCveSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM'>('ALL');
  const [cveSourceFilter, setCveSourceFilter] = useState<'ALL' | 'CISA KEV' | 'NIST NVD' | 'GitHub Advisory'>('ALL');

  const filteredCves = useMemo(() => {
    return MOCK_CVE_FEED.filter(item => {
      const matchesSearch = item.id.toLowerCase().includes(cveSearch.toLowerCase()) ||
                            item.title.toLowerCase().includes(cveSearch.toLowerCase()) ||
                            item.description.toLowerCase().includes(cveSearch.toLowerCase());
      const matchesSeverity = cveSeverityFilter === 'ALL' || item.severity === cveSeverityFilter;
      const matchesSource = cveSourceFilter === 'ALL' || item.source.includes(cveSourceFilter);

      return matchesSearch && matchesSeverity && matchesSource;
    });
  }, [cveSearch, cveSeverityFilter, cveSourceFilter]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
      
      {/* SOURCE blue-printing sidebar overview */}
      <div className="lg:col-span-12 xl:col-span-5 flex flex-col gap-6">
        
        <div className="bg-black border border-white/10 p-6 flex flex-col gap-5">
          <h3 className="font-mono text-xs uppercase tracking-widest text-[#CCFF00] font-bold flex items-center gap-2 border-b border-white/5 pb-3 pb-3">
            <Globe className="w-4 h-4" />
            [Web & Cloud Security Feeds]
          </h3>
          <p className="text-zinc-400 text-xs leading-relaxed font-sans">
            These authentic upstream databases provide machine-readable metadata vulnerability indicators to feed automated catalog ingestion streams via webhook schedules.
          </p>

          <div className="flex flex-col gap-3">
            {RELIABLE_SOURCES.map(s => (
              <div key={s.id} className="bg-[#121212] border border-white/5 p-4 flex flex-col gap-1.5 hover:border-[#CCFF00]/20 transition-all">
                <div className="flex justify-between items-start">
                  <h4 className="text-xs font-bold text-white font-display uppercase tracking-tight">{s.name}</h4>
                  <span className="font-mono text-[9px] uppercase px-1.5 py-0.2 border border-[#CCFF00]/10 text-[#CCFF00] bg-[#CCFF00]/2 select-none font-bold">
                    {s.reliability} RELIABLE
                  </span>
                </div>
                <p className="text-[11.5px] text-zinc-400 leading-relaxed font-sans mt-0.5">
                  {s.provides}
                </p>
                <div className="flex items-center justify-between font-mono text-[9.5px] mt-2 border-t border-zinc-900 pt-2 text-zinc-550">
                  <span>API Mapping: <strong className="text-[#CCFF00] font-bold font-mono">{s.data_access}</strong></span>
                  <a 
                    href={s.url} 
                    target="_blank" 
                    rel="noreferrer" 
                    referrerPolicy="no-referrer"
                    className="text-zinc-400 hover:text-white flex items-center gap-1 transition-colors select-none"
                  >
                    RAW DATA <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                </div>
              </div>
            ))}
          </div>

        </div>

      </div>

      {/* MONITOR STREAM SECTION */}
      <div className="lg:col-span-12 xl:col-span-7 bg-black border border-white/10 p-6 sm:p-8 flex flex-col gap-6">
        
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-white/5 pb-4">
          <div>
            <h3 className="text-lg font-black tracking-tight text-white uppercase flex items-center gap-2 font-display">
              <TrendingUp className="w-4 h-4 text-[#CCFF00]" />
              Threat Intelligence Pulse Stream
            </h3>
            <p className="text-zinc-500 font-mono text-[10px] uppercase tracking-wider uppercase leading-normal">
              Live filterable mock thread pulling recent critical CVE outputs to model catalog vulnerabilities.
            </p>
          </div>

          <div className="font-mono text-[9.5px] border border-[#CCFF00]/20 bg-[#CCFF00]/2 px-2.5 py-1 text-[#CCFF00] flex items-center gap-1.5 select-none font-bold">
            <span className="w-1.5 h-1.5 rounded-full bg-[#CCFF00] animate-ping"></span> INTEL FEED ACTIVE: MULTI-CHANNEL
          </div>
        </div>

        {/* BRUTALIST SEARCH & DROPDOWNS BAR */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          
          <div className="relative flex items-center bg-zinc-955 border border-white/10 px-3 py-1.5">
            <Search className="w-4 h-4 text-zinc-600 mr-2 flex-shrink-0" />
            <input
              type="text"
              placeholder="SEARCH IDENTIFIERS..."
              value={cveSearch}
              onChange={(e) => setCveSearch(e.target.value)}
              className="w-full bg-transparent text-xs text-white focus:outline-none placeholder-zinc-700 font-mono uppercase tracking-wider"
            />
          </div>

          <div className="flex items-center bg-zinc-955 border border-white/10 px-3.5 py-1.5">
            <span className="font-mono text-[10px] text-zinc-500 uppercase mr-2 font-bold whitespace-nowrap">SEV BLOCK:</span>
            <select
              value={cveSeverityFilter}
              onChange={(e) => setCveSeverityFilter(e.target.value as any)}
              className="bg-transparent text-xs text-zinc-300 focus:outline-none w-full cursor-pointer font-mono border-none uppercase"
            >
              <option value="ALL">ALL INTEL PILES</option>
              <option value="CRITICAL">CRITICAL ONLY</option>
              <option value="HIGH">HIGH + INDICATORS</option>
              <option value="MEDIUM">MEDIUM + INDICATORS</option>
            </select>
          </div>

          <div className="flex items-center bg-zinc-955 border border-white/10 px-3.5 py-1.5">
            <span className="font-mono text-[10px] text-zinc-500 uppercase mr-2 font-bold whitespace-nowrap">CHANNEL:</span>
            <select
              value={cveSourceFilter}
              onChange={(e) => setCveSourceFilter(e.target.value as any)}
              className="bg-transparent text-xs text-zinc-300 focus:outline-none w-full cursor-pointer font-mono border-none uppercase"
            >
              <option value="ALL">ALL SOURCES</option>
              <option value="CISA KEV">CISA KEV</option>
              <option value="NIST NVD">NIST NVD</option>
              <option value="GitHub Advisory">GITHUB APIS</option>
            </select>
          </div>

        </div>

        {/* FEED SEED RESULTS DOCK */}
        <div className="flex flex-col gap-4 min-h-[400px] max-h-[480px] overflow-y-auto pr-1">
          {filteredCves.length === 0 ? (
            <div className="p-12 text-center text-zinc-650 font-mono text-xs border border-white/5 bg-[#121212]/30 uppercase">
              -- NO THREAT CORRELATION MATCHES -- Try loosening filters
            </div>
          ) : (
            filteredCves.map(item => (
              <div key={item.id} className="bg-zinc-955 border border-white/5 p-4 flex flex-col gap-3 relative hover:border-[#CCFF00]/10 transition-all select-text">
                
                <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2 border-b border-white/5 pb-2.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10.5px] font-black text-black bg-[#CCFF00] px-2 py-0.5 select-all">
                      {item.id}
                    </span>
                    <span className="font-mono text-[9px] text-zinc-500">POLL TIMESTAMP: {item.published_date}</span>
                  </div>
                  <div className="flex items-center gap-2 font-mono text-[9px] select-none">
                    <span className="text-zinc-500 uppercase">Provider:</span>
                    <span className="text-white px-2 py-0.2 bg-zinc-900 border border-white/5 ">{item.source}</span>
                    <span className={`px-1.5 py-0.2 select-none font-bold border ${
                      item.severity === 'CRITICAL' 
                        ? 'text-red-400 border-red-500/15 bg-red-955/2' 
                        : 'text-amber-400 border-amber-500/15 bg-amber-955/2'
                    }`}>
                      {item.severity}
                    </span>
                  </div>
                </div>

                <div>
                  <h4 className="text-xs font-black uppercase text-white font-display tracking-tight mb-1">{item.title}</h4>
                  <p className="text-xs text-zinc-400 leading-relaxed font-sans filter shadow select-text">
                    {item.description}
                  </p>
                </div>

                <div className="flex justify-between items-center border-t border-white/5 pt-2.5 mt-1 font-mono text-[10px] text-zinc-550 select-none">
                  <span>Weakness Category Map: <strong className="text-zinc-400 font-bold font-mono">{item.cwe}</strong></span>
                  <button
                    onClick={() => {
                      // Navigate back to catalog and find best mapping
                      setCatalogSearch('');
                      const normalized = item.cwe.split(' (')[0].toLowerCase();
                      const match = vulnerabilitiesList.find(v => v.cwe_id.toLowerCase() === normalized);
                      if (match) {
                        setSelectedVulnerabilityId(match.id);
                      } else {
                        setCatalogSearch(item.cwe.split(' (')[0]);
                      }
                      setActiveTab('catalog');
                    }}
                    className="text-[#CCFF00] hover:underline font-bold uppercase flex items-center gap-1 transition-all"
                  >
                    Synthesize Weakness <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>

              </div>
            ))
          )}
        </div>

      </div>

    </div>
  );
}
