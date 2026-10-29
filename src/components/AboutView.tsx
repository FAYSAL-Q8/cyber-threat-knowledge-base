import React from 'react';
import { Shield, BookOpen, Database, Globe, Cpu, AlertTriangle, ArrowRight, Layout, Play } from 'lucide-react';

interface AboutViewProps {
  onNavigate: (tab: 'catalog' | 'sandbox' | 'sources' | 'agent-rag' | 'pentesting' | 'about' | 'websites' | 'cases') => void;
  vulnerabilitiesLength: number;
}

export default function AboutView({ onNavigate, vulnerabilitiesLength }: AboutViewProps) {
  return (
    <div className="max-w-4xl mx-auto py-4 px-2 animate-fade-in font-sans">
      {/* Dynamic Header Badge */}
      <div className="flex items-center gap-2.5 mb-6 text-[#CCFF00] font-mono text-[10px] uppercase tracking-widest bg-[#CCFF00]/10 border border-[#CCFF00]/20 px-3 py-1.5 rounded-full w-fit">
        <Shield className="w-3.5 h-3.5" />
        <span>Platform Architecture & Scope Specification</span>
      </div>

      {/* Main Title Section */}
      <div className="mb-12">
        <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight uppercase leading-tight font-display">
          About Security Gateway
        </h1>
        <p className="text-sm text-zinc-400 mt-2.5 leading-relaxed max-w-2xl select-text">
          A modular knowledge-base and safe local simulation workspace for identifying, analyzing, and validating fundamental application vulnerabilities.
        </p>
      </div>

      {/* Content Columns (Moved from Footer) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
        
        {/* Core Capabilities */}
        <div className="bg-black/40 border border-white/10 p-6 rounded-2xl flex flex-col gap-4 select-text hover:border-zinc-700 transition-all">
          <div className="w-10 h-10 rounded-xl bg-zinc-900 border border-white/15 flex items-center justify-center text-[#CCFF00]">
            <BookOpen className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-mono text-xs font-bold text-[#CCFF00] uppercase tracking-wider mb-2">
              [System Scope]
            </h3>
            <p className="text-xs text-zinc-350 leading-relaxed">
              This application functions as a robust <strong>offline-first security knowledge gateway</strong>. We structured fundamental web and server weaknesses mapping CWE classifications, exploitation mechanics, payloads, and code-level remediation patterns transparently.
            </p>
          </div>
        </div>

        {/* Model Integration */}
        <div className="bg-black/40 border border-white/10 p-6 rounded-2xl flex flex-col gap-4 select-text hover:border-zinc-700 transition-all">
          <div className="w-10 h-10 rounded-xl bg-zinc-900 border border-white/15 flex items-center justify-center text-[#CCFF00]">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-mono text-xs font-bold text-[#CCFF00] uppercase tracking-wider mb-2">
              [Model Integration]
            </h3>
            <p className="text-xs text-zinc-350 leading-relaxed">
              Configure credentials parameters in your Google Cloud environment to invoke the <code>@google/genai</code> model endpoint directly during user submissions. Use cosine embedding logic internally to evaluate redundancy and preserve structural index values cleanly.
            </p>
          </div>
        </div>

        {/* Industry Standards */}
        <div className="bg-black/40 border border-white/10 p-6 rounded-2xl flex flex-col gap-4 select-text hover:border-zinc-700 transition-all">
          <div className="w-10 h-10 rounded-xl bg-zinc-900 border border-white/15 flex items-center justify-center text-[#CCFF00]">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-mono text-xs font-bold text-[#CCFF00] uppercase tracking-wider mb-2">
              [Standards Align]
            </h3>
            <p className="text-xs text-zinc-350 leading-relaxed">
              Each vulnerabilities blueprint template is linked dynamically to corresponding standard industrial indices, derived from OWASP top-10 projects, MITRE CWE databases, and live cyber threat references published on CISA KEV feeds.
            </p>
          </div>
        </div>

      </div>

      {/* Navigation Shortcut Grid */}
      <div className="bg-zinc-950/60 border border-white/5 rounded-2xl p-6 sm:p-8 mb-8">
        <h3 className="font-mono text-[10px] uppercase tracking-widest text-[#CCFF00] mb-4">
          Interactive Modules Quick-Access
        </h3>
        
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <button
            onClick={() => onNavigate('catalog')}
            className="flex items-center justify-between p-4 bg-black/40 hover:bg-[#CCFF00]/5 border border-white/10 hover:border-[#CCFF00]/40 rounded-xl transition-all cursor-pointer group text-left"
          >
            <div className="flex items-center gap-3">
              <BookOpen className="w-4 h-4 text-zinc-400 group-hover:text-[#CCFF00] transition-colors" />
              <div>
                <div className="text-xs font-bold text-white uppercase">[01] Attack Catalog</div>
                <div className="text-[10px] text-zinc-500 mt-0.5 font-sans">Explore 20 core vulnerability categories</div>
              </div>
            </div>
            <ArrowRight className="w-4 h-4 text-zinc-600 group-hover:text-[#CCFF00] transition-colors group-hover:translate-x-1" />
          </button>

          <button
            onClick={() => onNavigate('sandbox')}
            className="flex items-center justify-between p-4 bg-black/40 hover:bg-[#CCFF00]/5 border border-white/10 hover:border-[#CCFF00]/40 rounded-xl transition-all cursor-pointer group text-left"
          >
            <div className="flex items-center gap-3">
              <Database className="w-4 h-4 text-zinc-400 group-hover:text-[#CCFF00] transition-colors" />
              <div>
                <div className="text-xs font-bold text-white uppercase">[02] Seeding Sandbox</div>
                <div className="text-[10px] text-zinc-500 mt-0.5 font-sans">Test custom vulnerability configurations</div>
              </div>
            </div>
            <ArrowRight className="w-4 h-4 text-zinc-600 group-hover:text-[#CCFF00] transition-colors group-hover:translate-x-1" />
          </button>

          <button
            onClick={() => onNavigate('sources')}
            className="flex items-center justify-between p-4 bg-black/40 hover:bg-[#CCFF00]/5 border border-white/10 hover:border-[#CCFF00]/40 rounded-xl transition-all cursor-pointer group text-left"
          >
            <div className="flex items-center gap-3">
              <Globe className="w-4 h-4 text-zinc-400 group-hover:text-[#CCFF00] transition-colors" />
              <div>
                <div className="text-xs font-bold text-white uppercase">[03] Intelligence Feeds</div>
                <div className="text-[10px] text-zinc-500 mt-0.5 font-sans">Real-time external news dashboards</div>
              </div>
            </div>
            <ArrowRight className="w-4 h-4 text-zinc-600 group-hover:text-[#CCFF00] transition-colors group-hover:translate-x-1" />
          </button>

          <button
            onClick={() => onNavigate('pentesting')}
            className="flex items-center justify-between p-4 bg-black/40 hover:bg-[#CCFF00]/5 border border-white/10 hover:border-[#CCFF00]/40 rounded-xl transition-all cursor-pointer group text-left"
          >
            <div className="flex items-center gap-3">
              <Play className="w-4 h-4 text-zinc-400 group-hover:text-[#CCFF00] transition-colors" />
              <div>
                <div className="text-xs font-bold text-white uppercase">[05] Active Pentesting</div>
                <div className="text-[10px] text-zinc-500 mt-0.5 font-sans">Manage checklist scopes and write actions</div>
              </div>
            </div>
            <ArrowRight className="w-4 h-4 text-zinc-600 group-hover:text-[#CCFF00] transition-colors group-hover:translate-x-1" />
          </button>

          <button
            onClick={() => onNavigate('websites')}
            className="flex items-center justify-between p-4 bg-[#CCFF00]/5 border border-[#CCFF00]/30 hover:border-[#CCFF00] rounded-xl transition-all cursor-pointer group text-left"
          >
            <div className="flex items-center gap-3">
              <Globe className="w-4 h-4 text-[#CCFF00] group-hover:scale-110 transition-transform" />
              <div>
                <div className="text-xs font-bold text-white uppercase text-[#CCFF00]">[07] Target Directory</div>
                <div className="text-[10px] text-zinc-400 mt-0.5 font-sans">List vulnerable sites, group targets, configure inputs & outcomes, and link found flaws with reuse templates</div>
              </div>
            </div>
            <ArrowRight className="w-4 h-4 text-[#CCFF00] transition-colors group-hover:translate-x-1" />
          </button>

          <button
            onClick={() => onNavigate('cases')}
            className="flex items-center justify-between p-4 bg-[#CCFF00]/5 border border-[#CCFF00]/30 hover:border-[#CCFF00] rounded-xl transition-all cursor-pointer group text-left"
          >
            <div className="flex items-center gap-3">
              <Shield className="w-4 h-4 text-[#CCFF00] group-hover:scale-110 transition-transform" />
              <div>
                <div className="text-xs font-bold text-white uppercase text-[#CCFF00]">[08] Cases Database</div>
                <div className="text-[10px] text-zinc-400 mt-0.5 font-sans">Build threat incident scenarios, trigger paths, fuzz setups, and extract patterns for future automation systems</div>
              </div>
            </div>
            <ArrowRight className="w-4 h-4 text-[#CCFF00] transition-colors group-hover:translate-x-1" />
          </button>
        </div>
      </div>

      {/* Platform Disclaimer Context */}
      <div className="p-4 bg-zinc-950/20 border border-zinc-900 rounded-xl text-zinc-500 text-[11px] leading-relaxed select-text flex gap-3 text-left">
        <AlertTriangle className="w-4.5 h-4.5 text-[#CCFF00] shrink-0 mt-0.5" />
        <div>
          <p className="font-bold text-zinc-400 mb-1">Disclaimer of offensive practices</p>
          The Security Knowledge Gateway is built exclusively for security education, penetration testing preparation, and robust defenses verification. Users assume absolute responsibility for ethical conduct. Never operate payload materials without explicit authority.
        </div>
      </div>

      <div className="mt-8 text-center text-[10.5px] text-zinc-500">
        Active threat library containing <strong className="text-white">{vulnerabilitiesLength} profiles</strong>. Built with safety constraints.
        <div className="mt-2 text-[10px]">
          Developed by{' '}
          <a
            href="https://github.com/FAYSAL-Q8"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[#CCFF00] font-bold hover:underline transition-colors"
          >
            FA
          </a>
        </div>
      </div>
    </div>
  );
}
