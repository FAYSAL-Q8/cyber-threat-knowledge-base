/**
 * Author: Faysal Alibrahim
 * GitHub: https://github.com/FAYSAL-Q8
 */

import React, { useState, useEffect } from 'react';
import { Shield, BookOpen, Database, Globe, Cpu, Sun, Moon, Play, ChevronDown, Info, FileText } from 'lucide-react';
import { INITIAL_VULNERABILITIES } from './data/vulnerabilities';
import { generateExtendedThreatIntelligence } from './data/generator';
import { Vulnerability } from './types';

import CatalogView from './components/CatalogView';
import SandboxView from './components/SandboxView';
import SourcesView from './components/SourcesView';
import AgentRagView from './components/AgentRagView';
import PentestView from './components/PentestView';
import AboutView from './components/AboutView';
import WebsitesView from './components/WebsitesView';
import CasesView from './components/CasesView';

export default function App() {
  const [activeTab, setActiveTab] = useState<'catalog' | 'sandbox' | 'sources' | 'agent-rag' | 'pentesting' | 'about' | 'websites' | 'cases'>('pentesting');
  const [showMenuDropdown, setShowMenuDropdown] = useState(false);
  const [vulnerabilitiesList, setVulnerabilitiesList] = useState<Vulnerability[]>(() => {
    const saved = localStorage.getItem('vulnerabilities_registry_db');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length >= 500) {
          return parsed;
        }
      } catch (e) {
        console.warn("Could not read local vulnerability storage.", e);
      }
    }
    return generateExtendedThreatIntelligence(INITIAL_VULNERABILITIES, 512);
  });
  const [selectedVulnerabilityId, setSelectedVulnerabilityId] = useState<string>('sqli');
  const [catalogSearch, setCatalogSearch] = useState('');

  useEffect(() => {
    localStorage.setItem('vulnerabilities_registry_db', JSON.stringify(vulnerabilitiesList));
  }, [vulnerabilitiesList]);

  const [isDarkMode, setIsDarkMode] = useState(() => {
    const saved = localStorage.getItem('theme_mode');
    return saved !== 'light';
  });

  const [showHeader, setShowHeader] = useState(true);
  const [lastScrollY, setLastScrollY] = useState(0);
  const [showScrollTop, setShowScrollTop] = useState(false);

  useEffect(() => {
    localStorage.setItem('theme_mode', isDarkMode ? 'dark' : 'light');
    if (isDarkMode) {
      document.documentElement.classList.remove('light');
      document.body.classList.remove('light');
    } else {
      document.documentElement.classList.add('light');
      document.body.classList.add('light');
    }
  }, [isDarkMode]);

  useEffect(() => {
    const handleScroll = () => {
      const currentScrollY = window.scrollY;

      if (currentScrollY > 300) {
        setShowScrollTop(true);
      } else {
        setShowScrollTop(false);
      }

      if (currentScrollY <= 60) {
        showHeader || setShowHeader(true);
      } else if (currentScrollY > lastScrollY && currentScrollY > 120) {
        showHeader && setShowHeader(false);
      }

      setLastScrollY(currentScrollY);
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, [lastScrollY, showHeader]);

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
    setShowHeader(true);
  };

  return (
    <div className={`min-h-screen flex flex-col font-sans selection:bg-[#CCFF00] selection:text-black bg-[#0D0D0D] text-[#F2F2F2] transition-colors duration-200 ${isDarkMode ? 'dark' : 'light'}`}>
      
      {/* Navigation Header */}
      <header className={`border-b border-white/10 bg-[#0D0D0D]/95 sticky top-0 z-50 transition-all duration-300 ease-out ${
        showHeader ? 'translate-y-0 opacity-100' : '-translate-y-full opacity-0 pointer-events-none'
      }`}>
        <div className="w-full max-w-7xl mx-auto px-6 py-5 flex flex-col lg:flex-row justify-between items-center gap-6">
          
          <div className="flex items-center gap-3.5 select-none animate-fade-in">
            <div className="bg-[#CCFF00] p-2.5 text-black rounded-lg shadow-sm flex-shrink-0 animate-pulse">
              <Shield className="w-5.5 h-3.5" />
            </div>
            <div>
              <h1 className="text-xl font-extrabold tracking-tight uppercase leading-none text-white font-display">
                Cybersecurity Knowledge Source
              </h1>
              <p className="text-[10px] text-zinc-500 font-mono tracking-widest uppercase mt-1">
                Web, Host Server & Multi-Cloud Attack Surface Schemas
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3.5">
            <div className="relative font-mono text-[10.5px]">
              <button
                onClick={() => setShowMenuDropdown(!showMenuDropdown)}
                className="px-5 py-3 bg-black border border-white/10 rounded-xl transition-all uppercase flex items-center justify-between gap-3 select-none font-bold text-[#CCFF00] hover:border-[#CCFF00]/50 cursor-pointer min-w-[210px]"
                title="Switch Knowledge Modules"
              >
                <div className="flex items-center gap-2">
                  {activeTab === 'catalog' && (
                    <>
                      <BookOpen className="w-3.5 h-3.5 text-[#CCFF00]" />
                      <span>[01] Attack Catalog</span>
                    </>
                  )}
                  {activeTab === 'sandbox' && (
                    <>
                      <Database className="w-3.5 h-3.5 text-[#CCFF00]" />
                      <span>[02] Seeding Sandbox</span>
                    </>
                  )}
                  {activeTab === 'sources' && (
                    <>
                      <Globe className="w-3.5 h-3.5 text-[#CCFF00]" />
                      <span>[03] Intelligence Feeds</span>
                    </>
                  )}
                  {activeTab === 'agent-rag' && (
                    <>
                      <Cpu className="w-3.5 h-3.5 text-[#CCFF00]" />
                      <span>[04] Semantic Assistant</span>
                    </>
                  )}
                  {activeTab === 'pentesting' && (
                    <>
                      <Play className="w-3.5 h-3.5 text-[#CCFF00]" />
                      <span>[05] Active Pentesting</span>
                    </>
                  )}
                  {activeTab === 'about' && (
                    <>
                      <Info className="w-3.5 h-3.5 text-[#CCFF00]" />
                      <span>[06] About Framework</span>
                    </>
                  )}
                  {activeTab === 'websites' && (
                    <>
                      <Globe className="w-3.5 h-3.5 text-[#CCFF00]" />
                      <span>[07] Target Directory</span>
                    </>
                  )}
                  {activeTab === 'cases' && (
                    <>
                      <FileText className="w-3.5 h-3.5 text-[#CCFF00]" />
                      <span>[08] Cases Database</span>
                    </>
                  )}
                </div>
                <ChevronDown className={`w-3.5 h-3.5 text-zinc-500 transition-transform duration-200 ${showMenuDropdown ? 'rotate-180' : 'rotate-0'}`} />
              </button>

              {showMenuDropdown && (
                <>
                  <div 
                    className="fixed inset-0 z-40 bg-transparent" 
                    onClick={() => setShowMenuDropdown(false)}
                  ></div>
                  
                  <nav className="absolute right-0 mt-2 w-56 bg-[#121212] border border-white/10 rounded-xl overflow-hidden shadow-2xl z-50 flex flex-col font-mono text-[10.5px] divide-y divide-white/5 animate-fade-in">
                    <div className="px-3 py-2.5 bg-zinc-950 text-[8.5px] uppercase font-bold text-zinc-500 tracking-wider">
                      Switch Platform View
                    </div>

                    <button
                      onClick={() => {
                        setActiveTab('catalog');
                        setShowMenuDropdown(false);
                      }}
                      className={`px-4 py-3 text-left transition-colors uppercase flex items-center gap-2.5 font-bold cursor-pointer ${
                        activeTab === 'catalog' ? 'bg-[#CCFF00]/10 text-[#CCFF00]' : 'text-zinc-400 hover:text-white hover:bg-zinc-900/40'
                      }`}
                    >
                      <BookOpen className="w-3.5 h-3.5" />
                      [01] Attack Catalog
                    </button>

                    <button
                      onClick={() => {
                        setActiveTab('sandbox');
                        setShowMenuDropdown(false);
                      }}
                      className={`px-4 py-3 text-left transition-colors uppercase flex items-center gap-2.5 font-bold cursor-pointer ${
                        activeTab === 'sandbox' ? 'bg-[#CCFF00]/10 text-[#CCFF00]' : 'text-zinc-400 hover:text-white hover:bg-zinc-900/40'
                      }`}
                    >
                      <Database className="w-3.5 h-3.5" />
                      [02] Seeding Sandbox
                    </button>

                    <button
                      onClick={() => {
                        setActiveTab('sources');
                        setShowMenuDropdown(false);
                      }}
                      className={`px-4 py-3 text-left transition-colors uppercase flex items-center gap-2.5 font-bold cursor-pointer ${
                        activeTab === 'sources' ? 'bg-[#CCFF00]/10 text-[#CCFF00]' : 'text-zinc-400 hover:text-white hover:bg-zinc-900/40'
                      }`}
                    >
                      <Globe className="w-3.5 h-3.5" />
                      [03] Intelligence Feeds
                    </button>

                    <button
                      onClick={() => {
                        setActiveTab('agent-rag');
                        setShowMenuDropdown(false);
                      }}
                      className={`px-4 py-3 text-left transition-colors uppercase flex items-center gap-2.5 font-bold cursor-pointer ${
                        activeTab === 'agent-rag' ? 'bg-[#CCFF00]/10 text-[#CCFF00]' : 'text-zinc-400 hover:text-white hover:bg-zinc-900/40'
                      }`}
                    >
                      <Cpu className="w-3.5 h-3.5" />
                      [04] Semantic Assistant
                    </button>

                    <button
                      onClick={() => {
                        setActiveTab('pentesting');
                        setShowMenuDropdown(false);
                      }}
                      className={`px-4 py-3 text-left transition-colors uppercase flex items-center gap-2.5 font-bold cursor-pointer ${
                        activeTab === 'pentesting' ? 'bg-[#CCFF00]/10 text-[#CCFF00]' : 'text-zinc-400 hover:text-white hover:bg-zinc-900/40'
                      }`}
                    >
                      <Play className="w-3.5 h-3.5" />
                      [05] Active Pentesting
                    </button>

                    <button
                      onClick={() => {
                        setActiveTab('about');
                        setShowMenuDropdown(false);
                      }}
                      className={`px-4 py-3 text-left transition-colors uppercase flex items-center gap-2.5 font-bold cursor-pointer ${
                        activeTab === 'about' ? 'bg-[#CCFF00]/10 text-[#CCFF00]' : 'text-zinc-400 hover:text-white hover:bg-zinc-900/40'
                      }`}
                    >
                      <Info className="w-3.5 h-3.5" />
                      [06] About Framework
                    </button>

                    <button
                      onClick={() => {
                        setActiveTab('websites');
                        setShowMenuDropdown(false);
                      }}
                      className={`px-4 py-3 text-left transition-colors uppercase flex items-center gap-2.5 font-bold cursor-pointer ${
                        activeTab === 'websites' ? 'bg-[#CCFF00]/10 text-[#CCFF00]' : 'text-zinc-400 hover:text-white hover:bg-zinc-900/40'
                      }`}
                    >
                      <Globe className="w-3.5 h-3.5" />
                      [07] Target Directory
                    </button>

                    <button
                      onClick={() => {
                        setActiveTab('cases');
                        setShowMenuDropdown(false);
                      }}
                      className={`px-4 py-3 text-left transition-colors uppercase flex items-center gap-2.5 font-bold cursor-pointer ${
                        activeTab === 'cases' ? 'bg-[#CCFF00]/10 text-[#CCFF00]' : 'text-zinc-400 hover:text-white hover:bg-zinc-900/40'
                      }`}
                    >
                      <FileText className="w-3.5 h-3.5" />
                      [08] Cases Database
                    </button>
                  </nav>
                </>
              )}
            </div>

            <button
              onClick={() => setIsDarkMode(!isDarkMode)}
              className="px-3.5 py-3 border border-white/10 hover:border-[#CCFF00] bg-black text-zinc-400 hover:text-[#CCFF00] transition-colors flex items-center justify-center font-mono text-xs font-bold gap-2 select-none cursor-pointer rounded-xl"
              title={isDarkMode ? "Switch to light theme" : "Switch to dark theme"}
            >
              {isDarkMode ? (
                <>
                  <Sun className="w-4 h-4 text-[#CCFF00]" />
                  <span className="hidden sm:inline text-[#CCFF00] text-[10.5px] uppercase tracking-wide">LIGHT</span>
                </>
              ) : (
                <>
                  <Moon className="w-4 h-4 text-zinc-300" />
                  <span className="hidden sm:inline text-zinc-400 text-[10.5px] uppercase tracking-wide">DARK</span>
                </>
              )}
            </button>
          </div>

        </div>
      </header>

      <main className="flex-1 w-full max-w-7xl mx-auto px-6 py-8">
        {activeTab === 'catalog' && (
          <CatalogView 
            vulnerabilitiesList={vulnerabilitiesList}
            setVulnerabilitiesList={setVulnerabilitiesList}
            selectedVulnerabilityId={selectedVulnerabilityId}
            setSelectedVulnerabilityId={setSelectedVulnerabilityId}
            setActiveTab={setActiveTab}
            catalogSearch={catalogSearch}
            setCatalogSearch={setCatalogSearch}
          />
        )}

        {activeTab === 'sandbox' && (
          <SandboxView 
            vulnerabilitiesList={vulnerabilitiesList}
            setVulnerabilitiesList={setVulnerabilitiesList}
            setSelectedVulnerabilityId={setSelectedVulnerabilityId}
            setActiveTab={setActiveTab}
          />
        )}

        {activeTab === 'sources' && (
          <SourcesView 
            vulnerabilitiesList={vulnerabilitiesList}
            setSelectedVulnerabilityId={setSelectedVulnerabilityId}
            setActiveTab={setActiveTab}
            setCatalogSearch={setCatalogSearch}
          />
        )}

        {activeTab === 'agent-rag' && (
          <AgentRagView 
            vulnerabilitiesList={vulnerabilitiesList}
          />
        )}

        {activeTab === 'pentesting' && (
          <PentestView 
            vulnerabilitiesList={vulnerabilitiesList}
            setSelectedVulnerabilityId={setSelectedVulnerabilityId}
            setActiveTab={setActiveTab}
          />
        )}

        {activeTab === 'about' && (
          <AboutView 
            onNavigate={(newTab) => setActiveTab(newTab)}
            vulnerabilitiesLength={vulnerabilitiesList.length}
          />
        )}

        {activeTab === 'websites' && (
          <WebsitesView 
            vulnerabilitiesList={vulnerabilitiesList}
          />
        )}

        {activeTab === 'cases' && (
          <CasesView 
            vulnerabilitiesList={vulnerabilitiesList}
          />
        )}
      </main>

      {/* Standardized UI Footer */}
      <footer className="border-t border-white/5 bg-black/40 py-6 mt-16 text-zinc-500 font-sans tracking-wide">
        <div className="max-w-7xl mx-auto px-6 font-mono text-[9.5px] uppercase tracking-wider flex flex-col md:flex-row justify-between items-center gap-4 select-none">
          <div className="flex flex-wrap items-center gap-3 text-zinc-500">
            <span>Cybersecurity Knowledge Architecture Framework © 2026</span>
            <span className="hidden md:inline text-zinc-800">•</span>
            <button
              onClick={() => {
                setActiveTab('about');
                scrollToTop();
              }}
              className="text-[#CCFF00] hover:underline uppercase cursor-pointer font-bold font-mono"
            >
              [ Specification & Scope ]
            </button>
            <span className="hidden md:inline text-zinc-800">•</span>
            <span className="text-zinc-400">
              Developed by{' '}
              <a
                href="https://github.com/FAYSAL-Q8"
                target="_blank"
                rel="noopener noreferrer"
                className="text-[#CCFF00] font-bold hover:underline transition-colors"
              >
                FA
              </a>
            </span>
          </div>
          <div className="flex items-center gap-4">
            <span>Status: <strong className="text-[#CCFF00] font-bold font-mono">Online</strong></span>
            <span>Registry: <strong className="text-white font-black">{vulnerabilitiesList.length} profiles</strong></span>
          </div>
        </div>
      </footer>

      {showScrollTop && (
        <button
          id="scroll-to-top-btn"
          onClick={scrollToTop}
          className="fixed bottom-6 right-6 z-50 bg-[#CCFF00] text-black hover:bg-black hover:text-[#CCFF00] border border-transparent hover:border-white/10 px-4 py-3.5 font-mono text-[10px] uppercase tracking-widest font-bold shadow-2xl transition-all flex items-center gap-2 select-none cursor-pointer duration-200"
          title="Scroll to top"
        >
          <span>↑</span>
          <span>[TOP]</span>
        </button>
      )}

    </div>
  );
}
