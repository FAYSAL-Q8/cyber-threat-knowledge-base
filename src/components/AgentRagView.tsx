import React, { useState } from 'react';
import { 
  RefreshCw, 
  Terminal, 
  BookOpen, 
  MessageSquare, 
  Clock 
} from 'lucide-react';
import { Vulnerability } from '../types';

interface AgentRagViewProps {
  vulnerabilitiesList: Vulnerability[];
}

export default function AgentRagView({ vulnerabilitiesList }: AgentRagViewProps) {
  const [chatMessages, setChatMessages] = useState<Array<{ sender: 'user' | 'agent'; text: string; timestamp: string }>>([
    {
      sender: 'agent',
      text: "Securing systems. I support parsing vulnerability context from our database, matching your inputs semantics via vector embeddings, and looking up CVEs. Ask me a question about cloud metadata exposure, SQL parameters, or security posture.",
      timestamp: '14:23:00'
    }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [activeRagStep, setActiveRagStep] = useState<number>(-1);
  const [isChatTyping, setIsChatTyping] = useState(false);
  const [ragTrace, setRagTrace] = useState<{
    queryEmbedding?: string;
    highestMatchDoc?: string;
    similarity?: number;
    retrievedContext?: string;
    constructedPrompt?: string;
  } | null>(null);

  const handleAgentPromptSubmit = (customText?: string) => {
    const promptToSend = customText || chatInput;
    if (!promptToSend.trim()) return;

    // Add user message
    const userMsg = {
      sender: 'user' as const,
      text: promptToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    };
    setChatMessages(prev => [...prev, userMsg]);
    setChatInput('');
    setIsChatTyping(true);
    setActiveRagStep(0);

    // Dynamic RAG execution trace loop
    setRagTrace({
      queryEmbedding: `[${Array.from({ length: 8 }, () => (Math.random() * 2 - 1).toFixed(4)).join(', ')}, ...]`,
    });

    // Step 2: Retrieve matched docs
    setTimeout(() => {
      setActiveRagStep(1);
      
      let match = vulnerabilitiesList[0] || { name: 'Unknown Module', cwe_id: 'CWE-000', severity: 'Critical', technical_explanation: 'Generic security flaw context.', remediation: 'Restore safe guidelines.' };
      let bestScore = 0.52;

      vulnerabilitiesList.forEach(v => {
        const queryNorm = promptToSend.toLowerCase();
        let currentScore = 0.45;
        if (queryNorm.includes(v.name.toLowerCase().split(' ')[0])) currentScore += 0.35;
        if (queryNorm.includes(v.cwe_id.toLowerCase())) currentScore += 0.4;
        if (queryNorm.includes('ssrf') && v.id === 'ssrf') currentScore += 0.45;
        if (queryNorm.includes('sql') && v.id === 'sqli') currentScore += 0.45;
        if (queryNorm.includes('xss') && v.id === 'xss') currentScore += 0.45;
        if (queryNorm.includes('cve') && v.id === 'rce') currentScore += 0.2;
        if (queryNorm.includes('cloud') && v.category === 'cloud-security') currentScore += 0.15;
        
        if (currentScore > bestScore) {
          bestScore = currentScore;
          match = v;
        }
      });

      setRagTrace(prev => ({
        ...prev,
        highestMatchDoc: `${match.name} (${match.cwe_id})`,
        similarity: parseFloat(Math.min(bestScore + 0.15, 0.97).toFixed(2)),
        retrievedContext: JSON.stringify({
          name: match.name,
          cwe_id: match.cwe_id,
          severity: match.severity,
          typical_impact: match.technical_explanation.slice(0, 150) + "...",
          remediation: match.remediation
        }, null, 2)
      }));
    }, 1000);

    // Step 3: Prompt reconstruction
    setTimeout(() => {
      setActiveRagStep(2);
      setRagTrace(prev => ({
        ...prev,
        constructedPrompt: `
<system_instructions>
You are an authorized security counselor helping with source architecture reviews. Return clear instructions using strict context.
</system_instructions>

<retrieved_context>
${prev?.retrievedContext}
</retrieved_context>

<user_query>
"${promptToSend}"
</user_query>`
      }));
    }, 2000);

    // Step 4: Deliver final structured synthesis
    setTimeout(() => {
      setActiveRagStep(3);
      setIsChatTyping(false);

      let matchedName = ragTrace?.highestMatchDoc?.split(' (')[0] || "Target Registry Module";
      let matchedContent = vulnerabilitiesList.find(x => x.name.toLowerCase().includes(matchedName.toLowerCase())) || vulnerabilitiesList[0];

      let replyText = `Regarding your query about "${promptToSend}": Our hybrid knowledge system generated text embedding vectors and successfully completed a cosine similarity check. The database matched this query directly with **${matchedContent.name}** (**${matchedContent.cwe_id}** - Severity: **${matchedContent.severity}**). \n\n**Technical Synopsis:**\n${matchedContent.technical_explanation}\n\n**Typical Exploit Vectors/Payload:**\n\`${matchedContent.payload_example}\`\n\n**Suggested Security Correction:**\n${matchedContent.remediation}`;

      if (promptToSend.toLowerCase().includes("xz") || promptToSend.toLowerCase().includes("backdoor")) {
        replyText = `Your search for the **XZ Utils Backdoor (CVE-2024-3094)** matched critical server-operating-system vectors. CVE-2024-3094 marks a highly advanced supply-chain injection where compromised compilation scripts loaded a backdoor into active sshd network services on generic Linux hosts.\n\n**Recommended Audits:**\n- Immediately query local liblzma versions: "xz --version". Ensure it is not v5.6.0 or v5.6.1.\n- Upgrade host frameworks directly on any exposed servers to pre-backdoor branches (v5.4.x).`;
      }

      setChatMessages(prev => [
        ...prev,
        {
          sender: 'agent',
          text: replyText,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        }
      ]);
    }, 3200);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
      
      {/* THE SECURITY CHAT FEED BLOCK */}
      <div className="lg:col-span-12 xl:col-span-6 bg-black border border-white/10 p-6 flex flex-col justify-between min-h-[580px]">
        
        <div>
          <div className="border-b border-white/5 pb-4 mb-4 flex justify-between items-center select-none">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#CCFF00] animate-pulse"></span>
              <div>
                <h3 className="text-xs font-mono font-bold uppercase tracking-widest text-zinc-300">
                  Neural Threat Intelligence Workspace
                </h3>
                <p className="text-[10px] text-zinc-500 lowercase">
                  vector embedding semantics matching simulations
                </p>
              </div>
            </div>

            <span className="font-mono text-[9px] bg-zinc-950 text-zinc-400 px-2 py-0.5 border border-zinc-900 select-none font-bold uppercase">
              Agent Simulator [Online]
            </span>
          </div>

          {/* DYNAMIC HELP CONCEPTS COORDS */}
          <div className="flex flex-col gap-2 mb-4">
            <span className="font-mono text-[9px] tracking-widest text-zinc-500 uppercase font-bold">[Preset Audit Prompts]</span>
            <div className="grid grid-cols-1 gap-1.5 font-mono text-[10.5px]">
              <button
                onClick={() => handleAgentPromptSubmit("Cloud SSRF instance metadata leak vector")}
                className="text-left bg-zinc-955 hover:bg-zinc-900 border border-white/5 hover:border-[#CCFF00]/10 p-2.5 text-zinc-400 hover:text-white transition-all uppercase"
              >
                [How do I abuse cloud metadata via SSRF?]
              </button>
              <button
                onClick={() => handleAgentPromptSubmit("Fix SQL parameter injection inside Node backend")}
                className="text-left bg-zinc-955 hover:bg-zinc-900 border border-white/5 hover:border-[#CCFF00]/10 p-2.5 text-zinc-400 hover:text-white transition-all uppercase"
              >
                [Prevent parameter injection in Express middleware]
              </button>
              <button
                onClick={() => handleAgentPromptSubmit("I heard XZ backdoor is extremely dangerous. What happened there?")}
                className="text-left bg-zinc-955 hover:bg-zinc-900 border border-white/5 hover:border-[#CCFF00]/10 p-2.5 text-zinc-400 hover:text-white transition-all uppercase"
              >
                [Supply-chain: XZ Backdoor analysis (CVE-2024-3094)]
              </button>
            </div>
          </div>

          {/* SPEECH CHAT LOG */}
          <div className="bg-[#121212] border border-white/10 rounded-2xl p-4 flex flex-col gap-4 overflow-y-auto min-h-[280px] max-h-[300px] font-sans">
            {chatMessages.map((msg, idx) => (
              <div 
                key={idx} 
                className={`flex flex-col max-w-[90%] border p-4 rounded-xl gap-2 select-text ${
                  msg.sender === 'user' 
                    ? 'self-end bg-black border-zinc-800 text-zinc-200' 
                    : 'bg-zinc-955 border-white/5 text-zinc-300'
                }`}
              >
                <div className="flex justify-between items-center font-mono text-[9px] text-zinc-550 select-none gap-4 border-b border-white/5 pb-1">
                  <span className="font-bold uppercase tracking-widest text-[#CCFF00]">
                    {msg.sender === 'user' ? 'Client Workspace' : 'Security Council Oracle v1'}
                  </span>
                  <span className="flex items-center gap-1"><Clock className="w-2.5 h-2.5" /> {msg.timestamp}</span>
                </div>
                <p className="whitespace-pre-wrap leading-relaxed select-text text-xs">
                  {msg.text}
                </p>
              </div>
            ))}

            {isChatTyping && (
              <div className="flex items-center gap-2 self-start bg-black border border-white/5 p-3.5 text-xs font-mono text-[#CCFF00]">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                Generating vector embeddings & synthesizing threat intelligence...
              </div>
            )}
          </div>

        </div>

        {/* INPUT SEND ROW BAR */}
        <div className="flex items-center gap-2 border-t border-white/5 pt-4 mt-4 text-xs font-mono select-none">
          <input
            type="text"
            placeholder="PROBE THE SEC_COUNCIL AUDITING AGENT OR TYPE QUESTION..."
            value={chatInput}
            onChange={(e) => setChatInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleAgentPromptSubmit()}
            className="flex-1 bg-zinc-955 border border-white/10 px-4 py-3 text-white placeholder-zinc-700 font-mono tracking-wider focus:outline-none focus:border-[#CCFF00]"
          />
          <button
            onClick={() => handleAgentPromptSubmit()}
            className="bg-[#CCFF00] hover:bg-[#b5e000] text-black font-black uppercase tracking-widest px-6 py-3 cursor-pointer transition-all select-none"
          >
            SEND
          </button>
        </div>

      </div>

      {/* RAG RETRIEVAL VISUAL DEBUGGER */}
      <div className="lg:col-span-12 xl:col-span-6 bg-black border border-white/10 p-6 sm:p-8 flex flex-col gap-5">
        
        <div>
          <h3 className="text-sm font-bold tracking-tight text-white font-mono uppercase tracking-widest flex items-center gap-2 border-b border-white/5 pb-2.5">
            <Terminal className="text-amber-400 w-4 h-4" /> 
            [Real-time Grounding Tracer]
          </h3>
          <p className="text-zinc-500 font-sans text-xs mt-1.5 leading-relaxed">
            Whenever a question is dispatched, the agent queries the vector index mapping Cosine properties to augment client context before synthetically calling the generative model. View the telemetry logs:
          </p>
        </div>

        {/* STEPS PIPELINE */}
        <div className="flex flex-col gap-4 font-mono text-xs">
          
          {/* STEP 1 */}
          <div className={`p-4 border flex flex-col gap-2 transition-all duration-150 ${
            activeRagStep >= 0 
              ? 'bg-[#121212] border-[#CCFF00]/10' 
              : 'bg-black border-white/5 opacity-30 select-none'
          }`}>
            <div className="flex justify-between items-center">
              <span className="font-bold text-[#CCFF00] flex items-center gap-1.5">
                <span className="w-4 h-4 bg-zinc-950 border border-white/10 text-white flex items-center justify-center text-[10px] font-bold">1</span>
                Vector Embeddings Generation
              </span>
              <span className="text-[9.5px] text-zinc-600">text-embedding-004</span>
            </div>
            <p className="text-zinc-400 font-sans text-xs leading-relaxed select-text">
              Translate search terms into a structured coordinate system with 768 float variables:
            </p>
            {ragTrace?.queryEmbedding && (
              <div className="bg-black font-mono text-[10.5px] p-2.5 border border-white/5 select-all text-zinc-350 break-all select-all leading-normal">
                {ragTrace.queryEmbedding}
              </div>
            )}
          </div>

          {/* STEP 2 */}
          <div className={`p-4 border flex flex-col gap-2 transition-all duration-150 ${
            activeRagStep >= 1 
              ? 'bg-[#121212] border-[#CCFF00]/10' 
              : 'bg-black border-white/5 opacity-30 select-none'
          }`}>
            <div className="flex justify-between items-center">
              <span className="font-bold text-[#CCFF00] flex items-center gap-1.5">
                <span className="w-4 h-4 bg-zinc-950 border border-white/10 text-white flex items-center justify-center text-[10px] font-bold">2</span>
                Indices Retrieval & Cosine Rank Sweep
              </span>
              <span className="text-[9.5px] text-red-400 font-semibold uppercase">Threshold &gt; 50% match limit</span>
            </div>
            <p className="text-zinc-400 font-sans text-xs leading-relaxed">
              Scan our local structured files to match similar data concepts. Results:
            </p>
            {ragTrace?.highestMatchDoc && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[10px] font-mono leading-normal">
                <div className="bg-black border border-white/5 p-2.5 flex justify-between items-center">
                  <span className="text-zinc-500">Matched Node:</span>
                  <strong className="text-white select-all">{ragTrace.highestMatchDoc}</strong>
                </div>
                <div className="bg-black border border-white/5 p-2.5 flex justify-between items-center">
                  <span className="text-zinc-500">Matched Proximity:</span>
                  <strong className="text-[#CCFF00]">{ragTrace.similarity !== undefined ? Math.round(ragTrace.similarity * 100) : 0}%</strong>
                </div>
              </div>
            )}
          </div>

          {/* STEP 3 */}
          <div className={`p-4 border flex flex-col gap-2 transition-all duration-150 ${
            activeRagStep >= 2 
              ? 'bg-[#121212] border-[#CCFF00]/10' 
              : 'bg-black border-white/5 opacity-30 select-none'
          }`}>
            <div className="flex justify-between items-center font-bold text-[#CCFF00]">
              <span className="flex items-center gap-1.5">
                <span className="w-4 h-4 bg-zinc-950 border border-white/10 text-white flex items-center justify-center text-[10px] font-bold">3</span>
                Context Prompt Augmentation
              </span>
              <span className="text-[9.5px] text-zinc-650 uppercase">Grounding Synthesis</span>
            </div>
            <p className="text-zinc-400 font-sans text-xs leading-relaxed">
              Combine database segments natively wrapped inside standard delimiters to inform LLM results factual safety:
            </p>
            {ragTrace?.constructedPrompt && (
              <pre className="bg-black text-[9.5px] text-zinc-400 p-3 border border-white/5 overflow-x-auto select-text whitespace-pre leading-loose max-h-[140px] font-mono">
                {ragTrace.constructedPrompt}
              </pre>
            )}
          </div>

        </div>

      </div>

    </div>
  );
}
