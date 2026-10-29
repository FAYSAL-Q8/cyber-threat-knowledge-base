/**
 * Author: Faysal Alibrahim
 * GitHub: https://github.com/FAYSAL-Q8
 */

import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(express.json());

const getGeminiClient = () => {
  const key = process.env.GEMINI_API_KEY;
  if (!key) {
    console.warn("WARNING: GEMINI_API_KEY environment variable is not defined");
  }
  return new GoogleGenAI({
    apiKey: key || "",
    httpOptions: {
      headers: {
        'User-Agent': 'cybersecurity-knowledge-engine',
      }
    }
  });
};

/**
 * Structured intelligence endpoint for threat blueprint profiling.
 */
app.post("/api/research", async (req, res) => {
  try {
    const { topic } = req.body;
    if (!topic || typeof topic !== "string" || topic.trim() === "") {
      return res.status(400).json({ error: "Search keyword or CWE topic is required." });
    }

    const ai = getGeminiClient();
    
    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: `Perform professional cybersecurity research and compile an active vulnerability threat blueprint profile regarding: "${topic}".`,
      config: {
        systemInstruction: `You are an authorized, elite security researcher. Return a highly detailed, professional, and comprehensive threat blueprint profiling the requested security weakness. You must provide clear explanations, fully-formed vulnerable code, secure remediated code, specific alternative payloads, and exploitation instructions. Make sure your payload example is a real, functional attack sequence. Output the result in structured JSON format according to the specification.`,
        responseMimeType: "application/json",
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            id: { type: Type.STRING, description: "A simple unique snake_case URL safe identifier, e.g. custom_cwe_123_bola" },
            category: { 
              type: Type.STRING, 
              enum: ["web-api", "server-os", "cloud-security"],
              description: "Web APIs, Host servers/Operating systems, or Multi-Cloud tenant instances"
            },
            name: { type: Type.STRING, description: "Official display name, e.g. SQL Injection or Graph Introspection Bypass" },
            cwe_id: { type: Type.STRING, description: "Standard MITRE CWE rating, e.g. CWE-918" },
            severity: { type: Type.STRING, enum: ["Critical", "High", "Medium", "Low"] },
            environment: { type: Type.STRING, description: "Involved runtime context, e.g. Kubernetes Host Nodes / node.js cluster" },
            technical_explanation: { type: Type.STRING, description: "Detailed multi-sentence explanation of inner workings, security risks, and technical root causes." },
            vulnerable_code_snippet: { type: Type.STRING, description: "Complete, representative vulnerable source code showing the flaw clearly." },
            vulnerable_code_lang: { type: Type.STRING, description: "Programming language code snippet is written in: e.g. javascript, typescript, python, java, c" },
            payload_example: { type: Type.STRING, description: "A real-world exploit payload vector, e.g. admin' OR 1=1 --" },
            remediation: { type: Type.STRING, description: "Detailed multi-sentence explanation of remediation steps and mitigation parameters." },
            remediation_code_snippet: { type: Type.STRING, description: "Complete, remediated secure source code showing the correct implementation or mitigation." },
            remediation_code_lang: { type: Type.STRING, description: "Matches vulnerable_code_lang" },
            exploit_steps: {
              type: Type.ARRAY,
              items: { type: Type.STRING },
              description: "Precise step-by-step instructions on how a pentester can identify, target, and validate this vulnerability safely in an authorized setting."
            }
          },
          required: [
            "id", "category", "name", "cwe_id", "severity", "environment", 
            "technical_explanation", "vulnerable_code_snippet", "vulnerable_code_lang", 
            "payload_example", "remediation", "remediation_code_snippet", 
            "remediation_code_lang", "exploit_steps"
          ]
        }
      }
    });

    if (!response.text) {
      throw new Error("No response content generated from model");
    }

    const data = JSON.parse(response.text);
    res.json(data);
  } catch (err: any) {
    console.error("Deep research API integration error: ", err);
    res.status(500).json({ error: err.message || "Deep inquiry process failed." });
  }
});

async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[FULL-STACK CORE] Security gateway running at http://localhost:${PORT}`);
  });
}

startServer();
