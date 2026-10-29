# CyberThreats Base

> **Live Application**: [https://cyberthreats-base.vercel.app/](https://cyberthreats-base.vercel.app/)

[![Live Deployment](https://img.shields.io/badge/Deployment-Live%20on%20Vercel-success?style=flat-square&logo=vercel)](https://cyberthreats-base.vercel.app/)
[![React](https://img.shields.io/badge/React-19.0-61DAFB?style=flat-square&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-v4.1-38B2AC?style=flat-square&logo=tailwind-css)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-CCFF00?style=flat-square)](./LICENSE)

CyberThreats Base is a production-grade, modular threat intelligence gateway, vulnerability repository, and offensive-defensive engineering platform designed to systematize web, server, and multi-cloud security assessments.

---

## Purpose

Modern security engineering often suffers from a critical disconnect: theoretical vulnerability registries (such as raw CVE IDs and abstract CWE definitions) lack actionable implementation details, while fragmented exploit blogs lack verified defensive remediation code and automated validation rules.

**CyberThreats Base solves this problem by uniting four core engineering disciplines into a cohesive workbench:**

1. **Theoretical Grounding**: Mapping each security flaw directly to formal MITRE CWE classifications, CVSS severity metrics, and attack surface categories (Web/API, Server OS, and Cloud Infrastructure).
2. **Offensive Verification**: Providing reproducible proof-of-concept payloads, weaponized request patterns, and automated response verification regexes for CI/CD test automation and ethical penetration testing.
3. **Defensive Hardening**: Pairing every vulnerability with side-by-side vulnerable source code and hardened production remediation implementations, supplemented by WAF rules and mitigation checklists.
4. **Threat Intelligence & Graph Modeling**: Visualizing attack relationship chains (e.g., SSRF pivoting to Cloud Metadata exfiltration, or SQL Injection enabling authentication bypass) alongside semantic vector search and deduplication controls.

Whether utilized by penetration testers constructing engagement audit trails, AppSec teams establishing secure coding standards, or DevSecOps engineers automating vulnerability scans, CyberThreats Base serves as a single source of truth for threat analysis.

---

## Core Features

- **Multi-Layer Attack Surface Catalog**: Exhaustive database spanning Web Applications, Microservice APIs, Operating Systems, Container Runtimes, and Cloud Services (AWS, GCP, Azure).
- **Side-by-Side Code Differentiators**: Direct comparisons between insecure code patterns and secure, production-ready remediation code across multiple languages (TypeScript, Python, Java, Go, C#).
- **Real-World CVE & Incident Scenarios**: Curated high-impact vulnerabilities (e.g., Log4Shell, Spring4Shell, ProxyLogon, Atlassian OGNL) with automated HTTP request parameters and regex assertion rules.
- **Automated Verification Matrix**: Built-in test configurations (HTTP methods, endpoints, custom headers, payload bodies, and response regex patterns) ready for automation pipelines or terminal execution.
- **Penetration Testing Workbench**: Interactive project tracker for auditing targets, managing checklist verification states (Discovered, Verified, Remediated), and generating findings reports.
- **Interactive Relational Logic Graph**: Visual graph representation of vulnerability chains, illustrating how individual weaknesses correlate and escalate into catastrophic multi-stage exploits.
- **Target Directory & Scope Manager**: Centralized inventory for cataloging audit scopes, endpoint domains, authentication requirements, and testing profiles.
- **Semantic Intelligence & Grounding Visualizer**: Retrieval-Augmented Generation (RAG) assistant with visual cosine similarity distance metrics matching queries against the threat database.
- **Deduplication Sandbox**: Ingestion filter computing Jaccard term overlap and cosine vector proximity to prevent redundant threat submissions.
- **WCAG-Compliant Dual Theme**: High-contrast dark and light modes engineered specifically for prolonged security operations center (SOC) sessions without overlapping text or background colors.

---

## Comprehensive Usage Guide

### 1. Navigating the Attack Surface Catalog
The **Catalog View** functions as the primary vulnerability intelligence engine:
- **Filtering by Infrastructure Layer**: Toggle between **Web / API**, **Server OS**, and **Cloud** tabs to isolate vulnerabilities relevant to your target environment.
- **Severity & Taxonomical Filtering**: Filter by severity level (**Critical**, **High**, **Medium**, **Low**) or search by CWE number (e.g., `CWE-89`, `CWE-918`), CVE identifiers, or threat title keywords.
- **Inspecting Vulnerability Dossiers**: Select any vulnerability card to expand its complete security dossier:
  - **Overview**: High-level impact summary, CVSS severity, and affected software layers.
  - **Vulnerable vs. Remediated Code**: Review side-by-side code blocks showing the root-cause bug and the corresponding secure defensive fix.
  - **Verification Procedure**: Follow ordered, step-by-step instructions to reproduce the vulnerability in a controlled lab.
  - **Payload Vectors**: Copy verified proof-of-concept payloads and test strings for ethical validation.
  - **Mitigation & Countermeasures**: Implement Defense-in-Depth guidelines, including WAF regex rules, network segmentation, and principle-of-least-privilege configurations.
- **Live Threat Research**: Trigger the deep research assistant on any topic to synthesize an expanded JSON threat profile.

### 2. Executing Real-World CVE Scenarios & Automation Regex
The **CVE Scenarios** module translates abstract CVE advisories into executable validation criteria:
- **Scenario Inspection**: Select any listed scenario (e.g., Log4Shell `CVE-2021-44228`, Spring4Shell `CVE-2022-22965`, Fortinet SSL-VPN `CVE-2022-40684`) to review the breach history, root mechanism, and real-world blast radius.
- **Automated Test Parameters**: Review exact HTTP request structures:
  - **Method**: Target HTTP verb (`GET`, `POST`, `PUT`, `PATCH`).
  - **Target Endpoint**: Vulnerable API path or URI template.
  - **Headers**: Dynamic headers required to trigger the flaw (e.g., `X-Api-Version`, `Forwarded`, `Content-Type`).
  - **Body Template**: Raw JSON or multipart payload structures required to elicit the vulnerability.
- **Response Verification Regex**: Inspect the compiled regular expression used to confirm vulnerability existence (e.g., matching JVM DNS callback reflections, stack trace leakages, or serialized gadget execution markers). These regexes can be directly integrated into CI/CD security pipelines or custom automation scripts.

### 3. Managing Audits with the Pentest Workbench & Graph
The **Pentest View** provides a structured environment for conducting security assessments:
- **Project Tracking**: Create and manage distinct security audit engagements for web applications, microservices, or cloud tenants.
- **Interactive Relational Graph**: Open the D3-powered relationship graph to visualize attack chain links. Nodes represent vulnerabilities, while directed edges illustrate exploit escalation paths (e.g., SSRF &rarr; AWS IMDSv1 token theft &rarr; S3 data exfiltration).
- **Checklist Verification Workflow**: Mark vulnerabilities across progressive assessment states:
  - `Discovered`: Identified during reconnaissance or initial scanning.
  - `Verified`: Confirmed via manual proof-of-concept payload execution.
  - `Remediated`: Verified as patched following development team fixes.
- **Reporting & Export**: Export complete engagement findings as structured data for inclusion into client-ready penetration testing deliverables.

### 4. Scoping in the Target Directory
The **Targets View** simplifies multi-target scope management:
- **Domain & IP Inventory**: Catalog testing boundaries, in-scope domains, staging environments, and production IP ranges.
- **Testing Profiles**: Attach target-specific variables, such as testing credentials, base URLs, rate limits, and proxy configurations.
- **Fuzzing Notes**: Record observed web server banners, open ports, and anomalous behavioral responses for collaborative auditing.

### 5. Leveraging Semantic RAG Intelligence & Grounding Visualizer
The **RAG Assistant View** demonstrates modern vector-based threat querying:
- **Natural Language Search**: Enter technical security questions (e.g., *"How do I remediate SSRF in Kubernetes cloud workloads?"*).
- **Grounding Inspection**: View the exact threat vectors retrieved by the semantic indexing engine. The visualizer illustrates cosine proximity scores, demonstrating which CWE profiles and CVE scenarios grounded the answer.

### 6. Validating Threat Entries in the Deduplication Sandbox
The **Sandbox View** ensures database integrity by preventing redundant entries:
- **Candidate Submission**: Input a proposed threat definition, title, CWE mapping, and description.
- **Similarity Scoring**: The sandbox computes real-time Jaccard term overlap and vector cosine similarity against all existing records in the database.
- **Collision Prevention**: If a collision is detected (similarity score > 0.65), the sandbox highlights the matching existing vulnerability, preventing database bloat and maintaining strict taxonomical quality.

### 7. Technical Help & Reference Center
- Click the **Help** button located in the global footer from any view.
- Access technical definitions, methodology standards, and documentation without cluttering the primary operational interfaces.

### 8. Theme & High-Contrast Adaptation
- Toggle between **Dark Mode** and **Light Mode** using the theme switcher in the top navigation bar.
- Both themes are engineered with rigorous WCAG contrast standards, ensuring no text is obscured by background surfaces across all tables, code viewers, and interactive badges.

---

## Tech Stack & Architecture

### Core Technologies
- **Frontend Framework**: React 19 (TypeScript)
- **Build System**: Vite 6
- **Styling**: Tailwind CSS v4 with custom dark/light theme tokens
- **Data Visualization**: D3.js (Interactive relational attack graphs and severity metrics)
- **Icons**: Lucide React
- **Motion Engine**: Motion (Framer Motion)
- **Backend Server**: Express 4 mounted via Vite middleware with Node.js TypeScript runner (`tsx`)
- **Intelligence Model**: Google GenAI SDK (`@google/genai`) for structured threat research synthesis

### Directory Structure

```text
├── server.ts                  # Express HTTP backend & /api/research endpoint
├── src/
│   ├── main.tsx               # Application bootstrap & React StrictMode root
│   ├── App.tsx                # Master container, state coordinator & footer navigation
│   ├── index.css              # Global styles, Tailwind CSS v4, and theme surface definitions
│   ├── types.ts               # Strong TypeScript models (Vulnerability, CVE Case, Project, Feed)
│   ├── components/            # Modular feature views
│   │   ├── CatalogView.tsx         # Searchable attack surface catalog with code diffs
│   │   ├── CasesView.tsx           # Real-world CVE scenarios & regex automation matrix
│   │   ├── PentestView.tsx         # Pentest project manager & D3 relational logic graph
│   │   ├── WebsitesView.tsx        # Target directory & testing profiles
│   │   ├── SandboxView.tsx         # Cosine-similarity deduplication testing sandbox
│   │   ├── AgentRagView.tsx        # Semantic embedding retrieval & grounding visualizer
│   │   ├── SourcesView.tsx         # Upstream intelligence feeds (NIST NVD, CISA KEV)
│   │   ├── HelpModal.tsx           # Centralized help & methodology reference drawer
│   │   ├── SeverityDashboard.tsx   # Interactive D3 vulnerability distribution chart
│   │   └── AboutView.tsx           # Platform architecture specifications & ethical guidelines
│   └── data/                  # Core threat intelligence datasets
│       ├── vulnerabilities.ts      # Primary vulnerability catalog seed
│       ├── cveScenariosData.ts     # Seeded CVE case studies & automated regex rules
│       ├── generator.ts            # Procedural catalog expansion generator
│       └── sources.ts              # Upstream security intelligence feeds
├── public/
│   ├── robots.txt             # Web crawler indexing policy
│   └── sitemap.xml            # Search engine sitemap
└── vercel.json                # Single-page application routing & security headers
```

---

## Local Development Setup

To run CyberThreats Base locally on your workstation:

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher (or pnpm / yarn)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/FAYSAL-Q8/cybersecurity-knowledge-source.git
   cd cybersecurity-knowledge-source
   ```

2. **Install project dependencies:**
   ```bash
   npm install
   ```

3. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   *(Optional)* Add a `GEMINI_API_KEY` in `.env` to enable dynamic real-time threat intelligence synthesis:
   ```env
   GEMINI_API_KEY="your-api-key-here"
   PORT=3000
   NODE_ENV="development"
   ```

4. **Start the local development server:**
   ```bash
   npm run dev
   ```
   The application will be accessible at `http://localhost:3000`.

5. **Validate TypeScript & linting:**
   ```bash
   npm run lint
   ```

---

## Author

**Faysal Alibrahim**  
GitHub: [https://github.com/FAYSAL-Q8](https://github.com/FAYSAL-Q8)

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](./LICENSE) file for complete details.
