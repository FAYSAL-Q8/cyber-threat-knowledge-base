# Cybersecurity Knowledge Source

Cybersecurity Knowledge Source is a production-grade, modular threat intelligence gateway and offensive-defensive engineering repository designed to systematize web, server, and multi-cloud vulnerability analysis. It bridges the gap between theoretical CWE taxonomies and real-world penetration testing by coupling structured threat profiles with verifiable proof-of-concept payloads, automated verification regex rules, and remediation blueprints.

---

## Core Features

- **Comprehensive Attack Surface Catalog**: Detailed vulnerability profiles covering Web APIs, Server Operating Systems, and Cloud Environments mapped directly to MITRE CWE ratings and ATT&CK techniques.
- **Full Remediation & Exploitation Blueprints**: Each vulnerability includes functional vulnerable source code snippets, secured remediation code, step-by-step verification flows, and curated payload vectors.
- **Real-World Incident & CVE Scenarios Database**: Rich scenario database featuring automated test parameters (HTTP methods, endpoints, dynamic request headers, JSON body templates, and response regex verification rules) for CI/CD security automation.
- **Target Environment Directory**: Directory module for cataloging audit scopes, target infrastructure endpoints, observed outcomes, and reusable testing profiles.
- **Active Pentesting Checklist & Relation Graph**: Interactive auditing workbench mapping security flaw relationships (e.g., SSRF to Cloud Metadata exposure, SQLi to JWT secret leaks) with project export capabilities.
- **Semantic Intelligence Assistant & RAG Visualizer**: Interactive grounding tracer simulating vector embeddings (cosine proximity matching) against local intelligence indices to augment security reasoning.
- **Seeding Sandbox & De-duplication Engine**: Local rule validator that computes term intersection and cosine similarity scores to prevent duplicate vulnerability entries before ingestion.
- **Deep Threat Intelligence Synthesis**: Backend endpoint generating structured JSON threat profiles with automated fallback to robust offline synthesis.
- **Dual-Mode High Contrast Interface**: Resilient dark/light theme switching with smooth UI state persistence via localStorage.

---

## Tech Stack & Architecture

### Frontend
- **Framework**: React 19 (TypeScript)
- **Styling**: Tailwind CSS v4 with custom dark/light color surfaces and responsive typography
- **Icons**: Lucide React
- **Data Visualization**: D3.js (Severity distribution and metrics rendering)
- **Motion**: Motion (Framer Motion)
- **Build Tool**: Vite 6

### Backend & Middleware
- **Runtime**: Node.js with TypeScript (`tsx` runner)
- **HTTP Server**: Express 4 mounted with Vite middleware for unified development and static production serving
- **AI / Model Integration**: Google GenAI SDK (`@google/genai`) for structured threat research synthesis

### Architecture Overview

```text
├── server.ts              # Express server with Vite middleware & /api/research endpoint
├── src/
│   ├── main.tsx           # Application entry point with React StrictMode
│   ├── App.tsx            # Root component with navigation state, theme control, & global footer
│   ├── index.css          # Tailwind CSS configuration, theme variables, & surface overrides
│   ├── types.ts           # Strict TypeScript interfaces for vulnerabilities, cases, & feeds
│   ├── components/        # Modular view components
│   │   ├── CatalogView.tsx         # Searchable attack surface catalog with deep research
│   │   ├── CasesView.tsx           # Real-world incident scenarios & regex automation matrix
│   │   ├── PentestView.tsx         # Pentesting project manager & relational logic graph
│   │   ├── WebsitesView.tsx        # Target directory & reusable fuzzing profiles
│   │   ├── SandboxView.tsx         # Cosine-similarity deduplication testing sandbox
│   │   ├── AgentRagView.tsx        # Semantic embedding retrieval & grounding tracer
│   │   ├── SourcesView.tsx         # Upstream intelligence feeds (NIST NVD, CISA KEV)
│   │   ├── SeverityDashboard.tsx   # D3.js interactive vulnerability distribution chart
│   │   └── AboutView.tsx           # Technical architecture specifications & disclaimer
│   └── data/              # Initial threat intelligence & scenario seeds
│       ├── vulnerabilities.ts      # Core vulnerability baseline
│       ├── cveScenariosData.ts     # Seeded CVE cases
│       ├── generator.ts            # Procedural catalog expansion generator
│       └── sources.ts              # External intelligence feed sources
```

---

## Prerequisites & Setup

### Prerequisites
- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher (or pnpm / yarn)
- **Gemini API Key** *(optional, for live deep research)*: Obtain from [Google AI Studio](https://aistudio.google.com/)

### Installation Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/FAYSAL-Q8/cybersecurity-knowledge-source.git
   cd cybersecurity-knowledge-source
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` to provide your API key (if leveraging dynamic research):
   ```env
   GEMINI_API_KEY="your-api-key-here"
   PORT=3000
   NODE_ENV="development"
   ```

---

## Usage / Execution Guide

### Development Server
Start the full-stack application in development mode with hot-reloading:
```bash
npm run dev
```
Open your browser and navigate to `http://localhost:3000`.

### Type Checking & Linting
Validate TypeScript types across the entire project:
```bash
npm run lint
```

### Production Build & Execution
Build the client bundle and compile the Node.js server for production deployment:
```bash
npm run build
npm start
```

### Deploy to Vercel

You can deploy this repository instantly to Vercel with zero extra configuration (using `vercel.json` SPA routing preset):

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2FFAYSAL-Q8%2Fcybersecurity-knowledge-source)

1. Push your repository to GitHub under `https://github.com/FAYSAL-Q8/cybersecurity-knowledge-source`.
2. Visit [Vercel Dashboard](https://vercel.com/new) and import the repository.
3. Keep default settings:
   - **Framework Preset**: `Vite`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
4. Add environment variables if desired (`GEMINI_API_KEY`).
5. Click **Deploy**.

---

## Author

**Faysal Alibrahim**
- GitHub: [https://github.com/FAYSAL-Q8](https://github.com/FAYSAL-Q8)

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](./LICENSE) file for details.
