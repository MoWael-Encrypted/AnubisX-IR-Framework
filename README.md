# AnubisX: Incident Response Framework 🛡️

**A centralized platform for Detection Rules, Incident Response Playbooks, and Automated Workflows.**

[![Tech Stack](https://img.shields.io/badge/Stack-React%20%7C%20TypeScript%20%7C%20Vite%20%7C%20Tailwind-blue)]()
[![Course](https://img.shields.io/badge/Course-CSE344%20Cybersecurity-orange)]()
[![Status](https://img.shields.io/badge/Status-Active-success)]()

## 📖 Project Overview

**AnubisX** is a comprehensive incident response framework designed to centralize security operations resources. It bridges the gap between detection and response by providing a single source of truth for SOC analysts and incident responders.

The platform is built using **React.ts** and serves as a curated repository for:
* **Detection:** Standardized rules mapped to MITRE ATT&CK.
* **Response:** Actionable, downloadable PDF playbooks.
* **Automation:** Visual guides for **n8n** response workflows.

---

## 📺 System Demo

### Watch the AnubisX Walkthrough
[![Watch the Demo](https://img.youtube.com/vi/4YyKIuC_ga4/0.jpg)](https://youtu.be/4YyKIuC_ga4)
* (Click the image above to watch the video)

---

## 📸 Interface Screenshots

| **Landing Page** | **Detection Rules** |
|:---:|:---:|
| <img src="https://github.com/user-attachments/assets/3dba91b8-0b1a-4bdd-9d7e-351141fe07ec" alt="IR-home" width="100%"/> | <img src="https://github.com/user-attachments/assets/629384a2-2983-42b5-9c7c-417d421b6768" alt="IR-Rules" width="100%"/> |
| *Centralized Dashboard* | *Searchable Rule Catalog* |

| **IR Playbooks** | **Automated Workflows** |
|:---:|:---:|
| <img src="https://github.com/user-attachments/assets/ea4080ba-3dd2-4f3e-b9c8-afd1f407e03e" alt="IR-IR" width="100%"/> | <img src="https://github.com/user-attachments/assets/9c313edf-7e15-4ba9-a352-222c28e6dd4f" alt="IR-WF" width="100%"/> |
| *PDF Download Library* | *n8n Visual Guides* |

---

## 🚀 Key Features

### 🔍 1. Detection Rule Repository
A searchable catalog of **65+ detection rules**.
* **Formats:** Supports Sigma, YARA, Snort, and EQL.
* **MITRE ATT&CK Mapping:** Every rule is tagged with Tactics and Techniques (e.g., *T1059 Command and Scripting Interpreter*).
* **Operational Utility:** Includes "Copy Code" functionality for quick implementation in SIEMs/EDRs.

### 📘 2. Incident Response (IR) Playbooks
A library of **10+ standardized playbooks** covering critical attack scenarios.
* **Scenarios:** Data Breach, Ransomware, Phishing, Endpoint Beaconing, and more.
* **Standard Structure:** Each playbook follows NIST IR phases: *Identification, Containment, Eradication, Recovery, and Lessons Learned*.
* **Downloadable:** Available as high-quality PDFs stored in the public assets folder.

### 🤖 3. Automated Response Workflows
A collection of **15+ automation guides** designed for **n8n**.
* **Visual Logic:** Step-by-step visualizations showing Trigger, Enrichment, Decision, and Response nodes.
* **Use Cases:**
    * *Phishing Triage* (Enrichment via PhishTank/VirusTotal).
    * *Impossible Travel Verification* (GeoIP checks).
    * *Failed Login Monitoring* (Slack alerting).

---

## 📂 Folder Structure

The project uses a modern monorepo-like structure with `client` and `server` directories, powered by Vite and TypeScript.

```text
AnubisX/
├── .local/                 # Local configuration files
├── attached_assets/        # Project design assets and raw images
├── client/                 # Frontend Application (React + Vite)
│   ├── src/
│   │   ├── components/     # UI Components (Cards, Nav, Search)
│   │   ├── lib/            # Utility functions
│   │   ├── pages/          # Application Routes (Home, Rules, Playbooks)
│   │   └── data.ts         # Static Data (Rules, Playbooks, Workflows)
│   └── public/             # Static Assets (PDFs, Images)
├── server/                 # Backend Configuration (if applicable)
├── shared/                 # Shared Types and Schemas
│   └── schema.ts           # Database schema definitions
├── dist/                   # Production build output
├── node_modules/           # Dependencies
├── drizzle.config.ts       # Database configuration
├── tailwind.config.ts      # Tailwind CSS styling configuration
├── vite.config.ts          # Vite bundler configuration
└── package.json            # Project dependencies and scripts
```

## 💻 How to Use

Follow these steps to run the project locally.

### Prerequisites
* **Node.js** (v18 or higher)
* **npm** (Node Package Manager)

### Steps

1.  **Clone the Repository**
    Open your terminal and run:
    ```bash
    git clone [https://github.com/your-username/anubisx-framework.git](https://github.com/your-username/anubisx-framework.git)
    cd anubisx-framework
    ```

2.  **Install Dependencies**
    Install the required packages for both the client and server:
    ```bash
    npm install
    ```

3.  **Run the Development Server**
    Start the application in development mode:
    ```bash
    npm run dev
    ```

4.  **Access the Application**
    Open your browser and navigate to the local host URL provided in the terminal (usually `http://localhost:5000` or `http://localhost:5173`).

---

## 🔮 Future Roadmap

The project is actively evolving to close the "Triage Gap" identified in our research.

* **Investigation Runbooks (Q4 2025):** Interactive guides for verifying alerts (differentiating True/False Positives) before initiating full IR playbooks.
* **Community Portal:** A submission form allowing external security researchers to submit new Sigma rules to the repository.
* **API Gateway:** A REST API allowing SIEM tools to programmatically fetch the latest JSON version of detection rules.

---

## 👥 Team AnubisX

This project was developed by a specialized team under the supervision of **Dr. Eman Kamel**.

* **Mostafa Wael Hamdy**
* **Islam Walid**
* **Hamza Shaaban**
* **Samar Elkharat**
* **Shahd Emad**

---

