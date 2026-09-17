# 📖 AegisLog Backend Architecture: The Plain-English Guide

> **Target Audience:** College professors, academic evaluators, hackathon judges, and non-technical stakeholders.  
> **Goal:** Explain how the backend works in 2 minutes without confusing jargon.

---

## 💡 The 10-Second Summary (Explain Like I'm 5)

Imagine a massive international airport where thousands of travelers arrive from 50 different countries:
- Some hold **English** passports, some hold **French**, some hold **Japanese**, and some arrive with **hand-written notes** or unreadable documents.
- The airport cannot have 50 separate customs systems. It needs **ONE standard universal entry form**.

**AegisLog's backend is that universal customs officer:**
1. It looks at the incoming message (the raw log).
2. It detects what language/format it is in (Cisco, JSON, CEF, Syslog, etc.).
3. If it's a known language, it reads it instantly in under **0.2 milliseconds**.
4. If it's a completely new or alien language, its **built-in AI learner** figures out the pattern, creates a new rule, and remembers it forever.
5. It translates all the data into one clean, universal international format (**OCSF v1.1**).
6. It grades its own work with a **confidence score (0 to 100%)**.
7. If anything looks suspicious (like a cyber attack), it flags the log with a **MITRE ATT&CK security risk tag**.
8. It saves everything into a lightning-fast database (**DuckDB**) for instant searching.

---

## 🗂️ The Backend Folder Cheat Sheet (6 Simple Blocks)

Here is what every folder in the backend actually does in one sentence:

| Folder | What It Does (Plain English) | Real-World Analogy |
| :--- | :--- | :--- |
| **`parsers/`** | **The Translators:** 6 fast plugins that recognize and read known log types (Cisco, JSON, CEF, LEEF, Syslog, Linux Audit). | The fast-track biometric passport gates at an airport. |
| **`inference/`** | **The Smart Learner:** When an unknown log arrives, it extracts the pattern (Drain3 algorithm) and learns how to read it automatically. | A linguist creating a new dictionary entry for a foreign dialect. |
| **`core/`** | **The Central Brain & Translator:** Converts all extracted fields into the universal OCSF format, normalizes dates, and calculates accuracy scores. | The official universal immigration form everyone gets transcribed into. |
| **`hitl/`** | **Human-In-The-Loop Review:** Holds low-confidence or confusing logs in a queue so a human analyst can review and approve them with 1 click. | The customs officer's secondary inspection desk for questionable papers. |
| **`storage/`** | **The Data Vault:** Stores millions of processed logs in DuckDB (sub-millisecond SQL searches) and dead-letter logs for auditing. | The permanent, searchable national archive vault. |
| **`api/`** | **The Front Door (FastAPI):** Exposes simple web URLs so other computers and SIEM servers can send logs into the system over HTTP. | The airport arrival gates where planes and luggage arrive. |

---

## 🔄 The 6-Step Journey of a Log (Data Flow)

Here is the exact step-by-step path every single log takes from arrival to storage:

```
[Raw Log Arrives]
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 1: Fast-Path Identification (parsers/)                 │
│ Does it match Cisco, CEF, LEEF, Syslog, JSON, or Auditd?    │
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
             YES                               NO (Unseen format)
               │                               │
               ▼                               ▼
       [Fast Plugin Runs]             ┌─────────────────────────────────┐
       (< 200 microseconds)           │ STEP 2: Cold-Path AI Synthesis  │
                                      │ (inference/)                    │
                                      │ • Drain3 extracts structure     │
                                      │ • Creates new regex rule        │
                                      │ • Saves rule to SQLite for next │
                                      │   time                          │
                                      └────────────────┬────────────────┘
                                                       │
               ┌───────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 3: Fallback Safety Net (parsers/fallback/)              │
│ If anything is partially corrupt, extract whatever IPs/dates │
│ possible — NEVER throw away or drop any log silently!        │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 4: Canonical Normalization (core/normalizer.py)         │
│ Convert all different field names into ONE standard format:  │
│   • Timestamps  -> Standard ISO-8601 UTC                    │
│   • Source IP   -> Classified (Private / Public)            │
│   • Action      -> ALLOW, DENY, DROP, or ALERT              │
│   • Threat Tag  -> MITRE ATT&CK Technique ID & Risk Score    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ STEP 5: Calibrated Confidence Scoring (core/confidence.py)  │
│ System grades its own work across 4 dimensions:              │
│   1. Format syntax validity (0-100%)                        │
│   2. Field values valid (IPs, ports, dates) (0-100%)        │
│   3. Standard schema completeness (0-100%)                   │
│   4. Overall composite score (0-100%)                       │
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
        Score >= 60%                    Score < 60%
               │                               │
               ▼                               ▼
┌─────────────────────────────┐ ┌─────────────────────────────┐
│ STEP 6A: Direct Ingestion   │ │ STEP 6B: Human Review Queue │
│ Saved to DuckDB for instant │ │ (hitl/)                     │
│ analyst threat hunting      │ │ Queued for 1-click human    │
│                             │ │ verification in Dashboard   │
└─────────────────────────────┘ └─────────────────────────────┘
```

---

## 🎯 Top 5 Questions Teachers & Judges Ask (and How to Answer Them)

### Q1: "Why is your backend so fast (38,000+ logs per second)?"
> **Answer:** *"Because we use a **Deterministic-First** architecture. We don't send every log through a slow LLM or AI model. Over 98% of known logs go through compiled regex plugins in `parsers/` that take less than 0.2 milliseconds. We only activate the AI learner when a genuinely novel, unseen format arrives."*

### Q2: "What happens if a log is completely broken, corrupted, or has weird characters?"
> **Answer:** *"We have a **Zero Silent Drop guarantee**. Our `GenericFallbackExtractor` in `parsers/fallback/` rescues any valid IPs, timestamps, and action keywords. We preserve the verbatim 100% original raw text in `record.raw_log`, and tag it with error codes so nothing is ever lost for defense forensics."*

### Q3: "What is OCSF v1.1 and why did you use it?"
> **Answer:** *"OCSF stands for **Open Cybersecurity Schema Framework**, an open industry standard supported by AWS, Splunk, and IBM. Instead of inventing our own custom field names, we map every log into OCSF v1.1 so any defense SIEM or security tool can immediately understand the output."*

### Q4: "How does the system learn new formats without an external internet connection?"
> **Answer:** *"Our system has an air-gapped **heuristic template miner** (`inference/template_miner.py`) powered by the Drain3 algorithm. It clusters logs, detects variable tokens (like IPs and dates), and synthesizes a regular expression locally in memory without needing OpenAI, Gemini, or internet access. However, it can optionally plug into local Ollama if desired."*

### Q5: "What is Human-In-The-Loop (HITL)?"
> **Answer:** *"If a log has low confidence (below 60%), it is routed to `hitl/review_queue.py`. A security analyst sees it in Tab 4 of the dashboard, corrects the field mapping, and clicks 'Approve'. That single click compiles a new rule into our permanent SQLite store so the system never needs human help for that log type again."*

---

## 📊 Summary: Backend File-by-File Index

| File Path | Plain English Purpose |
| :--- | :--- |
| `api/app.py` | The FastAPI server handling HTTP requests and serving web pages. |
| `core/pipeline.py` | The central traffic controller orchestrating the 6-stage log pipeline. |
| `core/normalizer.py` | The translator that cleans dates, validates IP addresses, and standardizes actions. |
| `core/schema.py` | The strict data contract defining the OCSF v1.1 canonical record structure. |
| `core/confidence.py` | The automated grading engine calculating the 4-level confidence scores. |
| `core/multiline.py` | Stitches split Java/Python stack traces back into a single event. |
| `parsers/registry.py` | Dispatches incoming logs to the correct parser plugin. |
| `inference/template_miner.py` | Drain3 algorithm that detects the structural skeleton of unseen logs. |
| `inference/rule_store.py` | SQLite database storing learned rules so they persist across restarts. |
| `hitl/review_queue.py` | The waiting room for uncertain logs awaiting human review. |
| `storage/duckdb_sink.py` | Fast embedded columnar database for sub-second SQL threat analytics. |

