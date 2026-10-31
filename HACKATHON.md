# HACKTOBERFEST 2026 — HACK DAY SONIPAT

## Team Information

**Team Name:** The Debuggers

**Event:** Hacktoberfest 2026 — Hack Day Sonipat  
**Venue:** Newton School of Technology, Rishihood University

## Team Members

1. Dixit Dahiya
2. Himank Choudhary
3. Kanan Gupta
4. Panshul Sharma

## Selected Problem Statement

**Problem Statement 04: Published Package vs Source Code Integrity Analyzer**

**Category:** Software Supply Chain Security | Package Management | Security Automation

### Problem Description

Developers commonly review source code hosted on platforms such as GitHub but install software packages distributed through package registries such as npm and PyPI. However, the published package is not always identical to the source repository that developers have reviewed.

Build processes, generated files, release scripts, and potentially malicious modifications can introduce differences between reviewed source code and distributed packages. These differences can create software supply-chain security risks.

Our objective is to develop an intelligent package integrity analysis tool that compares published packages against their corresponding source repositories, identifies unexpected or suspicious modifications, and explains the differences with supporting evidence.

### Our Proposed Solution — TrustPack

TrustPack is an open-source software supply-chain integrity analyzer designed to help developers verify the integrity of published npm packages against their corresponding source repositories.

The application will:

- Retrieve published npm packages and their metadata.
- Identify and retrieve corresponding source repositories.
- Compare source files with published package contents.
- Generate file-level integrity reports using cryptographic hashing.
- Identify additional, missing, and modified files.
- Recognize common generated files and legitimate build artifacts.
- Detect potentially suspicious modifications and unexpected package changes.
- Analyze package metadata, dependencies, and lifecycle scripts.
- Provide evidence-backed risk assessments and explanations.
- Generate structured reports to help developers investigate package integrity.

Our initial implementation will focus on npm packages, with the architecture designed to support additional package ecosystems in the future.

## AI Models Used

**Model:** GPT-OSS-120B  
**License:** Apache 2.0  
**Inference Provider:** Groq

### Reason for Model Selection

We selected GPT-OSS-120B because it is an open-weight reasoning model suitable for analyzing complex technical information and generating structured explanations.

Within TrustPack, the model will serve as an AI-powered security explanation engine.

It will be used to:

- Explain differences between published package files and source code.
- Analyze potentially suspicious code modifications.
- Explain possible security implications of unexpected changes.
- Summarize dependency and package metadata changes.
- Generate human-readable security findings and investigation recommendations.
- Communicate uncertainties rather than making unsupported security claims.

We chose this model to make technical integrity reports easier for developers and maintainers to understand while retaining evidence-based analysis.

**Important:** Package downloading, cryptographic hashing, file comparison, provenance verification, and deterministic security checks will be performed by our application's backend. GPT-OSS-120B will assist with contextual analysis and explanations rather than independently determining whether a package is safe or malicious.

## Technology Stack

- **Frontend:** React, Vite, Tailwind CSS
- **Backend:** Python, FastAPI
- **Package Registry:** npm Registry API
- **Source Retrieval:** GitHub REST API
- **Integrity Verification:** SHA-256
- **AI Model:** GPT-OSS-120B
- **Inference Provider:** Groq
- **Testing:** Pytest
- **CI/CD:** GitHub Actions

## Project Goal

Our goal is to improve software supply-chain transparency by helping developers understand whether published packages correspond to their reviewed source code, identify unexplained modifications, and make better-informed security decisions.

We aim to provide an accessible, evidence-driven tool that makes package integrity analysis easier and more transparent for the open-source ecosystem.