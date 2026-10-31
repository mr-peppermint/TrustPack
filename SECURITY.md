
# TrustPack – Security Analysis Methodology

## 1. Overview

TrustPack analyzes differences between source code and published npm packages to identify potentially suspicious changes.

It uses static analysis and a heuristic risk-scoring engine.

## 2. Security Checks

TrustPack currently checks for:

- Unexpected executable files
- Suspicious installation scripts
- Remote shell execution patterns
- Remote downloads
- Child process execution
- Added dependencies
- Dependency version changes
- Removed dependencies
- Package metadata differences

## 3. Risk Scoring

Each finding is assigned a predefined risk weight.

| Finding | Weight |
|---|---:|
| Unexpected executable | 15 |
| Added dependency | 10 |
| Dependency version changed | 10 |
| Removed dependency | 5 |
| Dynamic execution | 20 |
| Remote download | 15 |
| Remote shell execution | 40 |
| Encoded execution | 25 |
| Child process execution | 10 |

The maximum risk score is 100.

## 4. Risk Levels

| Risk score | Risk level |
|---|---|
| 0–24 | LOW |
| 25–59 | MEDIUM |
| 60–100 | HIGH |

A remote shell execution finding automatically forces HIGH risk.

## 5. Provenance Verification

TrustPack can use npm signature auditing to check registry signature verification status.

This is a provenance signal. It does not prove that the published package matches the source repository.

## 6. Limitations

- Static pattern matching can produce false positives.
- Risk scores are heuristic indicators, not probabilities.
- Multiple findings may describe related behavior in the same script.
- Static analysis cannot detect every malicious behavior.
- Signature verification does not establish source-to-package equivalence.
- TrustPack does not execute untrusted installation scripts.

## 7. Safety

Untrusted package scripts should never be executed during analysis.
