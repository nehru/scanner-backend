# Scanner Backend

[![Python Version](https://img.shields.io/badge/python-3.10+-blue)]()

## Overview

`scanner-backend` is a backend service for a **vulnerability scanning tool**.  
It is designed to analyze code (Java and other supported languages) and detect potential security issues using customizable rules.

This repository contains the main backend logic, database handling, and scanning engines required for the application.

---

## Features

- Java code scanning with custom security rules
- Database integration for storing scan results
- Configurable scanning pipelines
- Extensible architecture to add new scanners or engines
- REST API endpoints (if integrated with a frontend)
- Lightweight and easy to deploy

---
                           +----------------------+
                           |      Client / UI     |
                           |  (Optional Frontend) |
                           +----------+-----------+
                                      |
                                      v
                           +----------------------+
                           |     main.py          |
                           |  (Application Entry) |
                           +----------+-----------+
                                      |
             +------------------------+------------------------+
             |                        |                        |
             v                        v                        v
    +----------------+       +----------------+       +----------------+
    | Config Loader  |       | Scanner Engine |       | Database Layer |
    |  config.yaml   |       |  (Java, etc.)  |       | (Scan Results) |
    +----------------+       +----------------+       +----------------+
             |                        |                        |
             v                        v                        v
     +---------------+       +----------------+       +----------------+
     | Custom Rules  |       | Code Parsing   |       | DB Connection  |
     | (YAML / Python)|       | & Analysis    |       | & Storage      |
     +---------------+       +----------------+       +----------------+
             |                        |
             +-----------+------------+
                         |
                         v
                 +----------------+
                 |  Scan Output   |
                 |  (JSON / Logs) |
                 +----------------+


Explanation

Client / UI (Optional):
Can be a frontend or API consumer that triggers scans and views results.

main.py:
Entry point that orchestrates the scanning pipeline.

Config Loader:
Loads settings from config.yaml such as DB connections, engine configurations, and rules.

Scanner Engine:
Handles the actual code scanning. Currently supports Java, but the architecture allows adding more engines.

Database Layer:
Stores scan results, metadata, and logs.

Custom Rules:
User-defined security rules for scanning.

Code Parsing & Analysis:
Scanner engine parses code, applies rules, and generates findings.

Scan Output:
Consolidates results, logs, and optionally returns them to the client.


