# CodeAlpha_Tasks

Completed tasks for the CodeAlpha Cybersecurity Internship, covering practical network analysis and application security review.

## Tasks

### [Task 01 — Basic Network Sniffer](./Task%2001%20-%20Basic%20Network%20Sniffer)

A Python packet sniffer built with Scapy that captures live network traffic and displays protocol, addressing, and payload details in real time. Demonstrates packet-level analysis, BPF filtering, and the practical case for encrypted protocols over plaintext ones.

**Stack:** Python 3, Scapy

### [Task 03 — Secure Coding Review](./Task%2003%20-%20Secure%20Coding%20Review)

A manual and tool-assisted security audit of a Flask/Python web application. Fourteen vulnerabilities were identified across authentication, session management, database access, and file handling — including SQL injection and an IDOR that were exploited live against a running instance to confirm real-world impact. Findings are mapped to the OWASP Top 10 (2021), each with severity ratings, proof-of-concept steps, and remediation code.

**Stack:** Python 3, Flask, SQLite
**Includes:** custom AST-based static analysis scanner, full findings report, and the audited application source.

## About

These tasks were completed as part of the CodeAlpha Cybersecurity Internship program.
