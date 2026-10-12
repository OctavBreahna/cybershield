# CyberShield

Backend for a managed cybersecurity monitoring service for small and medium businesses. Built and run solo — handles continuous security scanning, automated alerting, client reporting, and VPN infrastructure for real paying clients.

## What it does

- **Automated security scanning** — port exposure, SSL certificate validity and expiry, domain reputation / blacklist status, checked on a recurring schedule per client
- **Scoring & reporting** — generates a 0–100 security score and a client-facing PDF report
- **Alerting** — sends immediate email alerts when a new issue is detected (e.g. SSL expiring soon, port newly open), plus daily/monthly summary reports
- **Managed VPN** — provisions and manages WireGuard VPN access per client (peer creation/removal, network isolation between clients, scoped access control)
- **Remediation tracking** — tracks and verifies when a flagged issue has been fixed

## Stack

Python · PostgreSQL · FastAPI · WireGuard · Resend / SendGrid (email) · nmap

## Architecture notes

- Each client's scans run independently on a schedule (`run_all_scans.py`, `hourly_watch.py`) and write results to PostgreSQL
- Reports are generated as PDFs (`report.py`) and delivered by email (`mailer.py`, with automatic failover between two email providers)
- VPN clients are provisioned via WireGuard (`vpn_manager.py`), with `iptables` rules enforcing network isolation so one client's VPN peer can never reach another's
- All configuration/secrets are loaded from environment variables — this repo contains no credentials, client data, or production configuration

## Status

In active production use since 2026, monitoring real client domains and managing live VPN infrastructure.

---

*This repository contains the application code only. No client data, credentials, or infrastructure configuration are included or tracked.*
