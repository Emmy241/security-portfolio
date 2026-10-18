# Security Portfolio

Hands-on security engineering portfolio: six projects built on a shared target
application (LendStack) and lab environment.

> ⚠️ **This repo is deliberately vulnerable by design.** LendStack is a
> fake multi-tenant lending SaaS built specifically to demonstrate security
> findings. Credentials in `.env` (and its git history) are **fake** — they
> exist to demonstrate secret-sprawl detection (finding V-06 in project #04).
> Do not use anything in this repo as production code. Nothing here connects
> to real systems, real data, or real customers.# Security Portfolio

Monorepo for six portfolio projects. Everything shares one target
environment (`lendstack/`) and one logging pipeline.

## Projects

| # | Title | Folder |
|---|-------|--------|
| 1 | Secure Multi-Tenant SaaS Architecture & Access Control | `projects/01-saas-architecture/` |
| 2 | Web Application & API Security Assessment | `projects/02-webapp-api-assessment/` |
| 3 | SIEM Detection Engineering & Incident Response | `projects/03-siem-detection/` |
| 4 | OAuth & JWT Security Review | `projects/04-oauth-jwt-review/` |
| 5 | Enterprise SOC Simulation & Threat Detection Lab | `projects/05-soc-lab/` |
| 6 | ISO 27001:2022 Implementation & Gap Assessment Toolkit | `projects/06-iso27001-toolkit/` |

## Target environment

`lendstack/` is a deliberately-vulnerable multi-tenant lending SaaS.
**Not safe to expose to any network.** Every host port is bound to
`127.0.0.1`. Planted vulnerabilities are enumerated in
`lendstack/docs/VULNS.md` (added in M1).

## Setup

See `docs/setup.md` for environment gotchas (BuildKit/Bake, YAML
indentation, port conflicts, fluent-bit formats).
