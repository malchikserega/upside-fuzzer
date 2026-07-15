# UpsideFuzz Documentation Index

This is the central documentation index for the **UpsideFuzz** platform — a coverage-guided REST API fuzzer for .NET. Start here or from [README.md](../README.md).

---

## Getting Started

| Document | Description |
|----------|-------------|
| [README.md](../README.md) | Project overview, quick start, feature table, and key flags |
| [INSTRUCTIONS.md](../INSTRUCTIONS.md) | Complete step-by-step runbook: prerequisites → instrument → grammar → fuzz → analyze |

---

## Architecture

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](../ARCHITECTURE.md) | Platform internals: SHM design, instrumentation pipeline, Go fuzzer components, epoch scheduling, mutation engine |
| [AI_CONTEXT.md](../AI_CONTEXT.md) | AI developer onboarding: component map, critical constraints, go-to-file guidance |

---

## Target Quickstarts

Step-by-step guides for instrumenting and fuzzing real-world applications:

| Target | Auth Style | Quickstart |
|--------|-----------|-----------|
| **eShopOnWeb** | JWT (login flow) | [QUICKSTART_ESHOP.md](../QUICKSTART_ESHOP.md) |
| **SimplCommerce** | Cookie + anti-forgery | [QUICKSTART_SIMPLCOMMERCE.md](../QUICKSTART_SIMPLCOMMERCE.md) |
| **BTCPayServer** | API key | [QUICKSTART_BTCPAYSERVER.md](../QUICKSTART_BTCPAYSERVER.md) |
| **Bitwarden** | JWT (identity service) | [QUICKSTART_BITWARDEN.md](../QUICKSTART_BITWARDEN.md) |

Which target to pick first → [README.md §Quickstarts](../README.md#quickstarts)

---

## Authentication

| Document | Description |
|----------|-------------|
| [FUZZER_AUTHENTICATION.md](FUZZER_AUTHENTICATION.md) | Canonical auth file schema, multi-identity scheduling, access-control campaign setup |
| [auth.identities.example.json](auth.identities.example.json) | Copyable example auth identity file |

---

## Security Research Reports

Campaign results and vulnerability analyses for all validated targets:

| Document | Target | Type |
|----------|--------|------|
| [BITWARDEN_REPORT.md](../BITWARDEN_REPORT.md) | Bitwarden | 30-min authenticated campaign findings |
| [BITWARDEN_MULTIAUTH_SECURITY_RUN_20260713.md](../BITWARDEN_MULTIAUTH_SECURITY_RUN_20260713.md) | Bitwarden | 15-min multi-auth validation run |
| [BTCPAYSERVER_REPORT.md](../BTCPAYSERVER_REPORT.md) | BTCPayServer | Initial fuzzing campaign findings |
| [BTCPAYSERVER_ESCALATION_ANALYSIS.md](../BTCPAYSERVER_ESCALATION_ANALYSIS.md) | BTCPayServer | Crash escalation analysis (DDoS / RCE paths) |
| [SIMPLCOMMERCE_REPORT.md](../SIMPLCOMMERCE_REPORT.md) | SimplCommerce | Baseline and professional dictionary campaign comparison |

---

## Benchmarks & Research

| Document | Description |
|----------|-------------|
| [BENCHMARK_AGENT_INSTRUCTIONS.md](../BENCHMARK_AGENT_INSTRUCTIONS.md) | Reproducible 20-minute Docker benchmark playbook: RESTler vs Void on 4 targets |

---

## Integrations

| Document | Description |
|----------|-------------|
| [MCP_INTEGRATION_GUIDE.md](../MCP_INTEGRATION_GUIDE.md) | Using Model Context Protocol (MCP) to enrich the fuzzer dictionary from live database data |

---

## Target Status

| Document | Description |
|----------|-------------|
| [TARGET_CANDIDATES.md](../TARGET_CANDIDATES.md) | Implemented targets and future fuzzing candidates |

---

## Go Fuzzer Reference

| Document | Description |
|----------|-------------|
| [void/README.md](../void/README.md) | Complete CLI flag reference, startup output guide, build for any platform, mutation categories |

---

**→ [Back to README](../README.md)**
