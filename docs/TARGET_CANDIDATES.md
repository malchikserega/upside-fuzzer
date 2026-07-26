# UpsideFuzz — Target Status

This document tracks the status of all fuzzing targets in the repository: those already implemented and validated, and those under consideration for future work.

**→ [Back to README](../README.md)**

---

## Implemented Targets

All targets below have been fully instrumented with `fuzz-prep-multi.py`, have an active quickstart guide, and have been validated with at least one documented fuzzing campaign.

| Target | Type | Auth | Quickstart | Report |
|--------|------|------|-----------|--------|
| **eShopOnWeb** | Sample store REST API | JWT (login flow) | [QUICKSTART_ESHOP.md](QUICKSTART_ESHOP.md) | — |
| **SimplCommerce** | Modular e-commerce monolith | Cookie + anti-forgery | [QUICKSTART_SIMPLCOMMERCE.md](QUICKSTART_SIMPLCOMMERCE.md) | [SIMPLCOMMERCE_REPORT.md](reports/SIMPLCOMMERCE_REPORT.md) |
| **BTCPayServer** | Payment processor (Greenfield API) | API key | [QUICKSTART_BTCPAYSERVER.md](QUICKSTART_BTCPAYSERVER.md) | [BTCPAYSERVER_REPORT.md](reports/BTCPAYSERVER_REPORT.md) · [Escalation Analysis](reports/BTCPAYSERVER_ESCALATION_ANALYSIS.md) |
| **Bitwarden** | Password manager backend | JWT (identity service) | [QUICKSTART_BITWARDEN.md](QUICKSTART_BITWARDEN.md) | [BITWARDEN_REPORT.md](reports/BITWARDEN_REPORT.md) |
| **Jellyfin** | Media server | Static token | See [BENCHMARK_AGENT_INSTRUCTIONS.md §9](BENCHMARK_AGENT_INSTRUCTIONS.md) | — |

### Which target to pick first

- **eShopOnWeb** — smallest end-to-end target; use it to verify the full pipeline works before moving to more complex targets.
- **Bitwarden** — best for multi-user auth, IDOR, and deep business logic; requires MSSQL and the identity service.
- **BTCPayServer** — best for API-key auth and a larger service graph; Greenfield API has rich producer/consumer chains.
- **SimplCommerce** — best for anti-forgery tokens and cookie-based auth; heaviest framework surface area.
- **Jellyfin** — best for large API surface exploration; used as a benchmark target in the research paper.

---

## Future Candidates

Targets not yet implemented in this repository but identified as high-value candidates.

### Squidex (Headless CMS / CQRS + Event Sourcing)

**Repository:** [https://github.com/Squidex/squidex](https://github.com/Squidex/squidex)

Squidex is a modern headless CMS built on ASP.NET Core with MongoDB, heavily using CQRS and Event Sourcing patterns.

**Why it is a strong candidate:**
- Fuzzing Event-Sourced systems is difficult because state is built from a history of events rather than simple CRUD. This is a natural stress test for the Sequence Engine.
- Rich producer/consumer chain opportunities: Schema creation → Content generation → Publishing.
- MongoDB backend makes NoSQL injection payloads directly relevant.
- The CQRS command structure maps well to `grammarc`'s producer/consumer dependency inference (see `ARCHITECTURE_REVIEW.md` Top-20 #9).

---

**→ [Back to README](../README.md)**
