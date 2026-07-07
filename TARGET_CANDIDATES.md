# UpsideFuzz: Future Fuzzing Targets

This document outlines potential open-source .NET projects that are excellent candidates for testing the advanced capabilities of the `UpsideFuzzer`, particularly the Stateful Sequence Engine and Identity token injection.

## 1. BTCPayServer (Fintech / Crypto)
**Repository:** [https://github.com/btcpayserver/btcpayserver](https://github.com/btcpayserver/btcpayserver)

BTCPayServer is a self-hosted, open-source cryptocurrency payment processor. It's heavily relied upon by businesses to accept Bitcoin without fees or intermediaries.
- **Why it's a great target:** Testing financial and transactional logic. It has a modern "Greenfield REST API" fully documented with Swagger. Finding race conditions or logic bypasses in invoice generation or payment processing would be highly impactful.

## 2. Squidex (Headless CMS / CQRS)
**Repository:** [https://github.com/Squidex/squidex](https://github.com/Squidex/squidex)

Squidex is a modern Headless CMS built using ASP.NET Core and MongoDB, heavily utilizing CQRS (Command Query Responsibility Segregation) and Event Sourcing patterns.
- **Why it's a great target:** Fuzzing Event-Sourced systems is notoriously difficult because state is built from a history of events rather than simple CRUD operations. This will be the ultimate stress test for UpsideFuzzer's Stateful Sequence Engine to ensure it can successfully chain complex API calls (e.g., Schema creation -> Content generation -> Publishing).

## 3. Bitwarden Server (Security / Vault)
**Repository:** [https://github.com/bitwarden/server](https://github.com/bitwarden/server)

The official core infrastructure backend for Bitwarden, the popular open-source password manager.
- **Why it's a great target:** Any bug found here has critical security implications. The API is heavily protected by IdentityServer, strict validations, and cryptography. Fuzzing this will prove that UpsideFuzzer can navigate enterprise-grade security perimeters when provided with valid authentication tokens.

## 4. Jellyfin (Media Server)
**Repository:** [https://github.com/jellyfin/jellyfin](https://github.com/jellyfin/jellyfin)

Jellyfin is the volunteer-built media solution that puts you in control of your media. It's an alternative to proprietary options like Emby and Plex.
- **Why it's a great target:** Massive API surface area. It handles thousands of edge cases for file parsing, metadata fetching, transcoding, and user management. This is an excellent target for finding Path Traversal vulnerabilities, DoS (Denial of Service) via malformed input, and unhandled exceptions (500 errors).
