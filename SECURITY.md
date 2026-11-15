# Security Policy

`praxis-authz-starter` wires fail-closed Spring Boot authorization enforcement, HTTP error mapping, database RLS session isolation, transactional audit outboxes, and metadata/control-plane governance bridges for the **Praxis Authorization Decision Platform**. Security defects must be handled responsibly.

## Reporting a Vulnerability

Do **not** open public GitHub issues containing exploit payloads, unmasked tenant records, production `masking-hmac-secret` values, tokens, keys, or customer details.

Report vulnerabilities privately to the repository maintainer via GitHub Security Advisories (`codexrodrigues/praxis-authz-starter`) and include:

- Affected version, tag, or commit hash;
- Component involved (auto-configuration, `AbstractAuthzGovernedResourceService`, `PraxisAuthzExceptionHandler`, `JdbcSessionContextIsolationGuard`, `JdbcTransactionalAuditOutbox`, `GovernedCollectionExportGuard`, or readiness reviewer);
- Minimal reproduction scenario without real credentials or tenant data;
- Security impact (e.g., startup fail-open, RLS session bleed across pooled connections, field-use bypass, or unmasked export/AI projection disclosure).

## Security Design Invariants

- **Fail-Closed Bootstrap:** Missing providers (`AUTHZ_BOOTSTRAP_MISSING_PROVIDER`), competing `AuthorizationProviderPort` beans (`AUTHZ_BOOTSTRAP_AMBIGUOUS_PROVIDERS`), missing bindings, or compatibility mismatches abort startup when `fail-closed-on-bootstrap-error=true` (`P20`, `P39`);
- **Non-Bypassable Pre-Hydration Governance:** `AbstractAuthzGovernedResourceService` executes `STEP_11` write authorization inside `final` lifecycle hooks before entity hydration (`STEP_12`) and rules evaluation;
- **Pooled JDBC RLS Scrubbing:** `JdbcSessionContextIsolationGuard` enforces admitted non-bypass DB roles (`praxis.authz.jdbc.admitted-db-roles`), sets transaction-scoped session variables before SQL execution, and scrubs connections in `finally`;
- **Export & AI Projection Hardening:** `GovernedCollectionExportGuard` verifies `OpaRuntimeHead` consistency before and after export, enforces `exportable = false`, applies lattice masks row-by-row, and neutralizes CSV/TSV formula injection.

## Credential & Release Hygiene

- Override `praxis.authz.masking-hmac-secret` in every non-local environment using externalized secrets management;
- Never commit Maven Central tokens, GitHub PATs, GPG private keys, or passphrases;
- All Maven Central releases wait for `praxis-authz-contracts`, `praxis-authz-enforcement-core`, and `praxis-authz-opa` before tagging in CI (see [RELEASING.md](RELEASING.md)).
