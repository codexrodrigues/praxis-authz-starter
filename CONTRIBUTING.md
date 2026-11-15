# Contributing to Praxis Authz Starter

Thank you for contributing to `praxis-authz-starter`.

## Development Baseline

- **Java:** 21+ (`[21,)` enforced by `maven-enforcer-plugin`, compiled with `--release 21`)
- **Maven:** 3.9.0 or newer
- **Spring Boot Parent:** `3.5.15`

Run the full local test and verification suite before submitting changes:

```powershell
mvn -B clean verify
```

## Module Boundary & Host Bridge Rules

`praxis-authz-starter` is the Spring Boot integration layer of the **Praxis Authorization Decision Platform**:

- Keep pure `CC01–CC12` contracts, digest calculators, and Kleene 3VL evaluators in `praxis-authz-contracts`;
- Keep framework-neutral PEP pipeline execution, header anti-spoofing, JPA adapters, and DTO masking in `praxis-authz-enforcement-core`;
- Keep Rego v1 compilation, bundle assembly, and OPA revision guarding in `praxis-authz-opa`;
- Keep optional integrations (`praxis-metadata-starter`, `praxis-config-starter`, Actuator, Data JPA, JDBC, Spring Web) resilient so conditional auto-configuration behaves cleanly even when optional starters are absent;
- Keep business rules (`decisionKind = BUSINESS`) in `praxis-rules-engine` and never bypass `AbstractAuthzGovernedResourceService` hooks or `AUTHZ-HOST-001..014` readiness checks.

## Contract & Release Discipline

- Changes to `PraxisAuthzProperties`, `AbstractAuthzGovernedResourceService`, `AuthzResourceGovernanceSpec`, `PraxisAuthzExceptionHandler`, or `AuthzHostReadinessReviewer` must include corresponding tests and updates to `README.md` / `CHANGELOG.md`;
- Never commit secrets, GPG material, production HMAC keys, database credentials, or personal tokens;
- Do not create release tags manually or run local `mvn deploy`; follow [RELEASING.md](RELEASING.md).
