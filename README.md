# Praxis Authz Spring Boot Starter

Spring Boot starter for the Praxis Authorization Decision Platform: fail-closed startup handshakes, OPA decision provider wiring, Spring Web caller context resolution, JPA `DataScope` / `FieldUse` / `WriteIntent` enforcement, and `praxis-metadata-starter` host bridge integration.

## Highlights

- **Fail-Closed Auto-Configuration:** `PraxisAuthzAutoConfiguration` and `PraxisAuthzHostBridgeAutoConfiguration` configure `praxis.authz.*` (`PraxisAuthzProperties`), readiness checks, compatibility verification, and PAP discovery integration.
- **HTTP Caller Context & Semantic Error Mapping:** `AuthzCallerContextFilter` validates caller headers (`UntrustedRequestHeaderGuard`), while `PraxisAuthzExceptionHandler` maps authentication, authorization, header-spoofing, field-use/write violations, and provider unavailability into canonical `RestApiResponse` envelopes (`401`, `403`, and `503`).
- **Metadata Resource & Stats Enforcement:** `AbstractAuthzGovernedResourceService`, `AbstractAuthzGovernedReadOnlyResourceService`, `JpaCriteriaDataScopeTranslator`, and `AuthzGovernedStatsQueryExecutor` enforce row-level predicates, masked DTO projections, write intents, and histogram/aggregate checks.
- **Host Readiness Governance:** `AuthzHostReadinessReviewer` audits Spring/Praxis hosts for unsafe filter/sort/stats exposure and governance drift before startup.

## Maven Coordinates

```xml
<dependency>
    <groupId>io.github.codexrodrigues</groupId>
    <artifactId>praxis-authz-starter</artifactId>
    <version>0.1.0-beta.1</version>
</dependency>
```

## License

Licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).
