# Changelog

All notable changes to `praxis-authz-starter` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-beta.1] - 2026-11-15

### Added
- Initial Maven Central beta publication of `io.github.codexrodrigues:praxis-authz-starter:0.1.0-beta.1` on Spring Boot `3.5.15`.
- Auto-configuration (`PraxisAuthzAutoConfiguration`, `PraxisAuthzHostBridgeAutoConfiguration`, `PraxisAuthzProperties`) with single-authoritative-provider checks (`AUTHZ_BOOTSTRAP_MISSING_PROVIDER`, `AUTHZ_BOOTSTRAP_AMBIGUOUS_PROVIDERS`), startup compatibility verification (`HostPolicyCompatibilityStartupVerifier`), and Actuator health integration (`PraxisAuthzReadinessHealthIndicator`).
- Full `praxis-metadata-starter` governed host hierarchy:
  - `AbstractAuthzGovernedResourceService` & `AbstractAuthzGovernedReadOnlyResourceService` enforcing `STEP_11` pre-hydration write authorization before business rules, `JpaCriteriaDataScopeTranslator`, and `AuthzMaskingResourceMapperDecorator`;
  - Zero-blueprint `AuthzResourceGovernanceSpec.fromAnnotatedResource(...)` and `AuthzHostPolicyBootstrapBuilder`;
  - Architectural readiness audit (`AuthzHostReadinessReviewer`: `AUTHZ-HOST-001` through `AUTHZ-HOST-014`);
  - `AuthzResourceOperationAvailabilityProvider` (wired ahead of `NoOpResourceOperationAvailabilityProvider`), `AuthzGovernedStatsQueryExecutor`, `AuthzGovernedOptionSourceProvider`, `AuthzGovernedReactiveDeterminationProvider`, `AuthzGovernedBulkDomainResourceAdapter`, and `AuthzGovernedCollectionExportExecutor`.
- `PraxisAuthzExceptionHandler` (`@RestControllerAdvice` at `Ordered.HIGHEST_PRECEDENCE`) translating fail-closed authorization, spoofing, field-use, field-write, and provider unavailability exceptions into structured HTTP `401`, `403`, and `503` responses.
- Transactional JDBC audit outbox (`JdbcTransactionalAuditOutbox`, `JdbcAuditOutboxRelayExecutor`), PostgreSQL RLS session isolation (`JdbcSessionContextIsolationGuard`), governed reentrant channel executor (`GovernedChannelInvocationExecutor`), collection export guard (`GovernedCollectionExportGuard`), PAP catalog service (`SemanticDecisionPointCatalogService`), and control-plane OPA reconciler (`ConfigMaterializationToOpaReconciler`).
- Comprehensive conformance suite (`P01..P64`, HTTP/reentrant integration, real `AbstractBaseResourceService` integration, and cross-host dual-scope delegation).
