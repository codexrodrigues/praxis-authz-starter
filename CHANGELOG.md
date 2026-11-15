# Histórico de Alterações (Changelog)

Todas as mudanças relevantes de `praxis-authz-starter` são documentadas neste arquivo.

O formato segue o padrão [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), e este projeto adere ao [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-beta.1] - 2026-11-15

### Adicionado
- Publicação beta inicial no Maven Central de `io.github.codexrodrigues:praxis-authz-starter:0.1.0-beta.1` sobre Spring Boot `3.5.15`.
- Auto-configuração (`PraxisAuthzAutoConfiguration`, `PraxisAuthzHostBridgeAutoConfiguration`, `PraxisAuthzProperties`) com validação de provedor autoritativo único (`AUTHZ_BOOTSTRAP_MISSING_PROVIDER`, `AUTHZ_BOOTSTRAP_AMBIGUOUS_PROVIDERS`), handshake de compatibilidade no startup (`HostPolicyCompatibilityStartupVerifier`) e health check Actuator (`PraxisAuthzReadinessHealthIndicator`).
- Hierarquia completa de serviços governados integrada ao `praxis-metadata-starter`:
  - `AbstractAuthzGovernedResourceService` e `AbstractAuthzGovernedReadOnlyResourceService` impondo `STEP_11` pré-hidratação antes das regras de negócio, `JpaCriteriaDataScopeTranslator` e `AuthzMaskingResourceMapperDecorator`;
  - Introspecção Zero-Blueprint `AuthzResourceGovernanceSpec.fromAnnotatedResource(...)` e `AuthzHostPolicyBootstrapBuilder`;
  - Auditoria arquitetural de prontidão (`AuthzHostReadinessReviewer`: `AUTHZ-HOST-001` a `AUTHZ-HOST-014`);
  - `AuthzResourceOperationAvailabilityProvider` (priorizado antes de `NoOpResourceOperationAvailabilityProvider`), `AuthzGovernedStatsQueryExecutor`, `AuthzGovernedOptionSourceProvider`, `AuthzGovernedReactiveDeterminationProvider`, `AuthzGovernedBulkDomainResourceAdapter` e `AuthzGovernedCollectionExportExecutor`.
- `PraxisAuthzExceptionHandler` (`@RestControllerAdvice` em `Ordered.HIGHEST_PRECEDENCE`) traduzindo exceções *fail-closed* de autorização, spoofing, uso/escrita de campos e indisponibilidade do provedor para respostas estruturadas HTTP `401`, `403` e `503`.
- Audit outbox transacional via JDBC (`JdbcTransactionalAuditOutbox`, `JdbcAuditOutboxRelayExecutor`), isolamento de sessão PostgreSQL RLS (`JdbcSessionContextIsolationGuard`), executor de canais reentrantes (`GovernedChannelInvocationExecutor`), guarda de exportação (`GovernedCollectionExportGuard`), catálogo PAP (`SemanticDecisionPointCatalogService`) e reconciliador OPA para o control plane (`ConfigMaterializationToOpaReconciler`).
- Suíte completa de conformidade (`P01..P64`, integração HTTP/reentrante, integração real com `AbstractBaseResourceService` e delegação *dual-scope* entre hosts).
