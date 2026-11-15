# Política de Segurança (`praxis-authz-starter`)

`praxis-authz-starter` realiza a orquestração *fail-closed* de autorização em Spring Boot, mapeamento de exceções HTTP, isolamento de sessão PostgreSQL RLS, outbox transacional de auditoria e integração com metadados e plano de controle da **Praxis Authorization Decision Platform**. Defeitos de segurança devem ser comunicados com total discrição ao mantenedor.

## Reportando uma Vulnerabilidade

**Não** abra issues públicas no GitHub contendo payloads de exploração, registros reais de tenants, valores de `masking-hmac-secret` de produção, tokens, chaves privadas ou dados de clientes.

Envie o relato em canal privado via **GitHub Security Advisories** (`codexrodrigues/praxis-authz-starter`), incluindo sempre que possível:

- Versão, tag ou hash de commit afetado;
- Componente envolvido (auto-configuração, `AbstractAuthzGovernedResourceService`, `PraxisAuthzExceptionHandler`, `JdbcSessionContextIsolationGuard`, `JdbcTransactionalAuditOutbox`, `GovernedCollectionExportGuard`, `GovernedChannelInvocationExecutor` ou `AuthzHostReadinessReviewer`);
- Cenário mínimo de reprodução sem credenciais nem registros reais;
- Impacto de segurança observado (ex.: startup *fail-open*, vazamento de variáveis RLS entre conexões do pool, contorno de `FIELD_USE`/`FIELD_WRITE`, falha em reentrância de proxy ou exposição sem máscara em exportações/AI).

## Invariantes de Segurança por Design

- **Bootstrap Fail-Closed:** Provedor ausente (`AUTHZ_BOOTSTRAP_MISSING_PROVIDER`), múltiplos `AuthorizationProviderPort` concorrentes (`AUTHZ_BOOTSTRAP_AMBIGUOUS_PROVIDERS`), bindings ausentes ou divergência de compatibilidade abortam a inicialização quando `fail-closed-on-bootstrap-error=true` (`P20`, `P39`);
- **Governança Pré-Hidratação Não Contornável:** `AbstractAuthzGovernedResourceService` executa a autorização de escrita `STEP_11` em hooks `final` do ciclo de vida antes da hidratação da entidade e do motor de regras (`STEP_12`);
- **Higienização de Sessão RLS em Pool JDBC:** `JdbcSessionContextIsolationGuard` exige roles de banco sem privilégio de bypass (`praxis.authz.jdbc.admitted-db-roles`), fixa variáveis escopadas à transação antes da execução SQL e limpa conexões do pool em `finally`;
- **Blindagem em Exportações e Projeções de IA:** `GovernedCollectionExportGuard` verifica consistência do `OpaRuntimeHead` antes e depois da exportação, respeita `exportable = false`, aplica máscaras do lattice linha a linha e neutraliza injeção de fórmulas CSV/TSV.

## Higiene de Credenciais e Releases

- Sobrescreva obrigatoriamente `praxis.authz.masking-hmac-secret` fora de ambiente local usando um gerenciador de segredos externo;
- Nunca comite tokens Maven Central, PATs do GitHub, chaves GPG ou passphrases;
- Toda publicação no Maven Central aguarda `praxis-authz-contracts`, `praxis-authz-enforcement-core` e `praxis-authz-opa` e ocorre apenas em CI (veja [RELEASING.md](RELEASING.md)).
