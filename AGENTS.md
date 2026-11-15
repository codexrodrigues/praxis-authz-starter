# AGENTS.md — Praxis Authz Starter

## Escopo e Herança

- Aplica-se a todo o repositório `praxis-authz-starter`.
- Herda as diretrizes do `AGENTS.md` da raiz do monorepo Praxis (`praxis-plataform`), adicionando as regras locais deste módulo.

## Fronteira Canônica

- Este artefato é o starter Spring Boot `3.5.15` da camada `decisionKind = AUTHORIZATION` da **Praxis Decision Platform**, responsável por auto-configuração (`PraxisAuthzAutoConfiguration`, `PraxisAuthzHostBridgeAutoConfiguration`), serviços governados (`AbstractAuthzGovernedResourceService`, `AbstractAuthzGovernedReadOnlyResourceService`), introspecção e readiness de hosts (`AuthzResourceGovernanceSpec`, `AuthzHostPolicyBootstrapBuilder`, `AuthzHostReadinessReviewer`), mapeamento HTTP (`PraxisAuthzExceptionHandler`), outbox JDBC, guarda RLS, exportação, catálogo PAP e reconciliação de control plane.
- Contratos puros `CC01–CC12` pertencem a `praxis-authz-contracts`; pipeline PEP framework-neutral pertence a `praxis-authz-enforcement-core`; compilador Rego v1 e adapter OPA pertencem a `praxis-authz-opa`.
- Regras de negócio (`decisionKind = BUSINESS`) pertencem a `praxis-rules-engine`; não misture avaliação de autorização com regras determinísticas de negócio.
- O repositório deve funcionar de forma autônoma no GitHub Actions, consumindo `praxis-authz-{contracts,enforcement-core,opa}`, `praxis-metadata-starter` e `praxis-config-starter` publicados.

## Invariantes de Segurança, Hosts e Metadata

- Toda nova propriedade em `PraxisAuthzProperties` deve manter default seguro (*fail-closed* para bootstrap, outbox transacional e verificação de compatibilidade; `admin-endpoints.enabled=false`) e ser documentada em `README.md`.
- Hooks `beforeCreate`, `beforeUpdate` e `beforeDelete` de `AbstractAuthzGovernedResourceService` permanecem `final` para garantir autorização pré-hidratação (`STEP_11`) antes de `hydrate*` e determinações/regras (`STEP_12`).
- Alterações em bridges com `praxis-metadata-starter` ou `praxis-config-starter` devem manter cobertura nos testes `P01ToP64CompleteConformanceMatrixTest`, `P102RealAbstractBaseResourceServiceIntegrationTest`, `P11HttpAndReentrantServiceIntegrationTest` e nas regras `AUTHZ-HOST-001` a `AUTHZ-HOST-014`.

## Validação e Economia de GitHub Actions

- Use Java 21 e Maven 3.9+ com `mvn -B clean verify`.
- Não execute `mvn deploy` localmente nem crie tags `v*` fora da ordem multi-repositório (`contracts -> enforcement-core -> opa -> starter`).
- Consulte [ACTIONS-RELEASE-POLICY.md](ACTIONS-RELEASE-POLICY.md) e [RELEASING.md](RELEASING.md) antes de qualquer dispatch de workflow.
