# Guia de Release (`praxis-authz-starter`)

Este repositório segue a [Política de Releases e GitHub Actions](ACTIONS-RELEASE-POLICY.md) para publicar o starter oficial da **Praxis Authorization Decision Platform** somente após todos os módulos anteriores já estarem disponíveis no Maven Central.

## Pré-requisitos do Ambiente

- **Java:** `[21,)` (compatível com Spring Boot `3.5.15`)
- **Apache Maven:** `3.9.0` ou superior (`requireReleaseDeps` ativo)
- **GPG & Central Portal:** segredos `CENTRAL_TOKEN_USER`, `CENTRAL_TOKEN_PASS`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`, `GPG_KEY_ID` e `RELEASE_PAT` configurados no repositório para execução em CI

## Ordem de Publicação Multi-Repositório

`praxis-authz-starter` é o **Nível 2 (camada final de publicação)** da stack:

1. `praxis-authz-contracts` *(Nível 0)*
2. `praxis-authz-enforcement-core` e `praxis-authz-opa` *(Nível 1)*
3. **`praxis-authz-starter`** ← *(publicar por último, após todos os anteriores visíveis no Maven Central)*

## Verificação Local Pré-Release

Antes de acionar a release via workflow:

```powershell
mvn -B clean verify
```

Garanta que:
- Toda a matriz `P01..P64`, testes de auto-configuração Spring Boot e integrações com `AbstractBaseResourceService` passaram;
- Não existam referências `-SNAPSHOT` no `pom.xml`;
- As tabelas de propriedades `praxis.authz.*` e histórico em `CHANGELOG.md` reflitam a versão alvo.

## Fluxo Oficial no GitHub Actions

- `ci.yml` executa **apenas** via `workflow_dispatch`;
- `release.yml` executa via `workflow_dispatch` ou tag `v*` aprovada, publicando via `central-publishing-maven-plugin`.
