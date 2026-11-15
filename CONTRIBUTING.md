# Como Contribuir com `praxis-authz-starter`

Contribuições para `praxis-authz-starter` devem preservar o comportamento *fail-closed* de inicialização e runtime, a compatibilidade com Spring Boot `3.5.x` e a integração limpa com [`praxis-metadata-starter`](https://github.com/codexrodrigues/praxis-metadata-starter) e [`praxis-config-starter`](https://github.com/codexrodrigues/praxis-config-starter).

## Baseline de Desenvolvimento

- **Java:** 21 (`[21,)` imposto pelo `maven-enforcer-plugin`)
- **Apache Maven:** `3.9.0` ou superior
- **Spring Boot:** `3.5.15`

Execute a suíte completa e inspecione a árvore de dependências de runtime antes de enviar alterações:

```powershell
mvn -B clean verify
mvn -B dependency:tree -Dscope=runtime
```

## Diretrizes de Contribuição

1. **Invariantes Fail-Closed no Startup e em Runtime:** Nunca degrade erros de provedor ausente (`AUTHZ_BOOTSTRAP_MISSING_PROVIDER`), ambiguidade de beans (`AUTHZ_BOOTSTRAP_AMBIGUOUS_PROVIDERS`) ou incompatibilidade de digests para avisos silenciosos quando `fail-closed-on-bootstrap-error=true`.
2. **Não Duplique Lógica de Negócio do `enforcement-core` ou `opa`:** Alterações no pipeline de 15 etapas pertencem a [`praxis-authz-enforcement-core`](https://github.com/codexrodrigues/praxis-authz-enforcement-core); compilação Rego v1 e guarda `SEARCH` pertencem a [`praxis-authz-opa`](https://github.com/codexrodrigues/praxis-authz-opa).
3. **Preserve Introspecção Zero-Blueprint (`PLAT-EVO-10`):** Novos pontos de extensão de recursos no `praxis-metadata-starter` devem ser descobertos automaticamente por `AuthzResourceGovernanceSpec` e auditados em `AuthzHostReadinessReviewer` (`AUTHZ-HOST-001`..`014`).
4. **Cobertura de Conformidade (`P01..P64`):** Toda nova ponte Spring, exceção HTTP em `PraxisAuthzExceptionHandler` ou guarda JDBC/outbox exige testes automatizados verificando caminhos permitidos e falhas fechadas, utilizando também [`AuthzPolicySimulationHarness`](README.md#mapa-de-pacotes-e-componentes) quando aplicável.
5. **Documentação em PT-BR:** Escreva guias, exemplos e atualizações em **PT-BR** claro e didático, preservando os identificadores exatos da API e propriedades `praxis.authz.*`. Consulte [o guia de adoção no host](src/main/resources/META-INF/praxis/AUTHZ-HOST-ADOPTION-GUIDE.md).

## Governança e Releases

Consulte [RELEASING.md](RELEASING.md), [AGENTS.md](AGENTS.md) e [ACTIONS-RELEASE-POLICY.md](ACTIONS-RELEASE-POLICY.md).
