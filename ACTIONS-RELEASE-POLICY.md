# Actions no Fechamento de Versões

O padrão durante desenvolvimento é **zero execuções remotas**. Valide alterações localmente; commits, PRs, documentação interna e tarefas rotineiras não são motivos para iniciar workflows no GitHub Actions. Use os workflows manuais somente no fechamento autorizado de uma versão/publicação ou em validação de corte de release. Não utilize `[skip ci]` como contorno nem desabilite gates estruturais.

Antes de push, tag ou dispatch, confira os gatilhos reais em `.github/workflows/`:
- `ci.yml` (`CI`): dispara apenas por `workflow_dispatch` para validação isolada em `ubuntu-latest` (`mvn --batch-mode --no-transfer-progress clean verify`).
- `release.yml` (`Release Praxis Authz Starter`): dispara por `workflow_dispatch` (job `create_tag`) ou por push de tag `v*` (job `publish`). O job `create_tag` verifica `HTTP 200` no Maven Central (`repo1.maven.org`) para `praxis-authz-contracts`, `praxis-authz-enforcement-core` e `praxis-authz-opa` na mesma versão `v*` antes de criar a tag anotada. **Nunca crie tags `v*` manualmente para testar automação**.

## Fluxo deste repositório

1. Durante o desenvolvimento local, valide com Java 21 e Maven 3.9+: `mvn -B clean verify`.
2. Garanta que `praxis-authz-contracts`, `praxis-authz-enforcement-core` e `praxis-authz-opa` da mesma versão já estejam disponíveis em `repo1.maven.org`.
3. No fechamento de versão, execute `release.yml` em `main` com `create_tag=true` para publicar `praxis-authz-starter` no Maven Central. Consulte [RELEASING.md](RELEASING.md).
