# Guia de Release — Praxis Authz Starter

## Linha Pública

A linha pública ativa é `0.1.0-beta.*` sob a coordenada `io.github.codexrodrigues:praxis-authz-starter` sobre Spring Boot `3.5.15` (release atual publicada: `0.1.0-beta.1`).

Este repositório segue a [Política de Releases e GitHub Actions](ACTIONS-RELEASE-POLICY.md).

## Ordem Sequencial de Publicação Multi-Repositório (4 Etapas)

`praxis-authz-starter` é a **etapa final (Etapa 4)** da cadeia de publicação e verifica a presença de todos os três módulos anteriores no `repo1.maven.org` antes de criar a tag:

1. `codexrodrigues/praxis-authz-contracts`
2. `codexrodrigues/praxis-authz-enforcement-core`
3. `codexrodrigues/praxis-authz-opa`
4. **`codexrodrigues/praxis-authz-starter`** *(este repositório — publicar somente após 1, 2 e 3 retornarem `HTTP 200` no Maven Central)*

Todos os quatro módulos de uma onda coordenada devem publicar exatamente a mesma string SemVer. O `maven-enforcer-plugin` impõe `requireReleaseDeps`, impedindo dependências `-SNAPSHOT`.

## Segredos Obrigatórios no Repositório

- `CENTRAL_TOKEN_USER`
- `CENTRAL_TOKEN_PASS`
- `GPG_PRIVATE_KEY` (bloco ASCII-armored com a linha em branco obrigatória pela RFC 4880 imediatamente após `-----BEGIN PGP PRIVATE KEY BLOCK-----`, ou exportação binária codificada em base64)
- `GPG_PASSPHRASE`
- `GPG_KEY_ID` (opcional)
- `RELEASE_PAT`, com permissão `contents: write` para enviar commits e tags para `main`

`RELEASE_PAT` é obrigatório porque tags enviadas via `GITHUB_TOKEN` não disparam o workflow separado com gatilho `push: tags: v*`.

## Fluxo Oficial de Release

1. Confirme que `contracts`, `enforcement-core` e `opa` já estão acessíveis na versão alvo em `repo1.maven.org`, que o working tree está limpo e toda a suíte local (`P01..P64`, integração HTTP/reentrante e `AbstractBaseResourceService`) passa com JDK 21 (`[21,)`) e Maven `3.9.0+`:

   ```powershell
   mvn -B clean verify
   ```

2. No GitHub Actions, execute **Release Praxis Authz Starter** (`workflow_dispatch`) em `main` com `create_tag=true` informando `version` ou `bump`/`preid`.
3. O job `create_tag` verifica os `.pom`s upstream em `repo1.maven.org`, grava a versão no `pom.xml`, cria a tag anotada `v<semver>` e envia `HEAD:main` + tag atomicamente.
4. O job `publish` valida a tag, importa a chave GPG, executa a matriz de conformidade completa, gera o POM achatado (`flatten-maven-plugin`, modo `oss`), assina `.pom`/`.jar`/`-sources.jar`/`-javadoc.jar`, publica via `central-publishing-maven-plugin` e aguarda `HTTP 200` em `repo1.maven.org`.
5. Antes de rodar `mvn install` localmente para alterações inéditas não publicadas, avance `<version>` para o próximo `-SNAPSHOT` para não sobrescrever o artefato oficial em `~/.m2`.
6. Valide as coordenadas publicadas usando um repositório local temporário isolado contra `repo1.maven.org`:

   ```powershell
   mvn -B -Dmaven.repo.local=<temp-dir> dependency:tree
   ```

Nunca crie tags manualmente para disparar CI nem execute `mvn deploy` localmente.
