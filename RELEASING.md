# Releasing — Praxis Authz Starter

## Public line

The active public line is `0.1.0-beta.*` under coordinate `io.github.codexrodrigues:praxis-authz-starter` (current published release: `0.1.0-beta.1`). Compatible corrections remain on this line while downstream hosts (`praxis-ergon-showcase`, Quickstart, and Ergon modules) validate auto-configuration, conformance matrix gates, and OPA HTTP integration. A stable `1.0.0` or new major requires a governed compatibility and migration plan.

## Multi-repository release order

This module sets `<praxis-authz.version>${project.version}</praxis-authz.version>` in `pom.xml`, and `release.yml` requires the matching `.pom` files for all three upstream modules to return `HTTP 200` on `repo1.maven.org` before tagging:

1. `codexrodrigues/praxis-authz-contracts`
2. `codexrodrigues/praxis-authz-enforcement-core`
3. `codexrodrigues/praxis-authz-opa`
4. `codexrodrigues/praxis-authz-starter` (this repository; published last)

## Required repository secrets

- `CENTRAL_TOKEN_USER`
- `CENTRAL_TOKEN_PASS`
- `GPG_PRIVATE_KEY` (ASCII-armored private key block with the mandatory RFC 4880 blank line immediately after `-----BEGIN PGP PRIVATE KEY BLOCK-----`, or base64-encoded binary key export)
- `GPG_PASSPHRASE`
- `GPG_KEY_ID` (optional)
- `RELEASE_PAT`, with `contents: write` permission to push commits and tags on `main`

`RELEASE_PAT` is required because tags pushed by `GITHUB_TOKEN` do not trigger the separate `push: tags: v*` publication workflow.

## Release flow

1. Confirm `praxis-authz-contracts`, `praxis-authz-enforcement-core`, and `praxis-authz-opa` at `<version>` are already live (`HTTP 200`) on `repo1.maven.org`.
2. Confirm the intended commit is on remote `main` and local validation passes with JDK 21:

   ```powershell
   mvn -B clean verify
   ```

3. In GitHub Actions, run **Release Praxis Authz Starter** (`workflow_dispatch`) on `main` with `create_tag=true` and either an explicit `version` matching upstream modules or `bump`/`preid`.
4. The `create_tag` job verifies upstream `.pom` availability on Maven Central, persists the resolved version in `pom.xml`, creates the annotated `v<semver>` tag, and pushes `HEAD:main` and the tag atomically.
5. The `publish` job verifies tag ancestry on `main`, imports the GPG key, enforces module boundaries, runs all starter and integration tests, flattens the published POM (`oss` mode), signs `.pom`/`.jar`/`-sources.jar`/`-javadoc.jar`, publishes via `central-publishing-maven-plugin`, and polls `repo1.maven.org` until the `.pom` returns `HTTP 200`.
6. After publication succeeds, downstream hosts (such as `praxis-ergon-showcase`) should pin `<praxis.authz.version>` to the released public version and verify resolution from Maven Central.
7. Before running `mvn install` locally for new unreleased work, bump `<version>` to the next `-SNAPSHOT` (e.g. `0.1.0-beta.2-SNAPSHOT`) so local builds do not overwrite published release artifacts in `~/.m2`.
8. Run an isolated clean `.m2` consumer smoke test (`mvn -B -Dmaven.repo.local=<temp-dir> dependency:tree`) depending on `io.github.codexrodrigues:praxis-authz-starter:<version>` before announcing adoption; a local Maven install is not release evidence.

Do not create release tags manually, run `mvn deploy` locally, or bypass a failed CI/release gate.
