# Guia Canônico de Adoção de Autorização Governada em Hosts Praxis (`praxis-authz-starter`)

Este guia documenta o padrão canônico **zero-boilerplate** para governar recursos corporativos (`AbstractBaseResourceService` e `AbstractReadOnlyResourceService`) em hosts Spring Boot que consomem `praxis-metadata-starter` e `praxis-authz-starter` (`Fases P10.1 .. P10.14`).

---

## 1. Visão Geral da Arquitetura no Host

Ao incluir `praxis-authz-starter` no classpath de um host com `praxis-metadata-starter`, a auto-configuração [`PraxisAuthzHostBridgeAutoConfiguration`](../../../java/org/praxisplatform/authz/autoconfigure/PraxisAuthzHostBridgeAutoConfiguration.java) ativa automaticamente:

1. **`MetadataDtoGovernanceIntrospector`:** Introspecta `@DomainLineage`, `@DomainGovernance` e `@Schema` nos DTOs (`ResponseDTO`, `CreateDTO`, `UpdateDTO`), herdando automaticamente a linhagem (`attributeId`), sensibilidade, elegibilidade de exportação e política de IA do `ResponseDTO` para propriedades mapeadas em `CreateDTO` e `UpdateDTO`, além de derivar os registros `FieldLineageCatalogEntry` para o Catálogo Semântico PAP (`Fase P10.13`).
2. **`ThreadLocalAuthzCallerContextProvider` + `AuthzCallerContextFilter` + `ResourceTenantContextResolver`:** Propaga o contexto do chamador autenticado (`tenantId`, fatos `subject.*`/`env.*`, cabeçalhos HTTP para proteção anti-spoofing `CC10` e usos de campo `FILTER`/`SORT`/`GROUP`) por requisição HTTP e vincula o isolamento de tenant para `@CustomFields` (`JSONB`).
3. **`AuthzResourceOperationAvailabilityProvider` (`@Order(300)`) + `ResourceStateSnapshotProvider`:** Avalia a disponibilidade contextual real (`/actions`, `/surfaces`, `/capabilities` e links HATEOAS `_links`) contra o motor de políticas, permissões de escrita por campo (`STEP_11`) e custódia dual (`Cedente` vs. `Cessionário`).
4. **`GovernedResourceCommandExecutor`:** Traduz violações `STEP_11` (`FieldWriteViolationException` / `SecurityException`) em respostas estruturadas `PERMISSION_DENIED` (`403`) com sanitização de evidências.
5. **`authzGovernedServicesReactiveDeterminationProvider`:** Agrega automaticamente as definições de `defineReactiveDeterminations()` declaradas nos serviços governados (`ReadOnly` e `Mutable`), aplicando supressão de atributos restritos.
6. **`authzGovernedResourceServiceInfrastructureInitializer` (`SmartInitializingSingleton`):** Conecta automaticamente `CollectionExportExecutor`, `OptionSourceQueryExecutor`, `StatsQueryExecutor`, bindings de disponibilidade contextual, `CustomFieldDefinitionProvider` e sincroniza `RuntimeDecisionPointRegistry` + `SemanticDecisionPointCatalogService` em todos os serviços governados.
7. **`AuthzHostReadinessReviewer`:** Validador arquitetural para execução em gates JUnit ou no startup (`praxis.authz.readiness-gate.verify-on-startup=true`, `AUTHZ-HOST-001 .. AUTHZ-HOST-009`).

---

## 2. Especificação Declarativa Única (`AuthzResourceGovernanceSpec<E>`) e Bootstrap (`AuthzHostPolicyBootstrapBuilder`)

Em vez de construir manualmente `FactContract`, `QueryableResourceProjection`, `DecisionPointDescriptor` ou sobrescrever métodos de escopo JPQL/Criteria em cada `Service`, declare um `AuthzResourceGovernanceSpec<E>` auto-contido (`Fase P10.14`):

```java
AuthzResourceGovernanceSpec<AfastamentoEntity> spec = AuthzResourceGovernanceSpec
        .<AfastamentoEntity>builder("human-resources.afastamentos")
        .serviceKey("praxis-hr-service")
        // 1. Bindings declarativos que geram automaticamente QueryableResourceProjection, FactContract e DecisionPointDescriptor
        .scalarFieldBinding(
                "resource.lotacaoSetorId",
                "human_resources.afastamentos.lotacao_setor_id",
                "lotacaoSetorId"
        )
        .resourceSensitiveFact(
                "resource.cidCodigo",
                "human_resources.afastamentos.cid_codigo",
                FactValueType.STRING,
                "HEALTH_DATA",
                "OFFICIAL_HEALTH_EXPERTISE"
        )
        // 2. Isolamento de Tenant (Hard-Scope automático em Criteria, JPQL e in-memory)
        .tenantField("tenantId")
        .stateField("status")
        // 3. Âncoras obrigatórias de escopo (bloqueia omissão no CREATE ou limpeza para null no UPDATE)
        .mandatoryScopeAnchorAttributeIds(Set.of(
                "human_resources.afastamentos.uo_origem_id",
                "human_resources.afastamentos.uo_destino_id"
        ))
        // 4. Custódia Dual (Cedente vs. Cessionário) declarativa
        .dualScopeDelegationSpec(dualScopeSpec)
        .cedenteCustody("uoOrigemId", "subject.uoId")
        .cessionarioCustody("uoDestinoId", "subject.uoId")
        // 5. Ações de workflow (@WorkflowAction) e superfícies (@UiSurface) auto-sintetizadas (Fase P10.15-R03)
        .workflowAction("homologar", Set.of("human_resources.afastamentos.status"))
        .uiSurface("ficha-medica-360")
        .build();

// Opcional (Dev / Showcase / Testes): Publique apenas 1 @Bean AuthzHostPolicyBootstrapBundle;
// PraxisAuthzAutoConfiguration extrai automaticamente HostRuntimePolicyCoordinates, OpaClientTransport,
// RuntimeDecisionPointRegistry e SemanticDecisionPointCatalogService (com todos os 18 FieldLineageCatalogEntry):
@Bean
public AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle authzBootstrapBundle() {
    return AuthzHostPolicyBootstrapBuilder.forService("praxis-hr-service")
            .addResourceSpec(
                    spec,
                    AfastamentoResponseDTO.class,
                    AfastamentoCreateDTO.class,
                    AfastamentoUpdateDTO.class
            )
            .addOrganizationalScopePolicy(
                    spec,
                    "rule-lotacao-scope",
                    "resource.lotacaoSetorId",
                    "subject.organizationUnitIds",
                    Map.of("human_resources.afastamentos.cid_codigo", "***CID-RESTRITO***")
            )
            .build();
}
```

---

## 3. Implementação de Serviço Governado Mutável (`AbstractAuthzGovernedResourceService`)

Com `AuthzResourceGovernanceSpec<E>` e `AuthzCallerContextProvider`, o serviço de recurso requer apenas o construtor declarativo e `getRawResourceMapper()`:

```java
@Service
public class AfastamentoGovernedService extends AbstractAuthzGovernedResourceService<
        AfastamentoEntity,
        AfastamentoResponseDTO,
        Long,
        AfastamentoFilterDTO,
        AfastamentoCreateDTO,
        AfastamentoUpdateDTO
> implements DuplicateDraftResourceService<AfastamentoCreateDTO, Long> {

    private final AfastamentoMapper mapper;

    public AfastamentoGovernedService(
            AfastamentoRepository repository,
            AuthzGovernedResourceServiceSupport serviceSupport,
            AuthzResourceGovernanceSpec<AfastamentoEntity> governanceSpec,
            AuthzCallerContextProvider callerContextProvider,
            AfastamentoMapper mapper
    ) {
        super(
                repository,
                AfastamentoEntity.class,
                AfastamentoResponseDTO.class,
                serviceSupport,
                governanceSpec,
                callerContextProvider
        );
        this.mapper = mapper;
    }

    @Override
    protected ResourceMapper<
            AfastamentoEntity,
            AfastamentoResponseDTO,
            AfastamentoCreateDTO,
            AfastamentoUpdateDTO,
            Long
    > getRawResourceMapper() {
        return mapper;
    }

    // Hidratação server-side: garantida por construção (final beforeCreate/beforeUpdate)
    // a rodar SEMPRE APÓS o STEP_11 (autorização de escrita) e ANTES do STEP_12 (validação/regras).
    @Override
    protected void hydrateBeforeCreate(AfastamentoCreateDTO dto, AfastamentoEntity entity) {
        entity.setTenantId(resolveCurrentTenantId());
        if (entity.getStatus() == null) {
            entity.setStatus("PENDENTE");
        }
    }

    // Comandos de Workflow (@WorkflowAction) com controle otimista (If-Match / ETag)
    @Transactional
    public ResourceRepresentationResult<AfastamentoResponseDTO> homologar(
            Long id,
            HomologarCommandDTO cmd,
            ResourceVersionUpdatePrecondition<Long> precondition
    ) {
        return executeGovernedVersionedCommand(
                id,
                "homologar",
                cmd,
                precondition,
                entity -> entity.setStatus("HOMOLOGADO")
        );
    }

    // Duplicação assistida não-persistente (DuplicateDraftResourceService)
    @Override
    @Transactional(readOnly = true)
    public AfastamentoCreateDTO duplicateDraft(Long sourceId) {
        return executeGovernedDuplicateDraft(sourceId, source -> new AfastamentoCreateDTO(
                source.getServidorNome(),
                source.getUoOrigemId(),
                source.getUoDestinoId(),
                source.getCidCodigo(),
                source.getObservacaoCedente(),
                source.getObservacaoCessionario()
        ));
    }

    // Determinações Reativas em tempo de formulário (auto-registradas pelo starter)
    @Override
    protected Collection<ReactiveDeterminationDefinition> defineReactiveDeterminations() {
        return List.of(
                ReactiveDeterminationDefinition.forCrudResource(
                        "calc-prazo-retorno",
                        AfastamentoResource.RESOURCE_KEY,
                        "calcularPrazoRetorno",
                        "/api/hr/afastamentos/determinations/prazo-retorno",
                        Set.of(ReactiveDeterminationFormMode.CREATE, ReactiveDeterminationFormMode.EDIT),
                        Set.of(ReactiveDeterminationTriggerType.FIELD_CHANGE),
                        List.of("/uoOrigemId"),
                        List.of(ReactiveDeterminationInputBinding.field("uoOrigemId", "/uoOrigemId")),
                        List.of(ReactiveDeterminationOutputBinding.value("/observacaoCedente", "observacaoCedente")),
                        180
                )
        );
    }
}
```

### Garantias Automáticas de Segurança e Governança

| Capacidade | Método / Hook no Serviço | Garantia Determinística |
| :--- | :--- | :--- |
| **Leitura, Paginação e `by-ids`** | `findAll`, `findById`, `findAllById` | Compõe `hardScope` (`tenantId`) + `DataScopePlan` (JPA Criteria), bloqueia filtros em campos `FILTER=DENY`, mascara `ResponseDTO` destacado e evita `N+1` chamadas ao OPA. |
| **Mutação (`CREATE`, `UPDATE`, `DELETE`)** | `create`, `update`, `deleteById` (`final before*`) | Executa `STEP_11` **antes** da hidratação (`hydrateBeforeCreate`/`hydrateBeforeUpdate`) e das regras (`validate*`), bloqueia remoção/omissão de âncoras de escopo (`CC06`), valida custódia dual (`Cedente`/`Cessionário`) e grava obrigações no `TransactionalAuditOutboxPort`. |
| **Comandos de Workflow (`@WorkflowAction`)** | `executeGovernedVersionedCommand` / `executeGovernedItemCommand` | Combina propriedades do `commandDto` com `operationModifiedAttributes(actionId)`, valida `If-Match` (`412 Precondition Failed` se defasado), executa `STEP_11`, aplica máscara pós-mutação e limpa `ThreadLocal` em caso de erro. |
| **Operações em Lote (`Bulking`)** | `bulkDomainAdapter(mapper, validator, etags)` | Deriva `ResourceVersionScope` automaticamente de `AuthzCallerContextProvider`, exige `authorizeBulkControlOrGrantOperation` antes de adquirir lock de proposta e aplica `authorizeWorkerItemTarget` por item com `REQUIRES_NEW`. |
| **Determinações Reativas** | `defineReactiveDeterminations()`, `evaluateGovernedItemDetermination`, `evaluateGovernedDraftDetermination` | Auto-registra definições no Spring Context suprimindo outputs `VALUE+DENY`; inicializa `DataScopePlan` em memória para entidades draft, avalia determinações em item ou rascunho com máscara `TARGET` ao vivo e zero entradas no outbox. |
| **Contexto de IA (`Copilot / RAG`)** | `projectGovernedItemAiContext(id)`, `projectAiGovernanceMetadata()` | Suprime 100% dos atributos com `aiAllowed = false` / `LGPD_SENSITIVE_DATA` / `SECRET` / `CREDENTIAL` (`P47`, `P57`, `P62`). |
| **Duplicação Assistida (`duplicate-draft`)** | `executeGovernedDuplicateDraft(sourceId, builder)` | Valida escopo de leitura, decisão `TARGET` e custódia `Cedente`/`Cessionário`; limpa incondicionalmente para `null` campos `LGPD_SENSITIVE_DATA`, campos com máscara ativa (evitando poluir o rascunho com `"***"`), ponteiros técnicos de concorrência (`"/version"`) e campos fora da partição de escrita do chamador. |
| **Catálogo Semântico PAP & `RuntimeDecisionPointRegistry` (`Fase P10.13`)** | `deriveFieldLineageCatalogEntries()`, `synchronizeCatalogAndRegistryIfSupported` | Deriva automaticamente os registros `FieldLineageCatalogEntry` de `ResponseDTO` (`READ_PROJECTION`), `CreateDTO` (`CREATE_INPUT`) e `UpdateDTO` (`UPDATE_INPUT`) herdando governança por `attributeId`, e sincroniza `DualScopeDelegationSpec`, âncoras de escopo e linhagem de campos no `RuntimeDecisionPointRegistry` e no `SemanticDecisionPointCatalogService` no startup. |
| **Extração Automática Universal de `FILTER` e `SORT` (`Fases P10.15-A, P10.15-R01 & P10.15-R02`)** | `filter`, `filterByCursor`, `locate`, `exportCollection`, `selectBulkIdentities`, `filterOptions`, `filterOptionSourceOptions`, `byIdsOptionSourceOptions`, `groupByStats`, `timeSeriesStats`, `distributionStats`, `comparisonStats` | Inspeciona em tempo de execução os campos populados do `FilterDTO` (incluindo `@Filterable(relation = ...)` e omnibox `@Filterable(relations = {...})`) e as cláusulas `Sort` em **todas** as superfícies de consulta, exportação, seleção de lote (`QUERY` bulk cohort), lookups e analytics, mapeando-os para `FieldUseCategory.FILTER` e `FieldUseCategory.SORT` para bloquear sondagem por oráculo (*oracle probing*) em atributos `LGPD_SENSITIVE_DATA` sem necessidade de chamada manual a `withRequestedQueryFieldUses(...)`. |
| **Outbox Transacional JDBC Habilitado por Padrão (`Fase P10.15-B`)** | `PraxisAuthzAutoConfiguration.jdbcTransactionalAuditOutbox`, `JdbcAuditOutboxRelayExecutor.drainPendingBatch(Instant)` | Quando `JdbcOperations` está presente no contexto Spring, registra `JdbcTransactionalAuditOutbox` por padrão (`praxis.authz.outbox.jdbc-enabled=true`, `initialize-schema=true`) e configura `JdbcAuditOutboxRelayExecutor` com `relay-batch-size` e `max-delivery-attempts`. |
| **Bootstrap Multi-Recurso Zero-Boilerplate (`Fases P10.14, P10.15-C, P10.15-R03 & P10.16-A`)** | `AuthzResourceGovernanceSpec.Builder` (`.workflowAction(...)`, `.bulkWorkflowAction(...)`, `.uiSurface(...)`) + `AuthzHostPolicyBootstrapBuilder` (`.addGovernedService(...)`, `.addGovernedReadOnlyService(...)`, `.addOrganizationalScopePolicy(...)`, `.addActionPolicy(...)`, `.addBulkActionPolicy(...)`, `.addSurfacePolicy(...)`) + `executeGovernedBulkCommand(...)` | Sintetiza automaticamente `DecisionPointDescriptor`s para ações unitárias, ações em lote (`ActionScope.COLLECTION` / `BulkMode.DOMAIN_COMMAND`) e superfícies declaradas na spec e, a partir de um único `@Bean AuthzHostPolicyBootstrapBundle`, compila políticas primárias, de ações unitárias, de ações em lote e de superfícies (`@UiSurface`), auto-configurando `HostRuntimePolicyCoordinates`, `OpaClientTransport`, `RuntimeDecisionPointRegistry` e `SemanticDecisionPointCatalogService`. |
| **Anti-Spoofing de Cabeçalhos na Fronteira Servlet (`Fase P10.15-D`)** | `AuthzCallerContextFilter.doFilterInternal` | Executa `UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders` imediatamente na entrada do filtro HTTP, bloqueando cabeçalhos forjados (`X-Praxis-Authz-*`, `X-Authz-*`, `X-Roles`, `X-Tenant-Id`) tanto em requisições autenticadas quanto não autenticadas. |
| **Diagnóstico Explicável de Disponibilidade Contextual (`Fases P10.16-B & P10.16-R01/R04`)** | `AuthzResourceOperationAvailabilityProvider.evaluate(...)`, `OperationAvailabilityEvaluation.toSanitizedDecisionMetadata()` | Publica metadados diagnósticos estruturados e livres de valores sensíveis (`operationId`, `evaluationScope`, `denialCategory`, `dualScopeCustodyRole`, `forbiddenWriteAttributeIds`, `policyReasonCodes`) em `AvailabilityDecision.metadata()`, trata ausência de `AuthzCallerContext` de forma fail-closed (`caller-context-missing` / `CALLER_CONTEXT_MISSING`) e exige aprovação no gate primário do recurso antes de aprovar ações ou superfícies customizadas em escopo `ITEM`. |
| **Simulador Declarativo de Matriz de Políticas (`Fases P10.16-C & P10.16-R05`)** | `AuthzPolicySimulationHarness.forResource(spec, bundle, ResponseDTO.class)` | Permite testar em memória combinações tabulares de `AuthzCallerContext` &times; `Operation` &times; `Entity` (`simulateItemAvailability`, `simulateCollectionAvailability`, `simulateTargetRead`, `simulateSurfaceRead`, `simulateBulkCommand` e `.matrix().verifyAll()`) em JUnit sem exigir banco ou servidor HTTP. |

---

## 4. Gate JUnit de Prontidão no Host (`AuthzHostReadinessReviewer`)

Todo host que adota `praxis-authz-starter` deve incluir um teste JUnit executando [`AuthzHostReadinessReviewer`](../../../java/org/praxisplatform/authz/host/metadata/AuthzHostReadinessReviewer.java) para auditar estaticamente todos os serviços governados:

```java
@SpringBootTest
class HostAuthzReadinessGateTest {

    @Autowired
    private AuthzHostReadinessReviewer readinessReviewer;

    @Autowired(required = false)
    private List<AbstractAuthzGovernedReadOnlyResourceService<?, ?, ?, ?>> readOnlyServices = List.of();

    @Autowired(required = false)
    private List<AbstractAuthzGovernedResourceService<?, ?, ?, ?, ?, ?>> mutableServices = List.of();

    @Test
    void allGovernedServicesMustPassAuthzReadinessGate() {
        AuthzHostReadinessReviewer.ReadinessReport report =
                readinessReviewer.reviewAll(readOnlyServices, mutableServices);
        report.assertZeroIssues();
    }
}
```

### Regras Auditadas pelo `AuthzHostReadinessReviewer`

- **`AUTHZ-HOST-001`:** Verifica adoção declarativa de `AuthzResourceGovernanceSpec` e presença de `resourceKey`, `decisionPoint` e `factContractDigest`.
- **`AUTHZ-HOST-002`:** Verifica cobertura de introspecção de `ResponseDTO` e ausência de colisões de `attributeId` duplicado em ponteiros JSON distintos.
- **`AUTHZ-HOST-003`:** Verifica que todas as âncoras obrigatórias (`mandatoryScopeAnchorAttributeIds`) estão mapeadas tanto em `ResponseDTO` quanto em `CreateDTO`.
- **`AUTHZ-HOST-004`:** Verifica que `DualScopeDelegationSpec` possui regras declarativas de custódia `Cedente` e `Cessionário`, partições de escrita disjuntas e atributos mapeados nos DTOs.
- **`AUTHZ-HOST-005`:** Verifica que todas as entradas de `operationModifiedAttributes` são não-vazias e referenciam `attributeId`s existentes nos DTOs do recurso.
- **`AUTHZ-HOST-006` (`Fase P10.15-R04`):** Verifica por reflexão que `tenantFieldName`, `stateFieldName`, `cedenteEntityFieldPath`, `cessionarioEntityFieldPath`, todos os `QueryAdapterFieldBinding.nativeJpaPath()` (incluindo caminhos aninhados e coleções `1:N`) e todos os caminhos `@Filterable(relation / relations)` declarados no `FilterDTO` (`AUTHZ-HOST-006-INVALID-FILTERABLE-ENTITY-PATH`) existem na classe JPA `entityClass`.
- **`AUTHZ-HOST-007`:** Verifica coerência entre `factContractDigest` e `decisionPoint.factContractRef().factContractDigest()`, além da admissão do `DecisionPointDescriptor` principal e de todos os decision points de ações/superfícies no `RuntimeDecisionPointRegistry` com seus respectivos digests.
- **`AUTHZ-HOST-008`:** Audita definições de `defineReactiveDeterminations()` que referenciam atributos `VALUE + DENY` (`ERROR` — `AUTHZ-HOST-008-RESTRICTED-DETERMINATION-BINDING`) ou que usam atributos `LGPD_SENSITIVE_DATA` / mascaráveis como inputs ou `sourcePath`s (`WARNING` — `AUTHZ-HOST-008-SENSITIVE-DETERMINATION-INPUT`, alertando contra envio de placeholders mascarados `"***"` pelo formulário).
- **`AUTHZ-HOST-009`:** Audita a linhagem de campos (`FieldLineageCatalogEntry`) derivada de `ResponseDTO`, `CreateDTO` e `UpdateDTO` para o Catálogo Semântico PAP (`P44..P50`, `P57`, `P58`, `P64`), detectando ausência de `@DomainGovernance` explícita (`AUTHZ-HOST-009-MISSING-EXPLICIT-GOVERNANCE`), classificações de sensibilidade/IA contraditórias entre DTOs para o mesmo `attributeId` (`AUTHZ-HOST-009-CONTRADICTORY-LINEAGE-GOVERNANCE`) e alargamento indevido de governança em campos derivados (`AUTHZ-HOST-009-DERIVED-GOVERNANCE-WIDENING`).
- **`AUTHZ-HOST-010` (`Fases P10.15-E & P10.16-A`):** Verifica que o `DecisionPointDescriptor` primário e todos os decision points customizados de ações (`actionDecisionPoints`) e superfícies (`surfaceDecisionPoints`) possuem binding e cobertura de impacto em `HostRuntimePolicyCoordinates` (`ERROR` — `AUTHZ-HOST-010-MISSING-COORDINATES-BINDING`), exige `QueryableProjectionRef` em ações em lote com `SEARCH` / `DATA_SCOPE` (`ERROR` — `AUTHZ-HOST-010-BULK-ACTION-MISSING-QUERY-PROJECTION`), e alerta quando um decision point de ação customizada com capacidade `FIELD_WRITE` omite a declaração de atributos modificados em `operationModifiedAttributes` (`WARNING` — `AUTHZ-HOST-010-UNDECLARED-CUSTOM-ACTION-ATTRIBUTES`).
- **`AUTHZ-HOST-011` (`Fase P10.21-A`):** Audita `defineRawStatsFieldRegistry()` verificando se todo `StatsFieldDescriptor` (`field`, `keyPropertyPath`, `labelPropertyPath`) resolve para um caminho JPA válido na entidade ou em `spec.fieldBindings()` (`ERROR` — `AUTHZ-HOST-011-INVALID-STATS-ENTITY-PATH`) e bloqueia descritores analíticos mapeados para atributos `VALUE + DENY` (`SECRET` / `CREDENTIAL`) (`ERROR` — `AUTHZ-HOST-011-VALUE-DENIED-STATS-FIELD`).
- **`AUTHZ-HOST-012` (`Fase P10.21-A`):** Audita o `FilterDTO` do recurso e bloqueia qualquer propriedade anotada com `@Filterable` que mapeie para um atributo com `FieldUseCategory.VALUE + RuleEffect.DENY` (`SECRET` / `CREDENTIAL`) (`ERROR` — `AUTHZ-HOST-012-VALUE-DENIED-FILTERABLE-FIELD`), prevenindo inferência por canal lateral (*oracle attack*) sobre segredos/credenciais.
- **`AUTHZ-HOST-013` (`Fase P10.22-A`):** Audita `defineRawExportFields()` em serviços governados e valida cada `CollectionExportField` contra caminhos inválidos no `ResponseDTO` (`ERROR` — `AUTHZ-HOST-013-INVALID-EXPORT-FIELD-PATH`), atributos marcados com `@DomainGovernance(exportable = false)` (`WARNING` — `AUTHZ-HOST-013-NON-EXPORTABLE-FIELD-IN-EXPORT-ALLOWLIST`) e atributos `VALUE + DENY` (`SECRET` / `CREDENTIAL`) (`ERROR` — `AUTHZ-HOST-013-VALUE-DENIED-EXPORT-FIELD`).
- **`AUTHZ-HOST-014` (`Fase P10.23-A`, `Fase P10.24-A` & `Fase P10.25-A`):** Audita `getDeclaredOptionSourceRegistry()` (`OptionSourceDescriptor`, `EntityLookupDescriptor`, `LookupSelectionPolicy`, `LookupDisplayDescriptor`, `LookupFilteringDescriptor` e `dependencyFilterMap`) contra caminhos de propriedade inexistentes na entidade JPA / `ResponseDTO` / `FilterDTO` (`ERROR` — `AUTHZ-HOST-014-INVALID-OPTION-SOURCE-PATH`), contra a exposição de atributos `VALUE + DENY` (`SECRET` / `CREDENTIAL`) em campos de projeção, política de seleção, ordenação ou filtros de lookup (`ERROR` — `AUTHZ-HOST-014-VALUE-DENIED-OPTION-SOURCE-FIELD`) e contra o uso de atributos estaticamente restritos para `FILTER` / `SORT` (`LGPD_SENSITIVE_DATA` / `RESTRICTED`) em `dependencyFilterMap`, `searchPropertyPaths`, `availableFilters`, `defaultFilters`, `quickFilterFields` ou `sortOptions` (`ERROR` — `AUTHZ-HOST-014-RESTRICTED-OPTION-SOURCE-QUERY-FIELD`).

---

## 5. Simulação Declarativa de Matriz de Políticas em JUnit (`AuthzPolicySimulationHarness` — `Fase P10.16-C`)

Use [`AuthzPolicySimulationHarness`](../../../java/org/praxisplatform/authz/host/metadata/AuthzPolicySimulationHarness.java) para validar a matriz de autorização de um recurso em memória:

```java
AuthzPolicySimulationHarness.forResource(spec, bundle, AfastamentoResponseDTO.class)
        .matrix()
        .expectItemAvailability("Cedente pode homologar", cedenteCaller, "homologar-afastamento", entity101, true, null)
        .expectItemAvailability("Cedente não designa substituto", cedenteCaller, "designar-substituto", entity101, false, "dual-scope-custody-denied")
        .expectCollectionAvailability("Cedente pode homologar em lote", cedenteCaller, "homologar-lote", true, null)
        .expectBulkCommand("Coorte mista em PER_ITEM", cedenteCaller, "homologar-lote", List.of(entity101, entity102), e -> e.getId(), BatchAuthorizationMode.PER_ITEM, List.of(true, false))
        .expectTargetReadAllowed("Leitura mascara CID", cedenteCaller, entity101, rawDto, Set.of("hr.afastamentos.cid_codigo"))
        .expectDuplicateDraft("Clonagem assistida limpa CID e partição Cessionário", cedenteCaller, entity101, rawDraft, true, Set.of("hr.afastamentos.cid_codigo", "substitutoDesignado"))
        .expectCollectionExport("Exportação exclui campos não-exportáveis e VALUE+DENY", cedenteCaller, List.of(entity101, entity102), service::toRawDto, 1, Set.of("cidCodigo"))
        .expectReactiveDetermination("Determinação reativa mascara CID", cedenteCaller, entity101, Map.of("cidCodigo", "J11", "diasPrevistos", 15), true, Set.of("hr.afastamentos.cid_codigo"))
        .expectAiContextProjection("Projeção AI suprime CID", cedenteCaller, entity101, rawDto, true, Set.of("cidCodigo", "hr.afastamentos.cid_codigo"))
        .expectQueryFieldUse("Filtro em CID sensível bloqueado fail-closed", cedenteCaller, Map.of(FieldUseCategory.FILTER, Set.of("cidCodigo")), false, FieldUseCategory.FILTER, "hr.afastamentos.cid_codigo")
        .expectGroupByStats("Agrupamento em CID bloqueado", cedenteCaller, "cidCodigo", Set.of(), false, FieldUseCategory.GROUP, "hr.afastamentos.cid_codigo")
        .expectOptionSource("OptionSource filtra apenas itens em escopo", cedenteCaller, List.of(entity101, entity102), e -> new OptionDTO<>(e.getId(), e.getStatus(), Map.of()), Set.of(101L))
        .expectUpdateMutation("Cedente bloqueado ao editar partição Cessionário", cedenteCaller, entity101, updateSubstitutoDto, false, "dual-scope-custody-denied")
        .expectComparisonStats("ComparisonStats bloqueia filtro em CID sensível", cedenteCaller, "statusAfastamento", Set.of(), filterPadrao, filterPorCid, false, FieldUseCategory.FILTER, "hr.afastamentos.cid_codigo")
        .expectBulkUpdateCohort("BulkUpdate em REJECT_ALL aborta coorte quando 1 item está fora de escopo", cedenteCaller, List.of(entity101, entity102), e -> e.getId(), updateCidDto, BatchAuthorizationMode.REJECT_ALL, true, Set.of())
        .expectBulkUpdateCohort("BulkUpdate em PER_ITEM confirma apenas itens elegíveis", cedenteCaller, List.of(entity101, entity102), e -> e.getId(), updateCidDto, BatchAuthorizationMode.PER_ITEM, false, Set.of(101L))
        .expectTwoPhaseBulkConfirm("Bulk 2 fases bloqueia Confused Deputy", cedenteCaller, outroCaller, "digest-v1", "digest-v1", List.of(entity101), e -> e.getId(), service::toRawDto, updateCidDto, BatchAuthorizationMode.REJECT_ALL, false, "AUTHZ_BULK_CONFUSED_DEPUTY_DENIED")
        .expectHeaderSpoofingGuard("Header X-Praxis-Authz-Roles bloqueado", spoofedHeaderCaller, false, "X-Praxis-Authz-Roles")
        .verifyAll();
```

---
## 6. Declarative Annotations (`@Authz*`) and Automatic `@DomainGovernance` Masking

Instead of hand-coding `FactContract`, `DualScopeDelegationSpec`, and JSON-Logic rule boilerplate for every resource, hosts can declare governance directly with annotations from `praxis-authz-contracts`:

| Annotation | Target | Purpose |
| :--- | :--- | :--- |
| `@AuthzTenantScope` | Service, Controller, Entity, or field/getter | Configures tenant/organization isolation (`TENANT_ONLY`, `ORGANIZATIONAL_UNIT`, `AUTHENTICATED_SHARED`), `tenantField`, `resourceFactPath`, `subjectFactPath`, and optional bulk-without-scope controls. |
| `@AuthzScopeAnchor` | Entity field/getter or DTO field | Marks mandatory scope anchor attributes (`requiredOnCreate`, `forbidClearOnUpdate`, `immutableAfterCreate`). |
| `@AuthzCustodyPartition` | Entity field/getter, Service, or Controller | Declares origin vs destination dual-custody split (`AuthzCustodyRole.ORIGIN` / `DESTINATION`, `AuthzDelegationSplitMode`) and field write partitions. |
| `@AuthzMask` | Response DTO field/record component or Service/Entity | Declares explicit `MaskContributionSpec` masking (`AuthzMaskStrategy`, `EvaluationMode`, optional target `surfaces`). |
| `@AuthzActionRule` | `@WorkflowAction` / `@UiSurface` method or type | Declares `requiredRoles`, `conditionFactPath` / `conditionAllowedValues`, `conditionJsonLogic`, `allowedWriteAttributes`, `reasonCode`, and audit obligations. |

When introspecting DTOs via `MetadataDtoGovernanceIntrospector`, sensitive/restricted/confidential fields annotated with `@DomainGovernance` automatically derive baseline `MaskContributionSpec` directives (`REDACT_CONSTANT("***")` for `String` fields and `NULLIFY` for nullable non-`String` reference fields) or fail-closed `FieldUseCategory.VALUE` + `RuleEffect.DENY` (`OMIT_BY_FIELD_USE_DENY`) for primitive or non-nullable non-`String` fields, while `SECRET` and `CREDENTIAL` classifications also enforce `VALUE + DENY`. Explicit `@AuthzMask` declarations override derived masks per `attributeId`.

With an introspected `AuthzResourceGovernanceSpec`, call `AuthzHostPolicyBootstrapBuilder.addAnnotatedResource(spec)` (or `addAnnotatedResources(specs)`) to synthesize zero-config primary scope policies, field-masking policies, workflow action policies, and UI surface policies automatically (keeping disjunctive `"or"` nodes at the JSON-Logic root for `RegoV1PolicyCompiler`).

---

## 7. Zero-Boilerplate Interception, Availability Rules, Multi-Organization Hard Scope, and `AUTHZ-HOST-010`

`PraxisAuthzHostBridgeAutoConfiguration` automatically registers platform beans with `@ConditionalOnMissingBean` and `@ConditionalOnClass`:

- **`AuthzResourceGovernanceInterceptor`**: Implements `ResourceGovernanceInterceptor` for plain Praxis `AbstractBaseQueryResourceService` and `AbstractBaseResourceService` services without requiring inheritance from `AbstractAuthzGovernedReadOnlyResourceService` or `AbstractAuthzGovernedResourceService` (which are automatically bypassed to prevent double enforcement). It resolves registered `AuthzResourceGovernanceSpec` beans or lazily introspects `@Authz*` + `@ApiResource` annotations, enforcing query hard scopes, OPA `DataScopePlan` pushdown, entity access checks, export/stats field-use filtering, `beforeMutation` (`WriteIntent` + immutable scope anchors), `afterMutationBeforeCommit` (`BEFORE_COMMIT_OUTBOX`), and detached DTO response masking. Set `praxis.authz.interceptor.fail-closed-unconfigured-services=true` to reject any plain service lacking both a spec bean and `@AuthzTenantScope`.
- **`AuthzResourceOperationAvailabilityRule` + `@Primary CompositeResourceOperationAvailabilityEvaluator`**: Wraps `AuthzResourceOperationAvailabilityProvider` as an ordered `ResourceOperationAvailabilityRule` (`DEFAULT_ORDER = Ordered.HIGHEST_PRECEDENCE + 300`) so Praxis authorization decisions combine cleanly under deny-wins semantics with host-specific availability rules.
- **`MultiOrganizationHardScopeResolver` (`HardScopeResolver`)**: Default hard-scope resolver supporting single-tenant (`= :__praxis_hard_tenant_id`), multi-organization (`IN :__praxis_hard_tenant_ids`), fail-closed empty organization sets, shared catalogs (`1 = 1` when `AUTHENTICATED_SHARED`), consolidation read-only write guards (`FACT_READ_ONLY_CONSOLIDATION_SCOPE`), and `immutableAfterCreate` anchor checks on updates.
- **Resolving `AUTHZ-HOST-010`**: Use `AuthzHostReadinessReviewer.reviewInterceptorBoundServices(...)` or the 4-argument `reviewAll(...)` alongside `reviewReadOnlyService` / `reviewMutableService`. Declare `allowedWriteAttributes` via `@AuthzActionRule` (or keep transition-only actions without `FIELD_WRITE` when `allowedWriteAttributes = {}`), type command payloads cleanly for DTO write-intent discovery, and keep `HostRuntimePolicyCoordinates` / `AuthzHostPolicyBootstrapBuilder.addAnnotatedResource(...)` aligned with all custom action and surface decision points.

---

## 8. Fail-Closed Agent Bridge (`PraxisAuthzAgentBridgeAutoConfiguration`)

When AI agents or tool runtimes operate over Praxis resources in the same Spring Boot application, `PraxisAuthzAgentBridgeAutoConfiguration` wires `AuthzAgentAuthorizationBridge` and `AuthzAgentThreadContextPropagator` using the host's configured `AuthzCallerContextProvider`, `MetadataResourceAuthorizationSeam`, and `AuthzResourceOperationAvailabilityProvider`:

- Agent invocations never run with ambient elevated privilege: every tool or catalog execution carries an explicit, fail-closed caller context (`AuthzCallerContext`).
- Advisory discovery checks (HATEOAS / action availability) remain separated from runtime target/write authorization enforcement so stale discovery metadata cannot bypass live policy updates.

---

## 9. Clonagem Assistida (`DuplicateDraft`) e Exportação Governada (`Fase P10.17`)

- **Clonagem Assistida (`executeGovernedDuplicateDraft`):**
  - Implementações de `DuplicateDraftResourceService` / `DuplicateDraftResourceCommandService` devem delegar para `executeGovernedDuplicateDraft(sourceId, rawDraftBuilder)` (ou `executeGovernedDuplicateDraft(sourceId, operationId, rawDraftBuilder)`).
  - O método valida o escopo do item de origem (`findEntityById(sourceId)`), avalia a projeção `TARGET` ao vivo (combinando o `decisionPoint` primário com o ponto de decisão específico de `duplicate-draft` quando existente), verifica custódia `DualScopeDelegationSpec` e limpa para `null` todo atributo sensível (`LGPD_SENSITIVE_DATA`/`SECRET`), `VALUE + DENY`, alvo de `MaskDirective`, negado para escrita (`FIELD_WRITE + DENY`), ponteiro técnico (`/version`) ou pertencente à partição exclusiva da contraparte (`Cedente`/`Cessionário`), preservando apenas âncoras obrigatórias de escopo.
- **Exportação Governada (`AuthzGovernedCollectionExportExecutor`):**
  - Remove automaticamente das colunas e linhas exportadas (`CSV`, `JSON`, `EXCEL`) todos os campos com `@DomainGovernance(exportable = false)`, atributos estática ou dinamicamente negados com `VALUE + DENY` no contexto `SEARCH` da requisição e atributos com `MaskStrategy.OMIT_FIELD`, aplicando as `MaskDirective`s ativas nas demais colunas.

---

## 10. Determinações Reativas, Projeção AI e Guarda de `QueryFieldUse` (`Fase P10.18`)

- **Determinações Reativas Governadas (`evaluateGovernedItemDetermination` / `evaluateGovernedDraftDetermination` / `simulateReactiveDetermination`):**
  - Avaliam o escopo organizacional e o gate `TARGET` (combinando o `decisionPoint` primário do recurso com o ponto de decisão específico da determinação quando existente) antes de executar o cálculo de domínio sobre a entidade bruta (`STEP_12`/`STEP_13`) e mascaram o mapa/DTO de retorno em cópia desacoplada (`STEP_15`) sem gerar `BEFORE_COMMIT_OUTBOX`.
- **Projeção de Contexto AI / Tool Grounding (`projectGovernedItemAiContext` / `simulateAiContextProjection`):**
  - Avalia o gate `TARGET` ao vivo e suprime integralmente todos os atributos com `@DomainGovernance(aiAllowed = false)` ou `LGPD_SENSITIVE_DATA` (`aiContextDeniedAttributeIds`), além de `VALUE + DENY` estáticos/dinâmicos, retornando um `SanitizedAiToolProjection` auditável.
- **Guarda de Uso de Campos em Consulta (`validateSearchQueryFieldUses` / `simulateQueryFieldUse` / `simulateFilterAndSortFieldUse`):**
  - Bloqueia *fail-closed* com `FieldUseViolationException` qualquer tentativa de filtrar (`FILTER`), ordenar (`SORT`), agrupar (`GROUP`), agregar (`AGGREGATE`) ou fazer junção (`JOIN`) sobre atributos sensíveis (`LGPD_SENSITIVE_DATA`, `SECRET`) ou negados por diretivas `FieldUseEffectDirective` estáticas ou dinâmicas do OPA, prevenindo inferência por canal lateral (*oracle attack*).

---

## 11. Simulação de Analytics (`StatsFieldRegistry`), `OptionSource` e Mutações de Escrita (`STEP_11`) (`Fase P10.19`)

- **Analytics (`simulateGroupByStats` / `simulateFilteredStatsRegistry`):**
  - Valida em memória que dimensões (`GROUP`) e métricas (`AGGREGATE`) sobre atributos restritos ou `VALUE + DENY` falham *fail-closed* e que `StatsFieldRegistry` remove dimensões sensíveis da descoberta (`/schemas/filtered` e `/capabilities`).
- **Lookups e `OptionSource` (`simulateOptionSource` / `sanitizeOptionsWithDirectives`):**
  - Garante omissão silenciosa de itens fora de escopo (`hardScope` + `DataScopePlan` + `TARGET`), mascaramento/redação de `OptionDTO.extra` (`displayFields`, `richFields`, `badges`, `description`, `label`) e marcação `selectable = false` / `historicalDisplayOnly = true` conforme `LookupSelectionPolicy`.
- **Mutações de Escrita em `STEP_11` (`simulateCreateMutation`, `simulateUpdateMutation`, `simulateDeleteMutation`, `simulateItemCommandMutation`):**
  - Executa a extração real de `WriteIntent` (`DtoWriteIntentExtractor`), proteção contra omissão/limpeza de âncoras de escopo (`scope-anchor-clear-forbidden`), partição de custódia `DualScopeDelegationSpec` (`dual-scope-custody-denied`) e `FieldWriteAuthorizer` (`field-write-denied`) em memória.

---

## 12. Paridade Read-Only e Simulação de Coortes Bulk (`REJECT_ALL` / `PER_ITEM`) + Modalidades Analíticas Completas (`Fase P10.20`)

- **Paridade Canônica em `AbstractAuthzGovernedReadOnlyResourceService` (`P10.20-A`):**
  - Serviços read-only e Radares analíticos que sobrescrevem o `DecisionPointDescriptor` em `evaluateGovernedItemDetermination`, `evaluateGovernedDraftDetermination` ou `projectGovernedItemAiContext` agora propagam automaticamente `primaryValueDenied` e `primaryMasks` do recurso primário para a avaliação secundária, além de honrar `callerCtx.callerMatchesCedente()` / `callerMatchesCessionario()` em `buildAvailabilityPolicyBinding()` e propagar `governanceSpec` para `AuthzGovernedStatsQueryExecutor`.
- **Modalidades Analíticas Completas com `FilterDTO` (`P10.20-B`):**
  - `simulateGroupByStats(caller, groupByField, metricFields, filterDto)`, `simulateTimeSeriesStats(...)`, `simulateDistributionStats(...)` e `simulateComparisonStats(...)` validam conjuntamente `FieldUseCategory.FILTER` (nos filtros primário e de comparação), `FieldUseCategory.GROUP` e `FieldUseCategory.AGGREGATE`.
- **Simulação de Coortes de Operações em Lote (`BulkMutationSimulationOutcome<ID>` — `P10.20-B`):**
  - `simulateBulkUpdateCohort`, `simulateBulkPerItemUpdateCohort`, `simulateBulkDeleteCohort` e `simulateBulkCommandCohort` avaliam o `STEP_11` completo para cada entidade da coorte sob `BatchAuthorizationMode.REJECT_ALL` (abortando toda a coorte ao menor item inválido com `BATCH_ABORTED`) ou `BatchAuthorizationMode.PER_ITEM` (isolando falhas por item em `FIELD_WRITE_DENIED` / `ACCESS_OR_SCOPE_DENIED` e confirmando os demais).

---

## 13. Gates Arquiteturais `AUTHZ-HOST-011` / `AUTHZ-HOST-012` e Simulação de Bulk em 2 Fases + Anti-Spoofing de Headers (`Fase P10.21`)

- **Auditoria Estática de `StatsFieldRegistry` e `FilterDTO` (`AUTHZ-HOST-011` & `AUTHZ-HOST-012` — `P10.21-A`):**
  - `AuthzHostReadinessReviewer` inspeciona automaticamente `defineRawStatsFieldRegistry()` em serviços read-only e mutáveis (`AUTHZ-HOST-011-INVALID-STATS-ENTITY-PATH` e `AUTHZ-HOST-011-VALUE-DENIED-STATS-FIELD`) e audita `@Filterable` no `FilterDTO` contra atributos `VALUE + DENY` (`AUTHZ-HOST-012-VALUE-DENIED-FILTERABLE-FIELD`).
- **Simulação de Proposta e Confirmação Bulk em 2 Fases (`simulateTwoPhaseBulkProposalAndConfirm` — `P10.21-B`):**
  - Valida a sanitização/mascaramento dos previews de proposta (`proposalPreviewsById`) na Fase 1 e verifica na Fase 2 a proteção anti-*confused-deputy* (`AUTHZ_BULK_CONFUSED_DEPUTY_DENIED` quando `confirmingCaller` difere de `proposingCaller` em principal ou tenant, `P15`/`P34`) e a continuidade do digest de política (`AUTHZ_BULK_POLICY_REVOKED_OR_ROTATED` quando `confirmPolicyDigest != proposalPolicyDigest`, `P15`/`P18`).
- **Simulação de Guarda Anti-Spoofing de Headers (`simulateHeaderSpoofingGuard` — `P10.21-B`):**
  - Valida `UntrustedRequestHeaderGuard` contra `AuthzCallerContext.incomingHeaderNames()` (`P02`, `P53`), rejeitando cabeçalhos internos/autoridade forjados pelo cliente (`UNTRUSTED_AUTHORITY_HEADER_SPOOFING`).

---

## 14. Filtragem Governada de `exportFields()` (`defineRawExportFields()`), Gate `AUTHZ-HOST-013` e Simulação de Determinações Reativas em Rascunho (`Fase P10.22`)

- **Descoberta Governada de Exportação (`defineRawExportFields()` / `exportFields()` — `P10.22-A`):**
  - `AbstractAuthzGovernedResourceService` e `AbstractAuthzGovernedReadOnlyResourceService` sobrescrevem `exportFields()` (`final`) delegando a `defineRawExportFields()` e filtrando via `AuthzGovernedCollectionExportExecutor.filterDiscoveryExportFields(...)` qualquer coluna com `exportable = false` ou `VALUE + DENY` (`SECRET` / `CREDENTIAL`), garantindo que recursos 100% restritos reportem `supportsCollectionExport() == false` em `/capabilities`.
- **Gate Estático `AUTHZ-HOST-013` (`P10.22-A`):**
  - `AuthzHostReadinessReviewer` inspeciona `defineRawExportFields()` (ou uma lista explícita de `CollectionExportField` em `reviewGovernanceSpec`) e bloqueia caminhos inexistentes no `ResponseDTO` (`AUTHZ-HOST-013-INVALID-EXPORT-FIELD-PATH`), campos não-exportáveis (`AUTHZ-HOST-013-NON-EXPORTABLE-FIELD-IN-EXPORT-ALLOWLIST`) e atributos `VALUE + DENY` (`AUTHZ-HOST-013-VALUE-DENIED-EXPORT-FIELD`).
- **Simulação de Determinações Reativas em Modo Rascunho (`simulateDraftReactiveDetermination` — `P10.22-B`):**
  - Valida determinações reativas `POST` em modo `CREATE`/rascunho (sem entidade persistida), bloqueando cabeçalhos forjados, verificando disponibilidade de coleção (`"create"`), rejeitando entradas `VALUE + DENY` (`"draft-input-value-denied"`) e mascarando o payload de saída.
- **Cobertura Completa no `MatrixRunner` (`P10.22-B`):**
  - `expectSurfaceRead`, `expectReactiveDetermination`, `expectDraftReactiveDetermination` e `expectBulkPerItemUpdateCohort` permitem compor toda a matriz declarativa em uma única bateria fluente.

---

## 15. Gate `AUTHZ-HOST-014` (`OptionSourceRegistry`) e Simulação de Paginação Keyset (`simulateCursorFilter`) (`Fase P10.23`)

- **Auditoria Estática de `OptionSourceRegistry` (`AUTHZ-HOST-014` — `P10.23-A`):**
  - `AuthzHostReadinessReviewer` inspeciona `getDeclaredOptionSourceRegistry()` (ou um `OptionSourceRegistry` explícito passado a `reviewGovernanceSpec`) e valida todos os caminhos declarados em `OptionSourceDescriptor`, `EntityLookupDescriptor`, `LookupSelectionPolicy` e `LookupDisplayDescriptor` contra a entidade JPA / `ResponseDTO` (`AUTHZ-HOST-014-INVALID-OPTION-SOURCE-PATH`) e contra atributos `VALUE + DENY` (`SECRET` / `CREDENTIAL`) (`AUTHZ-HOST-014-VALUE-DENIED-OPTION-SOURCE-FIELD`).
- **Simulação de Paginação por Cursor (`simulateCursorFilter` — `P10.23-B`):**
  - Simula `filterByCursor(filter, sort, after, before, size)` em memória, aplicando guarda anti-spoofing de cabeçalhos, validação pré-SQL de `FieldUseCategory.FILTER` e `FieldUseCategory.SORT`, escopo organizacional, fatiamento por cursor (`afterId` / `beforeId` / `pageSize`) e mascaramento desacoplado de `ResponseDTO`.
- **Expansão do `MatrixRunner` (`P10.23-B`):**
  - `expectCollectionExport`, `expectOptionSource` e `expectCursorFilter` completam a verificação declarativa tabular de exportação, lookups e paginação keyset.

---

## 16. Expansão do Gate `AUTHZ-HOST-014` (`LookupFilteringDescriptor` / `dependencyFilterMap`) e Simulação de `locate` / `findAllById` (`Fase P10.24`)

- **Auditoria Completa de `LookupFilteringDescriptor` e `dependencyFilterMap` (`AUTHZ-HOST-014` — `P10.24-A`):**
  - `AuthzHostReadinessReviewer` inspeciona `OptionSourceDescriptor.dependencyFilterMap()`, `EntityLookupDescriptor.dependencyFilterMap()`, `availableFilters` (`LookupFilterDefinition.field()`), `sortOptions` (`LookupSortOption.field()`) e `quickFilterFields` de `LookupFilteringDescriptor`, bloqueando caminhos inexistentes na entidade JPA / `ResponseDTO` / `FilterDTO` (`AUTHZ-HOST-014-INVALID-OPTION-SOURCE-PATH`) e campos `VALUE + DENY` (`SECRET` / `CREDENTIAL`) (`AUTHZ-HOST-014-VALUE-DENIED-OPTION-SOURCE-FIELD`).
- **Simulação de `locate(filterDto, sort, targetId)` e `findAllById(Collection<ID>)` (`P10.24-B`):**
  - `simulateLocate` (`LocateSimulationOutcome<ID>`) simula a localização posicional (`OptionalLong`) no conjunto filtrado e ordenado do chamador, bloqueando cabeçalhos forjados, validando `FieldUseCategory.FILTER` e `FieldUseCategory.SORT` pré-SQL e garantindo zero vazamento de existência (`OptionalLong.empty()`) para IDs fora de escopo ou cross-tenant (`P06`, `P07`, `P50`).
  - `simulateFindAllById` (`FindAllByIdSimulationOutcome<ID, ResponseDTO>`) simula a recuperação em lote por IDs preservando a ordem solicitada, omitindo silenciosamente registros fora de escopo (`P06`, `P07`) e aplicando mascaramento desacoplado (`DetachedDtoMaskingProcessor`).
  - `expectLocate` e `expectFindAllById` no `MatrixRunner` permitem verificar `locate` e `findAllById` na matriz declarativa.

---

## 17. Blindagem de `AuthzGovernedOptionSourceProvider` (`sortKey` Simbólico e `search`), `AUTHZ-HOST-014-RESTRICTED-OPTION-SOURCE-QUERY-FIELD` e Simulação Estruturada de `OptionSource` (`Fase P10.25`)

- **Resolução de `sortKey` Simbólico, `search` Textual e `QueryAdapterFieldBinding` em `AuthzGovernedOptionSourceProvider` (`P10.25-A`):**
  - `AuthzGovernedOptionSourceProvider` recebe `AuthzResourceGovernanceSpec<?>`, traduz chaves simbólicas `sortKey` através de `descriptor.effectiveFiltering().sortOptions()`, valida termos de busca `search` contra `searchPropertyPaths` e `quickFilterFields` (`FieldUseCategory.FILTER`) e resolve `QueryAdapterFieldBinding`s antes do SQL.
- **Gate `AUTHZ-HOST-014-RESTRICTED-OPTION-SOURCE-QUERY-FIELD` e `defaultFilters` (`P10.25-A`):**
  - `AuthzHostReadinessReviewer` audita `LookupFilteringDescriptor.defaultFilters()`, resolve anotações `@Filterable(relation/relations)` e `@DomainLineage` do `FilterDTO` e emite `AUTHZ-HOST-014-RESTRICTED-OPTION-SOURCE-QUERY-FIELD` (`ERROR`) quando filtros, buscas ou ordenações de `OptionSource` referenciam atributos com `FILTER + DENY` ou `SORT + DENY` estático (`LGPD_SENSITIVE_DATA` / `RESTRICTED`).
- **Simulação de `OptionSource` com `LookupFilterRequest`, `sortKey` e `search` (`P10.25-B`):**
  - `simulateOptionSource(...)` e `expectOptionSource(...)` no `AuthzPolicySimulationHarness` suportam `List<LookupFilterRequest> lookupFilters`, `String sortKey` e `String search`, validando anti-spoofing de cabeçalhos e `FieldUseCategory.FILTER` / `FieldUseCategory.SORT` com `assertDenied(FieldUseCategory, String)`.

---

## 18. Fallback de `search` para `labelPropertyPath`, Resolução de `defaultSort` / `Sort("label" | "id")`, `AUTHZ-HOST-014-INVALID-OPTION-SOURCE-DEFAULT-SORT` e Uniformidade Anti-Spoofing (`Fase P10.26`)

- **Fallback de `search` e Ordenação Implícita (`defaultSort` / `Sort("label" | "id")`) em `OptionSource` (`P10.26-A`):**
  - Quando `search` não está em branco (`allowSearch = true` e `searchMode != "none"`) e `searchPropertyPaths` está vazio, `AuthzGovernedOptionSourceProvider` e `AuthzPolicySimulationHarness` validam o caminho de fallback (`labelPropertyPath` ou `propertyPath`) contra `FieldUseCategory.FILTER` (espelhando `JpaOptionSourceQueryExecutor.resolveSearchPaths`).
  - Ordenações via `Pageable` ou `sortKey` usando `"label"` / `"id"` são traduzidas para `labelPropertyPath` / `valuePropertyPath` (ou `propertyPath`), e quando `sortKey` é omitido em `OptionSourceOperation.FILTER`, `descriptor.effectiveFiltering().defaultSort()` é resolvido e validado contra `FieldUseCategory.SORT`.
- **Gate `AUTHZ-HOST-014-INVALID-OPTION-SOURCE-DEFAULT-SORT` e `labelPropertyPath` Pesquisável (`P10.26-A`):**
  - `AuthzHostReadinessReviewer` emite `AUTHZ-HOST-014-INVALID-OPTION-SOURCE-DEFAULT-SORT` (`ERROR`) quando `LookupFilteringDescriptor.defaultSort()` não corresponde a nenhuma `LookupSortOption.key()` declarada em `sortOptions`, e audita `labelPropertyPath` / `propertyPath` quanto a `AUTHZ-HOST-014-RESTRICTED-OPTION-SOURCE-QUERY-FIELD` quando o lookup permite busca textual sem `searchPropertyPaths` explícito.
- **Uniformidade Anti-Spoofing (`P02` / `P53`) em `AuthzPolicySimulationHarness` (`P10.26-B`):**
  - `simulateQueryFieldUse` (incluindo `simulateFilterAndSortFieldUse` e todas as 4 modalidades analíticas `/stats/*`), `simulateCollectionExport`, `simulateReactiveDetermination` e `simulateAiContextProjection` validam `simulateHeaderSpoofingGuard(caller)` na entrada.

