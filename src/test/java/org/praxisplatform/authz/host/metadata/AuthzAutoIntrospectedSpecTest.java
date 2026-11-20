package org.praxisplatform.authz.host.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Transient;
import jakarta.persistence.Version;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.praxisplatform.authz.contracts.annotation.AuthzTenantScopeMode;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.datascope.ComparisonPredicateIr;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.DataScopePlan;
import org.praxisplatform.authz.contracts.datascope.LiteralListOperandIr;
import org.praxisplatform.authz.contracts.datascope.PushdownMode;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateOperator;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyRule;
import org.praxisplatform.authz.contracts.policy.FieldUseContributionSpec;
import org.praxisplatform.authz.contracts.policy.PolicyFieldSelector;
import org.praxisplatform.uischema.action.ActionScope;
import org.praxisplatform.uischema.annotation.ApiResource;
import org.praxisplatform.uischema.annotation.DomainGovernance;
import org.praxisplatform.uischema.annotation.DomainGovernancePreset;
import org.praxisplatform.uischema.annotation.UiSurface;
import org.praxisplatform.uischema.annotation.WorkflowAction;
import org.praxisplatform.uischema.filter.annotation.Filterable;
import org.praxisplatform.uischema.filter.annotation.Filterable.FilterOperation;
import org.praxisplatform.uischema.surface.SurfaceKind;
import org.praxisplatform.uischema.surface.SurfaceScope;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;

class AuthzAutoIntrospectedSpecTest {

    @Test
    void derivedFactAndProjectionDigestsUseCanonicalPathOrder() {
        var forward = resourceWithQueryableFields("alpha", "omega");
        var reverse = resourceWithQueryableFields("omega", "alpha");
        var changed = resourceWithQueryableFields("alpha", "zulu");

        assertThat(reverse.factContract()).isEqualTo(forward.factContract());
        assertThat(reverse.queryProjection()).isEqualTo(forward.queryProjection());
        assertThat(changed.factContractDigest()).isNotEqualTo(forward.factContractDigest());
        assertThat(changed.queryProjection().projectionDigest()).isNotEqualTo(forward.queryProjection().projectionDigest());
    }

    private static AuthzResourceGovernanceSpec<Object> resourceWithQueryableFields(String... fields) {
        var builder = AuthzResourceGovernanceSpec.builder("catalog.shared-records")
                .serviceKey("shared-catalog-host");
        for (String field : fields) {
            builder.scalarFieldBinding("resource." + field, "attribute." + field, field);
        }
        return builder.build();
    }

    @ParameterizedTest
    @CsvSource({
            "'', resource.middle",
            "resource.zulu, resource.zulu"
    })
    void sharedBootstrapUsesCanonicalPathsAndKeepsExplicitBulkScope(
            String configuredFactPath,
            String expectedBulkFactPath
    ) {
        String serviceKey = "shared-catalog-host";
        String actionKey = "approve-batch";
        Set<SearchPredicateOperator> bulkOperators = Set.of(
                SearchPredicateOperator.EQ, SearchPredicateOperator.IS_NOT_NULL
        );
        var spec = AuthzResourceGovernanceSpec.builder("catalog.shared-records")
                .serviceKey(serviceKey)
                .tenantScope(new AuthzResourceGovernanceSpec.TenantScopeSpec(
                        AuthzTenantScopeMode.AUTHENTICATED_SHARED, "", "",
                        "subject.principalId", "", "", false, configuredFactPath
                ))
                .scalarFieldBinding("resource.zulu", "attribute.a", "e.zulu",
                        FactValueType.STRING, bulkOperators, false)
                .scalarFieldBinding("resource.middle", "attribute.b", "e.middle",
                        FactValueType.STRING, bulkOperators, false)
                .scalarFieldBinding("resource.first", "attribute.c", "e.first",
                        FactValueType.STRING, Set.of(SearchPredicateOperator.EQ), false)
                .resourceSensitiveFact("resource.earliest", "attribute.d", FactValueType.STRING, null, null)
                .bulkWorkflowAction(actionKey, Set.of())
                .build();
        Map<String, Object> principalPresent = Map.of("!=", List.of(Map.of("var", "subject.principalId"), ""));
        var manual = AuthzHostPolicyBootstrapBuilder.forService(serviceKey)
                .addResourceSpec(spec, null, null, null)
                .addAuthenticatedSharedPolicy(spec, "shared-search", List.of())
                .addSharedBulkActionPolicy(spec, actionKey, "shared-approve", principalPresent, Set.of())
                .build();
        var annotated = AuthzHostPolicyBootstrapBuilder.forService(serviceKey)
                .addAnnotatedResource(spec, null, null, null)
                .build();

        var expectedGrant = new FieldUseContributionSpec(
                PolicyFieldSelector.exact(Set.of("attribute.c")), Set.of(FieldUseCategory.VALUE), RuleEffect.ALLOW
        );
        Map<String, Object> expectedBulkScope = Map.of("is_not_null", List.of(Map.of("var", expectedBulkFactPath)));
        for (var bundle : List.of(manual, annotated)) {
            List<AuthorizationPolicyRule> searchRules = bundle.policies().stream()
                    .flatMap(policy -> policy.rules().stream())
                    .filter(rule -> rule.evaluationModes().contains(EvaluationMode.SEARCH))
                    .toList();
            assertThat(searchRules).hasSize(2);
            assertThat(searchRules).anySatisfy(rule ->
                    assertThat(rule.contributions().fieldUse()).containsExactly(expectedGrant));
            assertThat(searchRules).filteredOn(rule -> rule.contributions().dataScope() != null).singleElement()
                    .satisfies(rule -> assertThat(rule.contributions().dataScope().resourceCondition().expression())
                            .isEqualTo(expectedBulkScope));
        }
    }

    static class SampleSetor {
        @Id
        Long id;

        @Column(nullable = false)
        String sigla;
    }

    static class SampleDependente {
        @Id
        Long id;

        String cpfDependente;
    }

    @Entity
    static class SampleProgressaoEntity {
        @Id
        Long id;

        @Column(nullable = false)
        Integer empCodigo;

        @Column(nullable = false)
        Long lotacaoSetorId;

        @Column(nullable = false)
        String sigla;

        String situacaoCandidato;

        BigDecimal valorProposto;

        LocalDate dtini;

        @ManyToOne(optional = false)
        @jakarta.persistence.JoinColumn(name = "setor_id", nullable = false)
        SampleSetor setor;

        @OneToMany
        List<SampleDependente> dependentes;

        @Transient
        Map<String, Object> runtimeScratch;

        @Version
        Long lockVersion;
    }

    static class SampleProgressaoResponseDTO {
        Long id;
        Integer empCodigo;
        Long lotacaoSetorId;
        String sigla;
        String situacaoCandidato;

        @DomainGovernance(preset = DomainGovernancePreset.LGPD_PERSONAL_ID)
        String servidorMatricula;

        @DomainGovernance(preset = DomainGovernancePreset.CONFIDENTIAL_FINANCIAL)
        BigDecimal valorProposto;
    }

    static class SampleProgressaoFilterDTO {
        @Filterable(operation = FilterOperation.EQUAL)
        Integer empCodigo;

        @Filterable(operation = FilterOperation.LIKE, relation = "setor.sigla")
        String setorSigla;

        @Filterable(operation = FilterOperation.EQUAL, relation = "dependentes.cpfDependente")
        String dependenteCpf;
    }

    @ApiResource(
            value = "/api/workforce/processos-progressao",
            resourceKey = "administracao-pessoal.processos-progressao",
            title = "Processos de progressão")
    static class SampleProgressaoController {

        @GetMapping("/{id}/detail")
        @UiSurface(
                id = "detail",
                kind = SurfaceKind.READ_PROJECTION,
                scope = SurfaceScope.ITEM,
                title = "Ficha 360°")
        public SampleProgressaoResponseDTO detail() {
            return null;
        }

        @PatchMapping("/{id}/registrar-avaliacao")
        @UiSurface(
                id = "registrar-avaliacao",
                kind = SurfaceKind.PARTIAL_FORM,
                scope = SurfaceScope.ITEM,
                title = "Avaliação")
        public SampleProgressaoResponseDTO patchAvaliacao() {
            return null;
        }

        @PostMapping("/{id}/actions/homologar-progressao")
        @WorkflowAction(
                id = "homologar-progressao",
                title = "Homologar progressão",
                scope = ActionScope.ITEM)
        public SampleProgressaoResponseDTO homologar() {
            return null;
        }

        @PostMapping("/actions/homologar-progressao-lote")
        @WorkflowAction(
                id = "homologar-progressao-lote",
                title = "Homologar lote",
                scope = ActionScope.COLLECTION)
        public void homologarLote() {
        }

        @GetMapping
        @UiSurface(
                id = "painel-raiz",
                kind = SurfaceKind.VIEW,
                scope = SurfaceScope.COLLECTION,
                title = "Painel raiz")
        public List<SampleProgressaoResponseDTO> painelRaiz() {
            return List.of();
        }
    }

    @Test
    void fromAnnotatedResourceSynthesizesCompleteGovernanceSpecAndCompilesOpaBootstrapBundle() {
        AuthzResourceGovernanceSpec<SampleProgressaoEntity> spec =
                AuthzResourceGovernanceSpec.fromAnnotatedResource(
                        "praxis-workforce-showcase",
                        "empCodigo",
                        SampleProgressaoEntity.class,
                        SampleProgressaoResponseDTO.class,
                        SampleProgressaoFilterDTO.class,
                        SampleProgressaoController.class
                );

        assertThat(spec.resourceKey()).isEqualTo("administracao-pessoal.processos-progressao");
        assertThat(spec.decisionPoint().httpMethod()).isEqualTo("POST");
        assertThat(spec.decisionPoint().canonicalPath()).isEqualTo("/api/workforce/processos-progressao/filter");
        assertThat(spec.technicalConcurrencyPointers()).contains("/version", "/lockVersion");
        assertThat(spec.buildHardScopeParams("1")).containsEntry(AuthzResourceGovernanceSpec.HARD_TENANT_PARAM, 1);

        // Verify scalar, ManyToOne nested, and 1:N collection bindings
        assertThat(spec.queryProjection().fieldsByPath())
                .containsKeys(
                        "resource.empCodigo",
                        "resource.lotacaoSetorId",
                        "resource.sigla",
                        "resource.valorProposto",
                        "resource.dtini",
                        "resource.setor_sigla",
                        "resource.dependentes_cpfDependente"
                )
                .doesNotContainKey("resource.runtimeScratch");

        // Verify @DomainGovernance sensitive facts
        FactDescriptor financialFact = spec.factContract().descriptorsByPath().get("resource.valorProposto");
        assertThat(financialFact).isNotNull();
        assertThat(financialFact.valueType()).isEqualTo(FactValueType.DECIMAL);
        assertThat(financialFact.classification()).isEqualTo("RESTRICTED");
        assertThat(financialFact.isSensitiveOrRestricted()).isTrue();
        assertThat(financialFact.complianceTags()).contains("FINANCIAL_RESTRICTED");

        FactDescriptor personalIdFact = spec.factContract().descriptorsByPath().get("resource.servidorMatricula");
        assertThat(personalIdFact).isNotNull();
        assertThat(personalIdFact.classification()).isEqualTo("RESTRICTED");
        assertThat(personalIdFact.isSensitiveOrRestricted()).isTrue();
        assertThat(personalIdFact.complianceTags()).contains("PII_RESTRICTED");

        // Verify @WorkflowAction (ITEM + COLLECTION) and @UiSurface decision points
        DecisionPointDescriptor itemAction = spec.actionDecisionPoints().get("homologar-progressao");
        assertThat(itemAction).isNotNull();
        assertThat(itemAction.canonicalPath())
                .isEqualTo("/api/workforce/processos-progressao/{id}/actions/homologar-progressao");
        assertThat(itemAction.evaluationModes()).containsExactly(EvaluationMode.TARGET);

        DecisionPointDescriptor bulkAction = spec.actionDecisionPoints().get("homologar-progressao-lote");
        assertThat(bulkAction).isNotNull();
        assertThat(bulkAction.canonicalPath())
                .isEqualTo("/api/workforce/processos-progressao/actions/homologar-progressao-lote");
        assertThat(bulkAction.evaluationModes()).containsExactlyInAnyOrder(EvaluationMode.SEARCH, EvaluationMode.TARGET);
        assertThat(bulkAction.supportedCapabilities()).contains(EnforcementCapability.DATA_SCOPE);

        DecisionPointDescriptor detailSurface = spec.surfaceDecisionPoints().get("detail");
        assertThat(detailSurface).isNotNull();
        assertThat(detailSurface.httpMethod()).isEqualTo("GET");
        assertThat(detailSurface.canonicalPath()).isEqualTo("/api/workforce/processos-progressao/{id}/detail");

        DecisionPointDescriptor patchSurface = spec.surfaceDecisionPoints().get("registrar-avaliacao");
        assertThat(patchSurface).isNotNull();
        assertThat(patchSurface.httpMethod()).isEqualTo("PATCH");
        assertThat(patchSurface.canonicalPath()).isEqualTo("/api/workforce/processos-progressao/{id}/registrar-avaliacao");

        // Empty-subpath @GetMapping resolves cleanly to basePath, and @ManyToOne(optional = false) + @JoinColumn(nullable = false) is non-nullable
        DecisionPointDescriptor rootSurface = spec.surfaceDecisionPoints().get("painel-raiz");
        assertThat(rootSurface).isNotNull();
        assertThat(rootSurface.canonicalPath()).isEqualTo("/api/workforce/processos-progressao");
        assertThat(spec.fieldBindings())
                .filteredOn(binding -> "resource.setor_sigla".equals(binding.fieldPath()))
                .singleElement()
                .satisfies(binding -> assertThat(binding.nullableColumn()).isFalse());
        assertThat(spec.factContract().descriptorsByPath().get("resource.setor_sigla").presenceModel())
                .isEqualTo(org.praxisplatform.authz.contracts.context.FactPresenceModel.ALWAYS_PRESENT);

        // Compile full OPA bundle with organizational scope, item action, bulk action, and surface policies
        AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle bundle =
                AuthzHostPolicyBootstrapBuilder.forService("praxis-workforce-showcase")
                        .addResourceSpec(spec, SampleProgressaoResponseDTO.class, null, null)
                        .addOrganizationalScopePolicy(
                                spec,
                                "rule-org-scope",
                                "resource.lotacaoSetorId",
                                "subject.organizationUnitIds",
                                Map.of(personalIdFact.attributeId(), "***")
                        )
                        .addActionPolicy(
                                spec,
                                "homologar-progressao",
                                "rule-homologar",
                                Map.of("==", List.of(Map.of("var", "resource.situacaoCandidato"), "APTO"))
                        )
                        .addBulkActionPolicy(
                                spec,
                                "homologar-progressao-lote",
                                "rule-homologar-lote",
                                "resource.lotacaoSetorId",
                                "subject.organizationUnitIds",
                                Set.of()
                        )
                        .addSurfacePolicy(
                                spec,
                                "detail",
                                "rule-detail-surface",
                                Map.of("!=", List.of(Map.of("var", "subject.principalId"), "")),
                                Map.of()
                        )
                        .build();

        assertThat(bundle.policies()).hasSize(4);
        assertThat(bundle.admissionRecords()).hasSize(6);

        // Runtime row-level verification with Integer tenantId == 1 and DataScopePlan
        SampleProgressaoEntity entity = new SampleProgressaoEntity();
        entity.id = 27401L;
        entity.empCodigo = 1;
        entity.lotacaoSetorId = 10L;
        entity.situacaoCandidato = "APTO";

        AuthzCallerContext caller = AuthzCallerContext.of(
                "1",
                Map.of("subject.principalId", "gestor-rh", "subject.organizationUnitIds", List.of(10L, 20L))
        );
        String lotacaoAttrId = spec.queryProjection().fieldsByPath().get("resource.lotacaoSetorId").attributeId();
        DataScopePlan allowedPlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-1",
                spec.decisionPoint().identity().pointKey(),
                spec.resourceKey(),
                bundle.bundleArtifact().runtimeRelease().runtimeRevision(),
                bundle.bundleArtifact().runtimeRelease().policySetDigest(),
                spec.factContractDigest(),
                spec.queryProjection().projectionId(),
                spec.queryProjection().projectionDigest(),
                DataScopeOutcome.FILTER,
                PushdownMode.FULL_PUSHDOWN,
                new ComparisonPredicateIr(
                        SearchPredicateOperator.IN,
                        "resource.lotacaoSetorId",
                        lotacaoAttrId,
                        FactValueType.INT64,
                        new LiteralListOperandIr(List.of(10L, 20L)),
                        false
                )
        );
        spec.verifyEntityAccessAllowed(entity, caller, allowedPlan);

        AuthzCallerContext wrongTenantCaller = AuthzCallerContext.of("2", Map.of());
        assertThatThrownBy(() -> spec.verifyEntityAccessAllowed(entity, wrongTenantCaller, allowedPlan))
                .isInstanceOf(SecurityException.class)
                .hasMessageContaining("AUTHZ_HARD_SCOPE_TENANT_MISMATCH");
    }
}
