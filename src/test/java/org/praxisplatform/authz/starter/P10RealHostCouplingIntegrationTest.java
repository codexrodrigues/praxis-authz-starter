package org.praxisplatform.authz.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzAutoConfiguration;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzHostBridgeAutoConfiguration;
import org.praxisplatform.authz.catalog.MethodBindingAdmissionRecord;
import org.praxisplatform.authz.compatibility.HostRuntimePolicyCoordinates;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.context.TemporalContext;
import org.praxisplatform.authz.contracts.datascope.ComparisonPredicateIr;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.DataScopePlan;
import org.praxisplatform.authz.contracts.datascope.FieldRefOperandIr;
import org.praxisplatform.authz.contracts.datascope.LiteralOperandIr;
import org.praxisplatform.authz.contracts.datascope.LogicalPredicateIr;
import org.praxisplatform.authz.contracts.datascope.PushdownMode;
import org.praxisplatform.authz.contracts.datascope.QueryableFieldDescriptor;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateOperator;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry;
import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseViolationException;
import org.praxisplatform.authz.enforcement.writeintent.DtoWriteIntentExtractor;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteViolationException;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.jpa.QueryAdapterFieldBinding;
import org.praxisplatform.authz.enforcement.jpa.RelationTraversalStrategy;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort;
import org.praxisplatform.authz.host.config.OperationalPolicyResolutionBridge;
import org.praxisplatform.authz.host.metadata.AuthzGovernedCollectionExportExecutor;
import org.praxisplatform.authz.host.metadata.AuthzGovernedResourceServiceSupport;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider;
import org.praxisplatform.authz.host.metadata.JpaCriteriaDataScopeTranslator;
import org.praxisplatform.authz.opa.client.OpaAuthorizationProviderAdapter;
import org.praxisplatform.authz.opa.client.OpaClientTransport;
import org.praxisplatform.authz.opa.compiler.RegoV1PolicyCompiler;
import org.praxisplatform.authz.opa.governance.GovernedOpaReleaseCoordinator;
import org.praxisplatform.authz.opa.governance.PolicyCandidateVerificationCorpusCase;
import org.praxisplatform.authz.opa.revision.SameInstanceSearchRevisionGuard;
import org.praxisplatform.authz.outbox.JdbcTransactionalAuditOutbox;
import org.praxisplatform.authz.pilot.AfastamentoAuthzPilotBlueprint;
import org.praxisplatform.authz.pilot.AfastamentoPilotRuntimeHost;
import org.praxisplatform.authz.pilot.AfastamentoPilotRuntimeHost.AfastamentoRecord;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam;
import org.praxisplatform.authz.telemetry.SanitizedAuthorizationTelemetryPublisher;
import org.praxisplatform.config.service.OperationalPolicyResolution;
import org.praxisplatform.config.service.OperationalPolicyTarget;
import org.praxisplatform.uischema.capability.ResourceOperationAvailabilityContext;
import org.praxisplatform.uischema.command.GovernedResourceCommandExecutor;
import org.praxisplatform.uischema.command.ResourceCommandExecutionRequest;
import org.praxisplatform.uischema.command.ResourceCommandExecutionResult;
import org.praxisplatform.uischema.command.ResourceCommandOutcome;
import org.praxisplatform.uischema.command.ResourceCommandResponsePolicy;
import org.praxisplatform.uischema.command.ResourceCommandScope;
import org.praxisplatform.uischema.exporting.CollectionExportField;
import org.praxisplatform.uischema.exporting.CollectionExportFormat;
import org.praxisplatform.uischema.exporting.CollectionExportRequest;
import org.praxisplatform.uischema.exporting.CollectionExportResult;
import org.praxisplatform.uischema.exporting.CollectionExportScope;
import org.praxisplatform.uischema.exporting.CsvCollectionExportEngine;
import org.praxisplatform.uischema.exporting.DefaultCollectionExportExecutor;
import org.praxisplatform.uischema.filter.dto.GenericFilterDTO;
import org.praxisplatform.uischema.service.base.ResourceFilterAccessScope;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * End-to-end integration test suite for {@code Fase P10.1} verifying direct host coupling with
 * {@code praxis-metadata-starter} ({@link ResourceFilterAccessScope}, JPA Criteria SQL execution,
 * {@link DefaultCollectionExportExecutor}, {@link CsvCollectionExportEngine},
 * {@link GovernedResourceCommandExecutor}) and {@code praxis-config-starter}
 * ({@link OperationalPolicyResolution}).
 */
class P10RealHostCouplingIntegrationTest {

    @Entity(name = "AfastamentoHostJpaEntity")
    @Table(name = "ergon_afastamentos_host_p10")
    static class AfastamentoHostJpaEntity {
        @Id
        private Long id;

        @Column(name = "tenant_id", nullable = false)
        private String tenantId;

        @Column(name = "cedente_orgao_id")
        private Long cedenteOrgaoId;

        @Column(name = "cessionario_orgao_id")
        private Long cessionarioOrgaoId;

        @Column(name = "lotacao_setor_id")
        private Long lotacaoSetorId;

        @Column(name = "status_afastamento")
        private String statusAfastamento;

        @Column(name = "substituto_servidor_id")
        private Long substitutoServidorId;

        @Column(name = "cid_codigo")
        private String cidCodigo;

        @OneToMany(mappedBy = "afastamento", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
        private List<DependenteHostJpaEntity> dependentes = new ArrayList<>();

        protected AfastamentoHostJpaEntity() {
        }

        AfastamentoHostJpaEntity(
                Long id,
                String tenantId,
                Long cedenteOrgaoId,
                Long cessionarioOrgaoId,
                Long lotacaoSetorId,
                String statusAfastamento,
                Long substitutoServidorId,
                String cidCodigo
        ) {
            this.id = id;
            this.tenantId = tenantId;
            this.cedenteOrgaoId = cedenteOrgaoId;
            this.cessionarioOrgaoId = cessionarioOrgaoId;
            this.lotacaoSetorId = lotacaoSetorId;
            this.statusAfastamento = statusAfastamento;
            this.substitutoServidorId = substitutoServidorId;
            this.cidCodigo = cidCodigo;
        }

        public Long getId() {
            return id;
        }

        public String getTenantId() {
            return tenantId;
        }

        public Long getCedenteOrgaoId() {
            return cedenteOrgaoId;
        }

        public Long getCessionarioOrgaoId() {
            return cessionarioOrgaoId;
        }

        public Long getLotacaoSetorId() {
            return lotacaoSetorId;
        }

        public String getStatusAfastamento() {
            return statusAfastamento;
        }

        public Long getSubstitutoServidorId() {
            return substitutoServidorId;
        }

        public String getCidCodigo() {
            return cidCodigo;
        }

        public List<DependenteHostJpaEntity> getDependentes() {
            return dependentes;
        }

        AfastamentoRecord toRecord() {
            return new AfastamentoRecord(
                    id, tenantId, cedenteOrgaoId, cessionarioOrgaoId,
                    lotacaoSetorId, statusAfastamento, substitutoServidorId, cidCodigo
            );
        }
    }

    @Entity(name = "DependenteHostJpaEntity")
    @Table(name = "ergon_dependentes_host_p10")
    static class DependenteHostJpaEntity {
        @Id
        private Long id;

        @ManyToOne(fetch = FetchType.LAZY)
        @JoinColumn(name = "afastamento_id")
        private AfastamentoHostJpaEntity afastamento;

        @Column(name = "cpf")
        private String cpf;

        protected DependenteHostJpaEntity() {
        }

        DependenteHostJpaEntity(Long id, AfastamentoHostJpaEntity afastamento, String cpf) {
            this.id = id;
            this.afastamento = afastamento;
            this.cpf = cpf;
        }
    }

    @Test
    void verifyP10RealJpaCriteriaScopePreHydrationMutationExportCommandAndConfigBridge() {
        AfastamentoAuthzPilotBlueprint blueprint = AfastamentoAuthzPilotBlueprint.createErgonAfastamentoBlueprint();

        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:praxis_p10_host_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
                "sa",
                ""
        );
        LocalContainerEntityManagerFactoryBean emfBean = new LocalContainerEntityManagerFactoryBean();
        emfBean.setDataSource(dataSource);
        emfBean.setPackagesToScan(P10RealHostCouplingIntegrationTest.class.getPackageName());
        HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
        vendorAdapter.setGenerateDdl(true);
        emfBean.setJpaVendorAdapter(vendorAdapter);
        emfBean.setJpaPropertyMap(Map.of("hibernate.hbm2ddl.auto", "create-drop"));
        emfBean.afterPropertiesSet();

        var emf = emfBean.getObject();
        assertNotNull(emf);
        JpaTransactionManager txManager = new JpaTransactionManager(emf);
        TransactionTemplate txTemplate = new TransactionTemplate(txManager);
        EntityManager em = SharedEntityManagerCreator.createSharedEntityManager(emf);

        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        JdbcTransactionalAuditOutbox jdbcOutbox = new JdbcTransactionalAuditOutbox(
                jdbcTemplate, "praxis_authz_obligation_outbox", true, true
        );
        SanitizedAuthorizationTelemetryPublisher telemetryPublisher =
                new SanitizedAuthorizationTelemetryPublisher(List.of(), 100);

        OpaAuthorizationProviderAdapter opaAdapter = new OpaAuthorizationProviderAdapter(
                blueprint.localOpaTransport(),
                new SameInstanceSearchRevisionGuard(1)
        );
        DetachedDtoMaskingProcessor maskingProcessor = new DetachedDtoMaskingProcessor();
        MetadataResourceAuthorizationSeam seam = new MetadataResourceAuthorizationSeam(
                opaAdapter,
                new FieldUseQueryGuard(),
                new DtoWriteIntentExtractor(),
                new FieldWriteAuthorizer(),
                maskingProcessor,
                new ObligationBarrierCoordinator(new DefaultObligationHandlerRegistry(), jdbcOutbox),
                telemetryPublisher
        );
        AuthzGovernedResourceServiceSupport serviceSupport =
                new AuthzGovernedResourceServiceSupport(seam, maskingProcessor);

        // Seed 4 JPA entities:
        // - #101: tenant-gov-br, lotacao 100 (IN SCOPE), cid M54.5, 2 dependentes
        // - #102: tenant-gov-br, lotacao 999 (OUT OF POLICY SCOPE), cid F32.0
        // - #103: tenant-gov-br, lotacao NULL (NULLABLE COLUMN), cid J06.9
        // - #104: tenant-outro,  lotacao 100 (OUT OF HARD TENANT SCOPE), cid A09
        txTemplate.executeWithoutResult(status -> {
            AfastamentoHostJpaEntity e101 = new AfastamentoHostJpaEntity(
                    101L, "tenant-gov-br", 1L, 2L, 100L, "DEFERIDO", 5001L, "M54.5");
            e101.getDependentes().add(new DependenteHostJpaEntity(1001L, e101, "11122233344"));
            e101.getDependentes().add(new DependenteHostJpaEntity(1002L, e101, "55566677788"));
            em.persist(e101);
            em.persist(new AfastamentoHostJpaEntity(
                    102L, "tenant-gov-br", 1L, 2L, 999L, "DEFERIDO", 5002L, "F32.0"));
            em.persist(new AfastamentoHostJpaEntity(
                    103L, "tenant-gov-br", 1L, 2L, null, "DEFERIDO", 5003L, "J06.9"));
            em.persist(new AfastamentoHostJpaEntity(
                    104L, "tenant-outro", 1L, 2L, 100L, "DEFERIDO", 5004L, "A09"));
        });

        JpaDataScopeAdapter jpaAdapter = new JpaDataScopeAdapter(
                blueprint.queryProjection(),
                List.of(new QueryAdapterFieldBinding(
                        blueprint.resourceKey(),
                        "resource.lotacaoSetorId",
                        "ergon.afastamentos.lotacao_setor_id",
                        "lotacaoSetorId",
                        RelationTraversalStrategy.INNER_JOIN_SCALAR,
                        true
                ))
        );
        JpaCriteriaDataScopeTranslator criteriaTranslator = new JpaCriteriaDataScopeTranslator(
                blueprint.queryProjection(),
                List.of(new QueryAdapterFieldBinding(
                        blueprint.resourceKey(),
                        "resource.lotacaoSetorId",
                        "ergon.afastamentos.lotacao_setor_id",
                        "lotacaoSetorId",
                        RelationTraversalStrategy.INNER_JOIN_SCALAR,
                        true
                ))
        );

        ResourceFilterAccessScope<AfastamentoHostJpaEntity> tenantHardScope =
                ResourceFilterAccessScope.restricted((root, query, cb) -> cb.equal(root.get("tenantId"), "tenant-gov-br"));

        // 1. Real JPA Criteria SQL Execution via ResourceFilterAccessScope + Detached Masking (P05..P09, P11, P12)
        List<AfastamentoRecord> maskedDtos = txTemplate.execute(status -> {
            ResourceFilterAccessScope<AfastamentoHostJpaEntity> composedScope =
                    serviceSupport.authorizeAndResolveAccessScope(
                            blueprint.decisionPoint(),
                            blueprint.factContract().factContractDigest(),
                            Set.of("Accept"),
                            Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L, 200L)),
                            Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT),
                            Map.of(),
                            List.of(new FieldUseEffectDirective("ergon.afastamentos.cid_codigo", FieldUseCategory.FILTER, RuleEffect.DENY)),
                            jpaAdapter,
                            "e.tenantId = :hardTenantId",
                            Map.of("hardTenantId", "tenant-gov-br"),
                            criteriaTranslator,
                            tenantHardScope
                    );
            assertEquals(ResourceFilterAccessScope.Mode.RESTRICTED, composedScope.mode());

            CriteriaBuilder cb = em.getCriteriaBuilder();
            CriteriaQuery<AfastamentoHostJpaEntity> cq = cb.createQuery(AfastamentoHostJpaEntity.class);
            Root<AfastamentoHostJpaEntity> root = cq.from(AfastamentoHostJpaEntity.class);
            Predicate predicate = composedScope.specification().toPredicate(root, cq, cb);
            cq.where(predicate);
            List<AfastamentoHostJpaEntity> entities = em.createQuery(cq).getResultList();

            // Only #101 matches both tenantId = 'tenant-gov-br' AND lotacaoSetorId IN (100, 200)
            assertEquals(1, entities.size());
            assertEquals(101L, entities.getFirst().getId());
            // Managed entity still holds raw CID in JPA persistence context before detached DTO masking
            assertEquals("M54.5", entities.getFirst().getCidCodigo());

            List<AfastamentoRecord> rawRecords = entities.stream().map(AfastamentoHostJpaEntity::toRecord).toList();
            List<AfastamentoRecord> masked = serviceSupport.maskQueryResponseDtos(
                    rawRecords,
                    AfastamentoRecord.class,
                    AfastamentoPilotRuntimeHost.defaultFieldSchemas()
            );
            // Verify managed entity was NOT mutated in JPA persistence context (P12)
            assertEquals("M54.5", entities.getFirst().getCidCodigo());
            return masked;
        });
        assertNotNull(maskedDtos);
        assertEquals(1, maskedDtos.size());
        assertEquals("***CID-RESTRITO***", maskedDtos.getFirst().cidCodigo());

        // 1b. Verify Kleene 3VL null-safety (NOT(lotacaoSetorId == 999) excludes NULL row #103!) and 1:N correlated EXISTS subquery in JPA Criteria (P06, P07)
        QueryableFieldDescriptor lotacaoDesc = new QueryableFieldDescriptor(
                "resource.lotacaoSetorId", "ergon.afastamentos.lotacao_setor_id", FactValueType.INT64,
                Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.IN), true);
        QueryableFieldDescriptor depCpfDesc = new QueryableFieldDescriptor(
                "resource.dependenteCpf", "ergon.dependentes.cpf", FactValueType.STRING,
                Set.of(SearchPredicateOperator.EQ), false);
        QueryableResourceProjection extProjection = new QueryableResourceProjection(
                QueryableResourceProjection.SCHEMA_VERSION_V1,
                "qp-ext",
                blueprint.resourceKey(),
                blueprint.queryProjection().projectionDigest(),
                Map.of("resource.lotacaoSetorId", lotacaoDesc, "resource.dependenteCpf", depCpfDesc)
        );
        JpaCriteriaDataScopeTranslator extTranslator = new JpaCriteriaDataScopeTranslator(
                extProjection,
                List.of(
                        new QueryAdapterFieldBinding(
                                blueprint.resourceKey(), "resource.lotacaoSetorId",
                                "ergon.afastamentos.lotacao_setor_id", "lotacaoSetorId",
                                RelationTraversalStrategy.INNER_JOIN_SCALAR, true),
                        new QueryAdapterFieldBinding(
                                blueprint.resourceKey(), "resource.dependenteCpf",
                                "ergon.dependentes.cpf", "dependentes.cpf",
                                RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY, false)
                )
        );
        DataScopePlan kleeneAndSubqueryPlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-kleene-sub",
                blueprint.decisionPoint().identity().pointKey(),
                blueprint.resourceKey(),
                "rev-1",
                blueprint.queryProjection().projectionDigest(),
                blueprint.queryProjection().projectionDigest(),
                extProjection.projectionId(),
                extProjection.projectionDigest(),
                DataScopeOutcome.FILTER,
                PushdownMode.FULL_PUSHDOWN,
                new LogicalPredicateIr(
                        SearchPredicateOperator.AND,
                        List.of(
                                new LogicalPredicateIr(
                                        SearchPredicateOperator.NOT,
                                        List.of(new ComparisonPredicateIr(
                                                SearchPredicateOperator.EQ,
                                                "resource.lotacaoSetorId",
                                                "ergon.afastamentos.lotacao_setor_id",
                                                FactValueType.INT64,
                                                new LiteralOperandIr(999L),
                                                false
                                        ))
                                ),
                                new ComparisonPredicateIr(
                                        SearchPredicateOperator.EQ,
                                        "resource.dependenteCpf",
                                        "ergon.dependentes.cpf",
                                        FactValueType.STRING,
                                        new LiteralOperandIr("11122233344"),
                                        false
                                )
                        )
                )
        );
        List<AfastamentoHostJpaEntity> kleeneRows = txTemplate.execute(status -> {
            ResourceFilterAccessScope<AfastamentoHostJpaEntity> scope =
                    extTranslator.toResourceFilterAccessScope(kleeneAndSubqueryPlan, tenantHardScope);
            CriteriaBuilder cb = em.getCriteriaBuilder();
            CriteriaQuery<AfastamentoHostJpaEntity> cq = cb.createQuery(AfastamentoHostJpaEntity.class);
            Root<AfastamentoHostJpaEntity> root = cq.from(AfastamentoHostJpaEntity.class);
            cq.where(scope.specification().toPredicate(root, cq, cb));
            return em.createQuery(cq).getResultList();
        });
        assertNotNull(kleeneRows);
        // Row #103 (lotacaoSetorId = NULL) and Row #102 (lotacaoSetorId = 999) are excluded; #101 is returned once without 1:N row multiplication!
        assertEquals(1, kleeneRows.size());
        assertEquals(101L, kleeneRows.getFirst().getId());

        // 1c. FieldUseQueryGuard blocks FILTER inference on cidCodigo (P08, P50)
        assertThrows(FieldUseViolationException.class, () ->
                serviceSupport.authorizeAndResolveAccessScope(
                        blueprint.decisionPoint(),
                        blueprint.factContract().factContractDigest(),
                        Set.of("Accept"),
                        Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L)),
                        Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT),
                        Map.of(FieldUseCategory.FILTER, Set.of("ergon.afastamentos.cid_codigo")),
                        List.of(new FieldUseEffectDirective("ergon.afastamentos.cid_codigo", FieldUseCategory.FILTER, RuleEffect.DENY)),
                        jpaAdapter,
                        "e.tenantId = :hardTenantId",
                        Map.of("hardTenantId", "tenant-gov-br"),
                        criteriaTranslator,
                        tenantHardScope
                )
        );

        // 2. Pre-Hydration Mutation (R-11: STEP_11 before STEP_12) + DualScopeDelegation + JdbcTransactionalAuditOutbox (P13, P14, P19, P22)
        Map<String, String> wireMap = Map.of(
                "/lotacaoSetorId", "ergon.afastamentos.lotacao_setor_id",
                "/statusAfastamento", "ergon.afastamentos.status_afastamento",
                "/substitutoServidorId", "ergon.afastamentos.substituto_servidor_id",
                "/cidCodigo", "ergon.afastamentos.cid_codigo"
        );
        AtomicBoolean step12HydrationOrRulesExecuted = new AtomicBoolean(false);
        assertThrows(FieldWriteViolationException.class, () -> {
            serviceSupport.authorizeBeforeHydrationAndRules(
                    blueprint.decisionPoint(),
                    blueprint.factContract().factContractDigest(),
                    "PATCH",
                    true,
                    Map.of("statusAfastamento", "REVOGADO"),
                    wireMap,
                    Set.of("/version"),
                    Set.of("ergon.afastamentos.lotacao_setor_id"),
                    blueprint.dualScopeSpec(),
                    false, // callerMatchesCedente = false
                    true,  // callerMatchesCessionario = true (cannot write Cedente field statusAfastamento!)
                    Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L), "resource.lotacaoSetorId", 100L),
                    Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT, "resource.lotacaoSetorId", FactResolutionStatus.PRESENT)
            );
            step12HydrationOrRulesExecuted.set(true);
        });
        assertFalse(step12HydrationOrRulesExecuted.get(), "STEP_12 (hydrate* / PraxisRulesEngine) must NEVER execute when STEP_11 fails");

        // Authorized Cessionário mutation on substitutoServidorId inside SQL transaction commits outbox and masks response
        AfastamentoRecord updatedMasked = txTemplate.execute(status -> {
            serviceSupport.authorizeBeforeHydrationAndRules(
                    blueprint.decisionPoint(),
                    blueprint.factContract().factContractDigest(),
                    "PATCH",
                    true,
                    Map.of("substitutoServidorId", 8888L),
                    wireMap,
                    Set.of("/version"),
                    Set.of("ergon.afastamentos.lotacao_setor_id"),
                    blueprint.dualScopeSpec(),
                    false,
                    true,
                    Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L), "resource.lotacaoSetorId", 100L),
                    Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT, "resource.lotacaoSetorId", FactResolutionStatus.PRESENT)
            );
            AfastamentoHostJpaEntity managed = em.find(AfastamentoHostJpaEntity.class, 101L);
            managed.substitutoServidorId = 8888L;
            em.flush();
            return serviceSupport.completePostMutationOutboxAndMask(
                    managed.toRecord(),
                    AfastamentoRecord.class,
                    AfastamentoPilotRuntimeHost.defaultFieldSchemas()
            );
        });
        assertNotNull(updatedMasked);
        assertEquals(8888L, updatedMasked.substitutoServidorId());
        assertEquals("***CID-RESTRITO***", updatedMasked.cidCodigo());
        assertEquals(1, jdbcOutbox.listCommittedEntries().size());

        // 3. Real Collection Export via DefaultCollectionExportExecutor + CsvCollectionExportEngine + AuthzGovernedCollectionExportExecutor (P16)
        DefaultCollectionExportExecutor baseExportExecutor = new DefaultCollectionExportExecutor(
                List.of(new CsvCollectionExportEngine())
        );
        AuthzGovernedCollectionExportExecutor governedExportExecutor = new AuthzGovernedCollectionExportExecutor(
                baseExportExecutor,
                maskingProcessor,
                AfastamentoPilotRuntimeHost.defaultFieldSchemas(),
                Set.of("cedenteOrgaoId"), // simulate @DomainGovernance(exportable = false) on cedenteOrgaoId
                List.of(new MaskDirective(
                        "ergon.afastamentos.cid_codigo",
                        "REDACT_CONSTANT",
                        Map.of("replacement", "***CID-RESTRITO***")
                ))
        );
        List<CollectionExportField> exportFields = List.of(
                new CollectionExportField("id", "ID", true, true, "number", "id"),
                new CollectionExportField("cedenteOrgaoId", "Órgão Cedente", true, true, "number", "cedenteOrgaoId"),
                new CollectionExportField("lotacaoSetorId", "Setor Lotação", true, true, "number", "lotacaoSetorId"),
                new CollectionExportField("cidCodigo", "CID Médico", true, true, "text", "cidCodigo")
        );
        CollectionExportRequest<GenericFilterDTO> exportReq = new CollectionExportRequest<>(
                "table", "tbl-afastamentos", "/api/human-resources/afastamentos",
                CollectionExportFormat.CSV, CollectionExportScope.ALL,
                null, null, null, null, null, null, true, false, 100, "afastamentos.csv", null, null, Map.of()
        );
        CollectionExportResult csvResult = governedExportExecutor.export(
                exportReq,
                List.of(new AfastamentoRecord(101L, "tenant-gov-br", 1L, 2L, 100L, "DEFERIDO", 8888L, "M54.5")),
                exportFields,
                (row, field) -> switch (field.key()) {
                    case "id" -> row.id();
                    case "cedenteOrgaoId" -> row.orgCedenteId();
                    case "lotacaoSetorId" -> row.lotacaoSetorId();
                    case "cidCodigo" -> row.cidCodigo();
                    default -> null;
                },
                Map.of()
        );
        String csvText = new String(csvResult.content(), StandardCharsets.UTF_8);
        assertTrue(csvText.contains("***CID-RESTRITO***"), "Exported CSV must redact cidCodigo via MaskDirective");
        assertFalse(csvText.contains("M54.5"), "Exported CSV must never leak raw CID M54.5");
        assertFalse(csvText.contains("Órgão Cedente"), "Exported CSV must strip non-exportable column cedenteOrgaoId");
        assertEquals(Boolean.TRUE, csvResult.metadata().get("authzExportSanitized"));

        // 4. Real GovernedResourceCommandExecutor + AuthzResourceOperationAvailabilityProvider (P02)
        AuthzResourceOperationAvailabilityProvider availabilityProvider = new AuthzResourceOperationAvailabilityProvider(
                seam,
                ctx -> blueprint.decisionPoint().identity().pointKey(),
                ctx -> !"DENIED_ITEM".equals(ctx.resourceId()),
                () -> blueprint.bundleArtifact().runtimeHead().runtimeRevision()
        );
        GovernedResourceCommandExecutor commandExecutor = new GovernedResourceCommandExecutor(
                req -> ResourceCommandExecutionResult.success(
                        req,
                        req.resourceId(),
                        Map.of("id", req.resourceId(), "status", "HOMOLOGADO"),
                        Map.of("policySetDigest", blueprint.bundleArtifact().runtimeRelease().policySetDigest())
                ),
                availabilityProvider,
                null
        );
        ResourceCommandExecutionRequest allowedCmd = ResourceCommandExecutionRequest.item(
                blueprint.resourceKey(),
                "/api/human-resources/afastamentos",
                "homologar",
                101L,
                Map.of(),
                ResourceCommandResponsePolicy.READ_AFTER_WRITE
        );
        ResourceCommandExecutionResult allowedCmdResult = commandExecutor.execute(allowedCmd);
        assertEquals(ResourceCommandOutcome.SUCCESS, allowedCmdResult.outcome());

        ResourceCommandExecutionRequest deniedCmd = new ResourceCommandExecutionRequest(
                blueprint.resourceKey(),
                "/api/human-resources/afastamentos",
                "homologar",
                ResourceCommandScope.ITEM,
                "DENIED_ITEM",
                Map.of(),
                ResourceCommandResponsePolicy.READ_AFTER_WRITE,
                Map.of("supported", true)
        );
        ResourceCommandExecutionResult deniedCmdResult = commandExecutor.execute(deniedCmd);
        assertEquals(ResourceCommandOutcome.PERMISSION_DENIED, deniedCmdResult.outcome());
        assertEquals(1, deniedCmdResult.messages().size());
        assertEquals("PERMISSION_DENIED", deniedCmdResult.messages().get(0).code());

        var directDecision = availabilityProvider.evaluate(
                ResourceOperationAvailabilityContext.item(blueprint.resourceKey(), "/api/human-resources/afastamentos", "homologar", 101L)
        );
        assertTrue(directDecision.allowed());
        assertEquals(Boolean.TRUE, directDecision.metadata().get("advisoryOnly"));
        assertEquals(Boolean.TRUE, directDecision.metadata().get("requiresRuntimeRevalidation"));

        // 5. Real OperationalPolicyResolutionBridge with praxis-config-starter's OperationalPolicyResolution (P18, P28, P53, P55, P63)
        RegoV1PolicyCompiler compiler = new RegoV1PolicyCompiler();
        OperationalPolicyResolutionBridge configBridge = new OperationalPolicyResolutionBridge(
                new ConfigMaterializationToOpaReconciler(compiler, new GovernedOpaReleaseCoordinator())
        );
        String expectedFp = compiler.compileUnit(
                blueprint.policyDefinition(),
                Map.of(blueprint.decisionPoint().identity().pointKey(), blueprint.decisionPoint()),
                Map.of(blueprint.factContract().factContractId(), blueprint.factContract()),
                Map.of(blueprint.queryProjection().projectionId(), blueprint.queryProjection())
        ).unitManifest().digestChain().definitionFingerprint();

        ObjectNode payloadNode = new ObjectMapper().createObjectNode();
        payloadNode.put("policyId", blueprint.policyDefinition().policyId());
        OperationalPolicyTarget configTarget = new OperationalPolicyTarget(
                "workflow_action", "resource-workflow-action", "human-resources.afastamentos:homologar"
        );
        OperationalPolicyResolution appliedResolution = new OperationalPolicyResolution(
                OperationalPolicyResolution.State.ELIGIBLE_APPLIED_HEAD,
                configTarget,
                expectedFp,
                new OperationalPolicyResolution.Policy(
                        UUID.randomUUID(),
                        UUID.randomUUID(),
                        1,
                        expectedFp,
                        OperationalPolicyResolution.Effect.ALLOW,
                        payloadNode
                ),
                Instant.now()
        );
        List<PolicyCandidateVerificationCorpusCase> corpus = List.of(
                new PolicyCandidateVerificationCorpusCase(
                        "case-pos", "Manager gets FILTER scope",
                        EvaluationMode.SEARCH,
                        new ProviderInputProjection(
                                ProviderInputProjection.SCHEMA_VERSION_V1,
                                blueprint.decisionPoint().identity().pointKey(),
                                "SEARCH",
                                blueprint.factContract().factContractDigest(),
                                new TemporalContext(Instant.now(), ZoneOffset.UTC),
                                Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L)),
                                Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT),
                                Set.of()
                        ),
                        null,
                        GateOutcome.ALLOW,
                        "ALLOW_LOTACAO_GESTOR",
                        DataScopeOutcome.FILTER
                ),
                new PolicyCandidateVerificationCorpusCase(
                        "case-neg", "Unauthorized intruder gets NOT_APPLICABLE / NONE",
                        EvaluationMode.SEARCH,
                        new ProviderInputProjection(
                                ProviderInputProjection.SCHEMA_VERSION_V1,
                                blueprint.decisionPoint().identity().pointKey(),
                                "SEARCH",
                                blueprint.factContract().factContractDigest(),
                                new TemporalContext(Instant.now(), ZoneOffset.UTC),
                                Map.of("subject.principalId", "usr-intruso-999", "subject.organizationUnitIds", List.of(999L)),
                                Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT),
                                Set.of()
                        ),
                        null,
                        GateOutcome.NOT_APPLICABLE,
                        null,
                        DataScopeOutcome.NONE
                )
        );
        String unitKey = "unit:pol-praxis-ergon-showcase-human-resources-afastamentos:v1";
        var reconcileOutcome = configBridge.reconcileFromOperationalResolution(
                "tenant-gov-br",
                "prod",
                appliedResolution,
                unitKey,
                "usr-author-1",
                "usr-approver-2",
                "usr-operator-1",
                Set.of(GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY),
                "opa-1",
                blueprint.bundleArtifact().runtimeHead().opaCapabilitiesDigest(),
                blueprint.policyDefinition(),
                corpus,
                Map.of(blueprint.decisionPoint().identity().pointKey(), blueprint.decisionPoint()),
                Map.of(blueprint.factContract().factContractId(), blueprint.factContract()),
                Map.of(blueprint.queryProjection().projectionId(), blueprint.queryProjection())
        );
        assertTrue(reconcileOutcome.bundleActivated());
        assertTrue(configBridge.reconciler().findActiveHead("tenant-gov-br", "prod", unitKey).isPresent());

        OperationalPolicyResolution withdrawnResolution = new OperationalPolicyResolution(
                OperationalPolicyResolution.State.PREVIOUSLY_APPLIED_WITHOUT_ELIGIBLE_HEAD,
                configTarget,
                expectedFp,
                null,
                Instant.now()
        );
        var withdrawOutcome = configBridge.reconcileFromOperationalResolution(
                "tenant-gov-br",
                "prod",
                withdrawnResolution,
                unitKey,
                "usr-author-1",
                "usr-approver-2",
                "usr-operator-1",
                Set.of(GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY),
                "opa-1",
                blueprint.bundleArtifact().runtimeHead().opaCapabilitiesDigest(),
                null,
                List.of(),
                Map.of(blueprint.decisionPoint().identity().pointKey(), blueprint.decisionPoint()),
                Map.of(blueprint.factContract().factContractId(), blueprint.factContract()),
                Map.of(blueprint.queryProjection().projectionId(), blueprint.queryProjection())
        );
        assertFalse(withdrawOutcome.bundleActivated());
        assertTrue(withdrawOutcome.previousHeadWithdrawn());
        assertTrue(configBridge.reconciler().findActiveHead("tenant-gov-br", "prod", unitKey).isEmpty());

        // 6. Verify PraxisAuthzHostBridgeAutoConfiguration registers both bridge beans automatically
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        PraxisAuthzAutoConfiguration.class,
                        PraxisAuthzHostBridgeAutoConfiguration.class
                ))
                .withBean(OpaClientTransport.class, blueprint::localOpaTransport)
                .withBean(HostRuntimePolicyCoordinates.class, blueprint::coordinates)
                .withBean(MethodBindingAdmissionRecord.class, () -> blueprint.admissionRecords().getFirst())
                .run(context -> {
                    assertNotNull(context.getBean(AuthzGovernedResourceServiceSupport.class));
                    assertNotNull(context.getBean(OperationalPolicyResolutionBridge.class));
                });

        // 7. Critical Review Regression Proofs (P10.1-R01 .. P10.1-R04)
        // P10.1-R01: FieldRefOperandIr column-to-column comparison + LIKE wildcard escaping in JpaCriteriaDataScopeTranslator
        QueryableFieldDescriptor cedenteDesc = new QueryableFieldDescriptor(
                "resource.cedenteOrgaoId",
                "ergon.afastamentos.cedente_orgao_id",
                FactValueType.INT64,
                Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.NE),
                true
        );
        QueryableFieldDescriptor cessionarioDesc = new QueryableFieldDescriptor(
                "resource.cessionarioOrgaoId",
                "ergon.afastamentos.cessionario_orgao_id",
                FactValueType.INT64,
                Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.NE),
                true
        );
        QueryableFieldDescriptor statusDesc = new QueryableFieldDescriptor(
                "resource.statusAfastamento",
                "ergon.afastamentos.status_afastamento",
                FactValueType.STRING,
                Set.of(SearchPredicateOperator.TEXT_CONTAINS),
                false
        );
        QueryableResourceProjection fieldRefProj = new QueryableResourceProjection(
                QueryableResourceProjection.SCHEMA_VERSION_V1,
                "qp-fieldref-like",
                blueprint.resourceKey(),
                blueprint.queryProjection().projectionDigest(),
                Map.of(
                        "resource.cedenteOrgaoId", cedenteDesc,
                        "resource.cessionarioOrgaoId", cessionarioDesc,
                        "resource.statusAfastamento", statusDesc
                )
        );
        JpaCriteriaDataScopeTranslator fieldRefTranslator = new JpaCriteriaDataScopeTranslator(
                fieldRefProj,
                List.of(
                        new QueryAdapterFieldBinding(
                                blueprint.resourceKey(), "resource.cedenteOrgaoId", "ergon.afastamentos.cedente_orgao_id",
                                "cedenteOrgaoId", RelationTraversalStrategy.INNER_JOIN_SCALAR, true),
                        new QueryAdapterFieldBinding(
                                blueprint.resourceKey(), "resource.cessionarioOrgaoId", "ergon.afastamentos.cessionario_orgao_id",
                                "cessionarioOrgaoId", RelationTraversalStrategy.INNER_JOIN_SCALAR, true),
                        new QueryAdapterFieldBinding(
                                blueprint.resourceKey(), "resource.statusAfastamento", "ergon.afastamentos.status_afastamento",
                                "statusAfastamento", RelationTraversalStrategy.INNER_JOIN_SCALAR, true)
                )
        );
        // Column-to-column NE (cedenteOrgaoId != cessionarioOrgaoId) matches rows #101, #102, #103 in tenant-gov-br
        DataScopePlan colNePlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-col-ne",
                blueprint.decisionPoint().identity().pointKey(),
                blueprint.resourceKey(),
                "rev-1",
                blueprint.queryProjection().projectionDigest(),
                blueprint.queryProjection().projectionDigest(),
                fieldRefProj.projectionId(),
                fieldRefProj.projectionDigest(),
                DataScopeOutcome.FILTER,
                PushdownMode.FULL_PUSHDOWN,
                new ComparisonPredicateIr(
                        SearchPredicateOperator.NE,
                        "resource.cedenteOrgaoId",
                        "ergon.afastamentos.cedente_orgao_id",
                        FactValueType.INT64,
                        new FieldRefOperandIr("resource.cessionarioOrgaoId", "ergon.afastamentos.cessionario_orgao_id"),
                        false
                )
        );
        List<AfastamentoHostJpaEntity> colNeRows = txTemplate.execute(status -> {
            ResourceFilterAccessScope<AfastamentoHostJpaEntity> s =
                    fieldRefTranslator.toResourceFilterAccessScope(colNePlan, tenantHardScope);
            CriteriaBuilder cb = em.getCriteriaBuilder();
            CriteriaQuery<AfastamentoHostJpaEntity> cq = cb.createQuery(AfastamentoHostJpaEntity.class);
            Root<AfastamentoHostJpaEntity> root = cq.from(AfastamentoHostJpaEntity.class);
            cq.select(root).where(s.specification().toPredicate(root, cq, cb));
            return em.createQuery(cq).getResultList();
        });
        assertNotNull(colNeRows);
        assertEquals(3, colNeRows.size());

        // Wildcard '%' in TEXT_CONTAINS literal must be escaped and NOT match "DEFERIDO"
        DataScopePlan wildcardLikePlan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-wildcard-like",
                blueprint.decisionPoint().identity().pointKey(),
                blueprint.resourceKey(),
                "rev-1",
                blueprint.queryProjection().projectionDigest(),
                blueprint.queryProjection().projectionDigest(),
                fieldRefProj.projectionId(),
                fieldRefProj.projectionDigest(),
                DataScopeOutcome.FILTER,
                PushdownMode.FULL_PUSHDOWN,
                new ComparisonPredicateIr(
                        SearchPredicateOperator.TEXT_CONTAINS,
                        "resource.statusAfastamento",
                        "ergon.afastamentos.status_afastamento",
                        FactValueType.STRING,
                        new LiteralOperandIr("%"),
                        false
                )
        );
        List<AfastamentoHostJpaEntity> wildcardRows = txTemplate.execute(status -> {
            ResourceFilterAccessScope<AfastamentoHostJpaEntity> s =
                    fieldRefTranslator.toResourceFilterAccessScope(wildcardLikePlan, tenantHardScope);
            CriteriaBuilder cb = em.getCriteriaBuilder();
            CriteriaQuery<AfastamentoHostJpaEntity> cq = cb.createQuery(AfastamentoHostJpaEntity.class);
            Root<AfastamentoHostJpaEntity> root = cq.from(AfastamentoHostJpaEntity.class);
            cq.select(root).where(s.specification().toPredicate(root, cq, cb));
            return em.createQuery(cq).getResultList();
        });
        assertNotNull(wildcardRows);
        assertTrue(wildcardRows.isEmpty(), "Escaped '%' literal in TEXT_CONTAINS must not match rows without literal '%'");

        // P10.1-R02: Calling maskQueryResponseDtos without an active AuthorizedQueryScopeContext fails closed
        assertThrows(IllegalStateException.class, () ->
                serviceSupport.maskQueryResponseDtos(
                        List.of(new AfastamentoRecord(101L, "tenant-gov-br", 1L, 2L, 100L, "DEFERIDO", 8888L, "M54.5")),
                        AfastamentoRecord.class,
                        AfastamentoPilotRuntimeHost.defaultFieldSchemas()
                )
        );

        // P10.1-R03: OMIT in AuthzGovernedCollectionExportExecutor never falls back to raw unmasked row
        AuthzGovernedCollectionExportExecutor omitExportExecutor = new AuthzGovernedCollectionExportExecutor(
                baseExportExecutor,
                maskingProcessor,
                AfastamentoPilotRuntimeHost.defaultFieldSchemas(),
                Set.of("cedenteOrgaoId"),
                List.of(new MaskDirective("ergon.afastamentos.cid_codigo", "OMIT", Map.of()))
        );
        CollectionExportResult omitCsvResult = omitExportExecutor.export(
                exportReq,
                List.of(new AfastamentoRecord(101L, "tenant-gov-br", 1L, 2L, 100L, "DEFERIDO", 8888L, "M54.5")),
                List.of(
                        new CollectionExportField("id", "ID", true, true, "number", "id"),
                        new CollectionExportField("aliasCedente", "Alias Cedente", true, true, "number", "cedenteOrgaoId"),
                        new CollectionExportField("cidCodigo", "CID Médico", true, true, "text", "cidCodigo")
                ),
                (row, field) -> "M54.5-RAW-LEAK",
                Map.of()
        );
        String omitCsvText = new String(omitCsvResult.content(), StandardCharsets.UTF_8);
        assertFalse(omitCsvText.contains("M54.5"), "OMIT_FIELD must not fall back to raw valueResolver");
        assertFalse(omitCsvText.contains("Alias Cedente"), "Non-exportable valuePath must be stripped even when key is aliased");

        // P10.1-R04: Unmapped pointKey or null runtimeRevision fails closed in AuthzResourceOperationAvailabilityProvider
        AuthzResourceOperationAvailabilityProvider unmappedProvider = new AuthzResourceOperationAvailabilityProvider(
                seam, ctx -> "", ctx -> true, () -> "rev-1"
        );
        var unmappedDecision = unmappedProvider.evaluate(
                ResourceOperationAvailabilityContext.item(blueprint.resourceKey(), "/api/human-resources/afastamentos", "homologar", 101L)
        );
        assertFalse(unmappedDecision.allowed());
        assertEquals("AUTHZ_DECISION_POINT_UNMAPPED", unmappedDecision.reason());

        AuthzResourceOperationAvailabilityProvider nullRevisionProvider = new AuthzResourceOperationAvailabilityProvider(
                seam, ctx -> blueprint.decisionPoint().identity().pointKey(), ctx -> true, () -> null
        );
        var nullRevDecision = nullRevisionProvider.evaluate(
                ResourceOperationAvailabilityContext.item(blueprint.resourceKey(), "/api/human-resources/afastamentos", "homologar", 101L)
        );
        assertFalse(nullRevDecision.allowed());
        assertEquals("AUTHZ_REVISION_UNAVAILABLE", nullRevDecision.reason());

        emfBean.destroy();
    }
}
