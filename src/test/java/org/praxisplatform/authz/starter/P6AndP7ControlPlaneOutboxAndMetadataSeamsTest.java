package org.praxisplatform.authz.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode;
import org.praxisplatform.authz.contracts.binding.TransactionCardinality;
import org.praxisplatform.authz.contracts.binding.WriteChangeKind;
import org.praxisplatform.authz.contracts.binding.WriteFieldChange;
import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.context.TemporalContext;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.EnforcementDisposition;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry;
import org.praxisplatform.authz.contracts.obligation.ObligationFulfillmentBarrier;
import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler;
import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler.ConfigRuleMaterializationSnapshot;
import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler.MaterializationResolutionState;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseViolationException;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.jpa.QueryAdapterFieldBinding;
import org.praxisplatform.authz.enforcement.jpa.RelationTraversalStrategy;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.writeintent.DtoWriteIntentExtractor;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteViolationException;
import org.praxisplatform.authz.opa.client.OpaAuthorizationProviderAdapter;
import org.praxisplatform.authz.opa.compiler.RegoV1PolicyCompiler;
import org.praxisplatform.authz.opa.governance.GovernedOpaReleaseCoordinator;
import org.praxisplatform.authz.opa.governance.PolicyCandidateVerificationCorpusCase;
import org.praxisplatform.authz.opa.revision.SameInstanceSearchRevisionGuard;
import org.praxisplatform.authz.outbox.JdbcTransactionalAuditOutbox;
import org.praxisplatform.authz.pilot.AfastamentoAuthzPilotBlueprint;
import org.praxisplatform.authz.pilot.AfastamentoPilotRuntimeHost;
import org.praxisplatform.authz.pilot.AfastamentoPilotRuntimeHost.AfastamentoRecord;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.AdvisoryOperationAvailability;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.AuthorizedPreMutationContext;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.AuthorizedQueryScopeContext;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.WorkerDelegationToken;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Verifies Phase {@code P6} (Control Plane {@code DomainRuleMaterialization} -> OPA Reconciler and
 * Durable SQL {@link JdbcTransactionalAuditOutbox}) and Phase {@code P7}
 * ({@link MetadataResourceAuthorizationSeam} for Query, Pre-Hydration Mutation, Durable Bulk Worker,
 * and Advisory HATEOAS Discovery).
 */
class P6AndP7ControlPlaneOutboxAndMetadataSeamsTest {

    @Test
    void verifyP6JdbcTransactionalAuditOutboxAndRollbackAtomicity() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:praxis_authz_outbox_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
                "sa",
                ""
        );
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        DataSourceTransactionManager txManager = new DataSourceTransactionManager(dataSource);
        TransactionTemplate txTemplate = new TransactionTemplate(txManager);

        JdbcTransactionalAuditOutbox jdbcOutbox = new JdbcTransactionalAuditOutbox(
                jdbcTemplate,
                "praxis_authz_obligation_outbox",
                true,
                true // requireActiveTransaction = true
        );
        ObligationBarrierCoordinator barrierCoordinator = new ObligationBarrierCoordinator(
                new DefaultObligationHandlerRegistry(),
                jdbcOutbox
        );
        List<ObligationDirective> auditObligations = List.of(new ObligationDirective(
                "DURABLE_AUDIT_EVIDENCE",
                "ON_PERMIT",
                "BEFORE_COMMIT_OUTBOX",
                Map.of("auditCategory", "SENSITIVE_HEALTH_ACCESS", "idempotencyEntryId", "outbox-entry-1")
        ));

        // 1. Outside an active transaction, BEFORE_COMMIT_OUTBOX fails closed and marks obligation unfulfilled (P19)
        var outsideTxResults = barrierCoordinator.fulfillAtBarrier(
                "resource-operation:praxis-ergon-showcase:human-resources.afastamentos:filter",
                "rev-2026-11-09-01",
                EnforcementDisposition.PERMIT,
                ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX,
                auditObligations,
                Map.of("principalId", "usr-gestor-101")
        );
        assertEquals(1, outsideTxResults.size());
        assertFalse(outsideTxResults.getFirst().fulfilled());
        assertTrue(jdbcOutbox.listCommittedEntries().isEmpty());

        // 2. Inside an active transaction that commits, the outbox record is durably persisted
        var committedResults = txTemplate.execute(status ->
                barrierCoordinator.fulfillAtBarrier(
                        "resource-operation:praxis-ergon-showcase:human-resources.afastamentos:filter",
                        "rev-2026-11-09-01",
                        EnforcementDisposition.PERMIT,
                        ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX,
                        auditObligations,
                        Map.of("principalId", "usr-gestor-101")
                )
        );
        assertNotNull(committedResults);
        assertTrue(committedResults.getFirst().fulfilled());
        assertEquals(1, jdbcOutbox.listCommittedEntries().size());
        assertEquals("outbox-entry-1", jdbcOutbox.listCommittedEntries().getFirst().entryId());

        // 3. Inside a transaction that rolls back after writing to the outbox, the outbox row is rolled back atomically!
        List<ObligationDirective> rollbackObligations = List.of(new ObligationDirective(
                "DURABLE_AUDIT_EVIDENCE",
                "ON_PERMIT",
                "BEFORE_COMMIT_OUTBOX",
                Map.of("auditCategory", "ROLLBACK_TEST", "idempotencyEntryId", "outbox-entry-rollback")
        ));
        assertThrows(RuntimeException.class, () ->
                txTemplate.execute(status -> {
                    var res = barrierCoordinator.fulfillAtBarrier(
                            "resource-operation:praxis-ergon-showcase:human-resources.afastamentos:filter",
                            "rev-2026-11-09-01",
                            EnforcementDisposition.PERMIT,
                            ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX,
                            rollbackObligations,
                            Map.of()
                    );
                    assertTrue(res.getFirst().fulfilled());
                    throw new RuntimeException("Simulated downstream commit failure");
                })
        );
        // Only the first committed entry remains!
        assertEquals(1, jdbcOutbox.listCommittedEntries().size());

        // 4. Inside a read-only transaction, BEFORE_COMMIT_OUTBOX fails closed and rejects write (P67-R01 / P19)
        TransactionTemplate readOnlyTxTemplate = new TransactionTemplate(txManager);
        readOnlyTxTemplate.setReadOnly(true);
        var readOnlyResults = readOnlyTxTemplate.execute(status ->
                barrierCoordinator.fulfillAtBarrier(
                        "resource-operation:praxis-ergon-showcase:human-resources.afastamentos:filter",
                        "rev-2026-11-09-01",
                        EnforcementDisposition.PERMIT,
                        ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX,
                        auditObligations,
                        Map.of("principalId", "usr-gestor-101")
                )
        );
        assertNotNull(readOnlyResults);
        assertFalse(readOnlyResults.getFirst().fulfilled());

        // 5. Canonical payloadDigest is deterministic regardless of Map insertion order (P67-R01)
        Map<String, Object> orderA = new LinkedHashMap<>();
        orderA.put("zKey", "valZ");
        orderA.put("aKey", "valA");
        orderA.put("idempotencyEntryId", "outbox-order-a");
        Map<String, Object> orderB = new LinkedHashMap<>();
        orderB.put("aKey", "valA");
        orderB.put("zKey", "valZ");
        orderB.put("idempotencyEntryId", "outbox-order-a");
        String digestA = txTemplate.execute(status -> {
            jdbcOutbox.appendAuditOutboxRecord("dp:1", "rev:1", orderA);
            var row = jdbcOutbox.listCommittedEntries().stream()
                    .filter(r -> "outbox-order-a".equals(r.entryId())).findFirst().orElseThrow();
            status.setRollbackOnly();
            return row.payloadDigest();
        });
        String digestB = txTemplate.execute(status -> {
            jdbcOutbox.appendAuditOutboxRecord("dp:1", "rev:1", orderB);
            var row = jdbcOutbox.listCommittedEntries().stream()
                    .filter(r -> "outbox-order-a".equals(r.entryId())).findFirst().orElseThrow();
            status.setRollbackOnly();
            return row.payloadDigest();
        });
        assertEquals(digestA, digestB);
    }

    @Test
    void verifyP6ConfigMaterializationToOpaReconcilerLifecycleAndWithdrawal() {
        AfastamentoAuthzPilotBlueprint blueprint = AfastamentoAuthzPilotBlueprint.createErgonAfastamentoBlueprint();
        RegoV1PolicyCompiler compiler = new RegoV1PolicyCompiler();
        ConfigMaterializationToOpaReconciler reconciler = new ConfigMaterializationToOpaReconciler(
                compiler,
                new GovernedOpaReleaseCoordinator()
        );

        String expectedFp = compiler.compileUnit(
                blueprint.policyDefinition(),
                Map.of(blueprint.decisionPoint().identity().pointKey(), blueprint.decisionPoint()),
                Map.of(blueprint.factContract().factContractId(), blueprint.factContract()),
                Map.of(blueprint.queryProjection().projectionId(), blueprint.queryProjection())
        ).unitManifest().digestChain().definitionFingerprint();

        ProviderInputProjection positiveInput = new ProviderInputProjection(
                ProviderInputProjection.SCHEMA_VERSION_V1,
                blueprint.decisionPoint().identity().pointKey(),
                "SEARCH",
                blueprint.factContract().factContractDigest(),
                new TemporalContext(Instant.now(), ZoneOffset.UTC),
                Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L)),
                Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT),
                Set.of()
        );
        ProviderInputProjection negativeInput = new ProviderInputProjection(
                ProviderInputProjection.SCHEMA_VERSION_V1,
                blueprint.decisionPoint().identity().pointKey(),
                "SEARCH",
                blueprint.factContract().factContractDigest(),
                new TemporalContext(Instant.now(), ZoneOffset.UTC),
                Map.of("subject.principalId", "usr-intruso-999", "subject.organizationUnitIds", List.of(999L)),
                Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT),
                Set.of()
        );
        List<PolicyCandidateVerificationCorpusCase> validCorpus = List.of(
                new PolicyCandidateVerificationCorpusCase(
                        "case-pos-1", "Authorized manager gets FILTER scope",
                        EvaluationMode.SEARCH, positiveInput, null,
                        GateOutcome.ALLOW, "ALLOW_LOTACAO_GESTOR", DataScopeOutcome.FILTER
                ),
                new PolicyCandidateVerificationCorpusCase(
                        "case-neg-1", "Unauthorized user gets NOT_APPLICABLE / NONE",
                        EvaluationMode.SEARCH, negativeInput, null,
                        GateOutcome.NOT_APPLICABLE, null, DataScopeOutcome.NONE
                )
        );
        String capDigest = blueprint.bundleArtifact().runtimeHead().opaCapabilitiesDigest();

        // 1. Self-approval (authoredBy == approvedBy) violates 4-eyes governance and fails closed (P28, P55)
        ConfigRuleMaterializationSnapshot selfApprovedSnapshot = new ConfigRuleMaterializationSnapshot(
                "mat-101", "def-101", 1, "tenant-gov-br", "prod",
                "policy_engine", "opa-policy", "unit:pol-praxis-ergon-showcase-human-resources-afastamentos:v1",
                "rel-config-101", "applied", true, expectedFp,
                "usr-author-1", "usr-author-1", "usr-operator-1",
                MaterializationResolutionState.ELIGIBLE_APPLIED_HEAD,
                blueprint.policyDefinition(), validCorpus, Instant.now()
        );
        assertThrows(SecurityException.class, () ->
                reconciler.reconcileOrWithdraw(
                        selfApprovedSnapshot, "opa-1", capDigest, "usr-operator-1",
                        Set.of(GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY),
                        Map.of(blueprint.decisionPoint().identity().pointKey(), blueprint.decisionPoint()),
                        Map.of(blueprint.factContract().factContractId(), blueprint.factContract()),
                        Map.of(blueprint.queryProjection().projectionId(), blueprint.queryProjection())
                )
        );

        // 2. Valid 4-eyes ELIGIBLE_APPLIED_HEAD activates bundle and pins OpaRuntimeHead (P53, P55, P63)
        ConfigRuleMaterializationSnapshot validSnapshot = new ConfigRuleMaterializationSnapshot(
                "mat-102", "def-101", 2, "tenant-gov-br", "prod",
                "policy_engine", "opa-policy", "unit:pol-praxis-ergon-showcase-human-resources-afastamentos:v1",
                "rel-config-102", "applied", true, expectedFp,
                "usr-author-1", "usr-approver-2", "usr-operator-1",
                MaterializationResolutionState.ELIGIBLE_APPLIED_HEAD,
                blueprint.policyDefinition(), validCorpus, Instant.now()
        );
        var activeOutcome = reconciler.reconcileOrWithdraw(
                validSnapshot, "opa-1", capDigest, "usr-operator-1",
                Set.of(GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY),
                Map.of(blueprint.decisionPoint().identity().pointKey(), blueprint.decisionPoint()),
                Map.of(blueprint.factContract().factContractId(), blueprint.factContract()),
                Map.of(blueprint.queryProjection().projectionId(), blueprint.queryProjection())
        );
        assertTrue(activeOutcome.bundleActivated());
        assertTrue(reconciler.findActiveHead(validSnapshot.targetArtifactKey()).isPresent());
        assertTrue(reconciler.findActiveHead("tenant-gov-br", "prod", validSnapshot.targetArtifactKey()).isPresent());

        // 2b. Replay/rollback of older definitionVersion (1 < 2) is rejected fail-closed (P67-R02 / P17 / P28)
        ConfigRuleMaterializationSnapshot rollbackSnapshot = new ConfigRuleMaterializationSnapshot(
                "mat-101-replay", "def-101", 1, "tenant-gov-br", "prod",
                "policy_engine", "opa-policy", "unit:pol-praxis-ergon-showcase-human-resources-afastamentos:v1",
                "rel-config-101-replay", "applied", true, expectedFp,
                "usr-author-1", "usr-approver-2", "usr-operator-1",
                MaterializationResolutionState.ELIGIBLE_APPLIED_HEAD,
                blueprint.policyDefinition(), validCorpus, Instant.now()
        );
        assertThrows(SecurityException.class, () ->
                reconciler.reconcileOrWithdraw(
                        rollbackSnapshot, "opa-1", capDigest, "usr-operator-1",
                        Set.of(GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY),
                        Map.of(blueprint.decisionPoint().identity().pointKey(), blueprint.decisionPoint()),
                        Map.of(blueprint.factContract().factContractId(), blueprint.factContract()),
                        Map.of(blueprint.queryProjection().projectionId(), blueprint.queryProjection())
                )
        );

        // 2c. Undeclared targetArtifactKey mismatch is rejected fail-closed (P67-R02 / P38)
        ConfigRuleMaterializationSnapshot mismatchedTargetSnapshot = new ConfigRuleMaterializationSnapshot(
                "mat-103", "def-101", 3, "tenant-gov-br", "prod",
                "policy_engine", "opa-policy", "unit:undeclared-target-key:v1",
                "rel-config-103", "applied", true, expectedFp,
                "usr-author-1", "usr-approver-2", "usr-operator-1",
                MaterializationResolutionState.ELIGIBLE_APPLIED_HEAD,
                blueprint.policyDefinition(), validCorpus, Instant.now()
        );
        assertThrows(SecurityException.class, () ->
                reconciler.reconcileOrWithdraw(
                        mismatchedTargetSnapshot, "opa-1", capDigest, "usr-operator-1",
                        Set.of(GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY),
                        Map.of(blueprint.decisionPoint().identity().pointKey(), blueprint.decisionPoint()),
                        Map.of(blueprint.factContract().factContractId(), blueprint.factContract()),
                        Map.of(blueprint.queryProjection().projectionId(), blueprint.queryProjection())
                )
        );

        // 3. Subsequent withdrawal (PREVIOUSLY_APPLIED_WITHOUT_ELIGIBLE_HEAD) revokes the active head (P18, P28, P55)
        ConfigRuleMaterializationSnapshot withdrawnSnapshot = new ConfigRuleMaterializationSnapshot(
                "mat-102", "def-101", 2, "tenant-gov-br", "prod",
                "policy_engine", "opa-policy", "unit:pol-praxis-ergon-showcase-human-resources-afastamentos:v1",
                "rel-config-102", "superseded", true, expectedFp,
                "usr-author-1", "usr-approver-2", "usr-operator-1",
                MaterializationResolutionState.PREVIOUSLY_APPLIED_WITHOUT_ELIGIBLE_HEAD,
                null, List.of(), Instant.now()
        );
        var withdrawnOutcome = reconciler.reconcileOrWithdraw(
                withdrawnSnapshot, "opa-1", capDigest, "usr-operator-1",
                Set.of(GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY),
                Map.of(blueprint.decisionPoint().identity().pointKey(), blueprint.decisionPoint()),
                Map.of(blueprint.factContract().factContractId(), blueprint.factContract()),
                Map.of(blueprint.queryProjection().projectionId(), blueprint.queryProjection())
        );
        assertFalse(withdrawnOutcome.bundleActivated());
        assertTrue(withdrawnOutcome.previousHeadWithdrawn());
        assertTrue(reconciler.findActiveHead(validSnapshot.targetArtifactKey()).isEmpty());
    }

    @Test
    void verifyP7MetadataResourceAuthorizationSeamEndToEnd() {
        AfastamentoAuthzPilotBlueprint blueprint = AfastamentoAuthzPilotBlueprint.createErgonAfastamentoBlueprint();
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:praxis_seam_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
                "sa",
                ""
        );
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        TransactionTemplate txTemplate = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        JdbcTransactionalAuditOutbox jdbcOutbox = new JdbcTransactionalAuditOutbox(
                jdbcTemplate, "praxis_authz_obligation_outbox", true, true
        );

        OpaAuthorizationProviderAdapter opaAdapter = new OpaAuthorizationProviderAdapter(
                blueprint.localOpaTransport(),
                new SameInstanceSearchRevisionGuard(1)
        );
        org.praxisplatform.authz.telemetry.SanitizedAuthorizationTelemetryPublisher telemetryPublisher =
                new org.praxisplatform.authz.telemetry.SanitizedAuthorizationTelemetryPublisher(List.of(), 100);
        MetadataResourceAuthorizationSeam seam = new MetadataResourceAuthorizationSeam(
                opaAdapter,
                new FieldUseQueryGuard(),
                new DtoWriteIntentExtractor(),
                new FieldWriteAuthorizer(),
                new DetachedDtoMaskingProcessor(),
                new ObligationBarrierCoordinator(new DefaultObligationHandlerRegistry(), jdbcOutbox),
                telemetryPublisher
        );

        JpaDataScopeAdapter jpaAdapter = new JpaDataScopeAdapter(
                blueprint.queryProjection(),
                List.of(new QueryAdapterFieldBinding(
                        blueprint.resourceKey(),
                        "resource.lotacaoSetorId",
                        "ergon.afastamentos.lotacao_setor_id",
                        "e.lotacaoSetorId",
                        RelationTraversalStrategy.INNER_JOIN_SCALAR,
                        false
                ))
        );

        // 1. Query Seam: Rejects untrusted header X-Tenant-Id (P01)
        assertThrows(Exception.class, () ->
                seam.authorizeAndCompileJpaQueryScope(
                        blueprint.decisionPoint(),
                        blueprint.factContract().factContractDigest(),
                        Set.of("X-Tenant-Id"),
                        Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L)),
                        Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT),
                        Map.of(),
                        List.of(),
                        jpaAdapter,
                        "e.tenantId = :hardTenantId",
                        Map.of("hardTenantId", "tenant-gov-br"),
                        row -> true
                )
        );

        // 2. Query Seam: Compiles hardScopeJpql AND policyJpql and masks query results (P05..P09, P12)
        AuthorizedQueryScopeContext queryCtx = seam.authorizeAndCompileJpaQueryScope(
                blueprint.decisionPoint(),
                blueprint.factContract().factContractDigest(),
                Set.of("Accept", "Content-Type"),
                Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L, 200L)),
                Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT),
                Map.of(),
                List.of(new FieldUseEffectDirective("ergon.afastamentos.cid_codigo", FieldUseCategory.FILTER, RuleEffect.DENY)),
                jpaAdapter,
                "e.tenantId = :hardTenantId",
                Map.of("hardTenantId", "tenant-gov-br"),
                row -> true
        );
        assertNotNull(queryCtx.compiledJpaDataScope());
        assertTrue(queryCtx.compiledJpaDataScope().composedWhereClause().contains("e.tenantId = :hardTenantId"));
        assertTrue(queryCtx.compiledJpaDataScope().composedWhereClause().contains("e.lotacaoSetorId IN"));

        List<DetachedDtoMaskingResult> maskedRows = seam.projectAndMaskQueryResults(
                queryCtx,
                List.of(new AfastamentoRecord(10L, "tenant-gov-br", 1L, 2L, 100L, "DEFERIDO", 5001L, "M54.5")),
                AfastamentoPilotRuntimeHost.defaultFieldSchemas()
        );
        assertEquals(1, maskedRows.size());
        assertEquals("***CID-RESTRITO***", maskedRows.getFirst().detachedProjection().get("cidCodigo"));

        // 3. Query Seam: Blocks FILTER on denied cidCodigo (P08, P50)
        assertThrows(FieldUseViolationException.class, () ->
                seam.authorizeAndCompileJpaQueryScope(
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
                        row -> true
                )
        );

        // 4. Pre-Hydration Mutation Seam + JDBC Outbox Commit + Detached Masking (P13, P14, P19, P40)
        Map<String, String> wireMap = Map.of(
                "/lotacaoSetorId", "ergon.afastamentos.lotacao_setor_id",
                "/statusAfastamento", "ergon.afastamentos.status_afastamento",
                "/substitutoServidorId", "ergon.afastamentos.substituto_servidor_id",
                "/cidCodigo", "ergon.afastamentos.cid_codigo"
        );
        // Clearing a mandatory scope anchor (lotacaoSetorId: null) is rejected fail-closed (P67-R04 / CC06 / P13)
        assertThrows(SecurityException.class, () ->
                seam.authorizePreHydrationMutation(
                        blueprint.decisionPoint(),
                        blueprint.factContract().factContractDigest(),
                        "PATCH",
                        true,
                        "{\"lotacaoSetorId\": null, \"substitutoServidorId\": 7777}",
                        wireMap,
                        Set.of("/version"),
                        Set.of("ergon.afastamentos.lotacao_setor_id"),
                        blueprint.dualScopeSpec(),
                        false,
                        true,
                        Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L), "resource.lotacaoSetorId", 100L),
                        Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT, "resource.lotacaoSetorId", FactResolutionStatus.PRESENT)
                )
        );
        // Cessionário attempting to modify Cedente field is blocked before hydration!
        assertThrows(FieldWriteViolationException.class, () ->
                seam.authorizePreHydrationMutation(
                        blueprint.decisionPoint(),
                        blueprint.factContract().factContractDigest(),
                        "PATCH",
                        true,
                        "{\"statusAfastamento\": \"REVOGADO\"}",
                        wireMap,
                        Set.of("/version"),
                        Set.of(),
                        blueprint.dualScopeSpec(),
                        false, // callerMatchesCedente = false
                        true,  // callerMatchesCessionario = true
                        Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L), "resource.lotacaoSetorId", 100L),
                        Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT, "resource.lotacaoSetorId", FactResolutionStatus.PRESENT)
                )
        );

        // Valid Cessionário mutation on substitutoServidorId inside SQL transaction commits outbox and masks response
        DetachedDtoMaskingResult mutationResult = txTemplate.execute(status -> {
            AuthorizedPreMutationContext preCtx = seam.authorizePreHydrationMutation(
                    blueprint.decisionPoint(),
                    blueprint.factContract().factContractDigest(),
                    "PATCH",
                    true,
                    "{\"substitutoServidorId\": 7777}",
                    wireMap,
                    Set.of("/version"),
                    Set.of(),
                    blueprint.dualScopeSpec(),
                    false,
                    true,
                    Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L), "resource.lotacaoSetorId", 100L),
                    Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT, "resource.lotacaoSetorId", FactResolutionStatus.PRESENT)
            );
            AfastamentoRecord updatedEntity = new AfastamentoRecord(
                    10L, "tenant-gov-br", 1L, 2L, 100L, "DEFERIDO", 7777L, "M54.5"
            );
            return seam.completePostMutationAndMask(
                    preCtx,
                    updatedEntity,
                    AfastamentoPilotRuntimeHost.defaultFieldSchemas()
            );
        });
        assertNotNull(mutationResult);
        assertEquals(7777, ((Number) mutationResult.detachedProjection().get("substitutoServidorId")).intValue());
        assertEquals("***CID-RESTRITO***", mutationResult.detachedProjection().get("cidCodigo"));
        assertEquals(1, jdbcOutbox.listCommittedEntries().size());

        // 5. Durable Bulk Worker Seam & Advisory Discovery HATEOAS Seam (P02, P10, P15, P17, P18)
        String activeDigest = blueprint.bundleArtifact().runtimeRelease().policySetDigest();
        WorkerDelegationToken validToken = new WorkerDelegationToken(
                "bulk-worker-1",
                "usr-gestor-101",
                "tenant-gov-br",
                "praxis-bulk-worker",
                Instant.now().plusSeconds(300),
                activeDigest,
                Map.of("subject.principalId", "usr-gestor-101")
        );
        seam.authorizeBulkDurableWorkerItem(validToken, "praxis-bulk-worker", activeDigest, Instant.now());
        // Live per-item OPA TARGET re-evaluation in BulkDurableWorker (P67-R05 / P15 / P18)
        WriteIntent workerItemIntent = new WriteIntent(
                "PATCH",
                true,
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.STATEMENT_ATOMIC,
                List.of(new WriteFieldChange("/substitutoServidorId", "ergon.afastamentos.substituto_servidor_id", WriteChangeKind.SET, 7777))
        );
        var workerItemEnvelope = seam.authorizeBulkDurableWorkerItem(
                validToken,
                "praxis-bulk-worker",
                activeDigest,
                Instant.now(),
                blueprint.decisionPoint(),
                blueprint.factContract().factContractDigest(),
                workerItemIntent,
                Map.of("subject.organizationUnitIds", List.of(100L), "resource.lotacaoSetorId", 100L),
                Map.of("subject.organizationUnitIds", FactResolutionStatus.PRESENT, "resource.lotacaoSetorId", FactResolutionStatus.PRESENT)
        );
        assertEquals(GateOutcome.ALLOW, workerItemEnvelope.gateOutcome());
        // Out-of-scope item (lotacaoSetorId = 999L) is rejected during per-item worker execution
        assertThrows(SecurityException.class, () ->
                seam.authorizeBulkDurableWorkerItem(
                        validToken,
                        "praxis-bulk-worker",
                        activeDigest,
                        Instant.now(),
                        blueprint.decisionPoint(),
                        blueprint.factContract().factContractDigest(),
                        workerItemIntent,
                        Map.of("subject.organizationUnitIds", List.of(100L), "resource.lotacaoSetorId", 999L),
                        Map.of("subject.organizationUnitIds", FactResolutionStatus.PRESENT, "resource.lotacaoSetorId", FactResolutionStatus.PRESENT)
                )
        );
        assertThrows(SecurityException.class, () ->
                seam.authorizeBulkDurableWorkerItem(validToken, "praxis-bulk-worker", "sha256:rotated-digest", Instant.now())
        );

        AdvisoryOperationAvailability advisoryLink = seam.evaluateAdvisoryAvailability(
                blueprint.decisionPoint().identity().pointKey(), true, "rev-1"
        );
        assertTrue(advisoryLink.advisoryOnly());
        assertTrue(advisoryLink.requiresRuntimeRevalidation());
        assertThrows(SecurityException.class, () ->
                seam.enforceAuthoritativeExecutionAgainstStaleLink(advisoryLink, false)
        );

        // P10-R05 (CC12 / P52): Verify sanitized telemetry was published across query, mutation, and bulk worker evaluations
        assertTrue(telemetryPublisher.recentEvents(100).size() >= 5);
        assertTrue(telemetryPublisher.recentEvents(100).stream().anyMatch(e -> GateOutcome.ALLOW == e.gateOutcome()));
        assertTrue(telemetryPublisher.recentEvents(100).stream().anyMatch(e -> GateOutcome.NOT_APPLICABLE == e.gateOutcome()));
    }
}
