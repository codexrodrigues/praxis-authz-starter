package org.praxisplatform.authz.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzAutoConfiguration;
import org.praxisplatform.authz.catalog.MethodBindingAdmissionRecord;
import org.praxisplatform.authz.catalog.PapCatalogQueryRequest;
import org.praxisplatform.authz.channel.GovernedChannelInvocationExecutor;
import org.praxisplatform.authz.compatibility.HostRuntimePolicyCoordinates;
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
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry;
import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler.ConfigRuleMaterializationSnapshot;
import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler.MaterializationResolutionState;
import org.praxisplatform.authz.controlplane.GovernedPapAdminOperationsService;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.jpa.QueryAdapterFieldBinding;
import org.praxisplatform.authz.enforcement.jpa.RelationTraversalStrategy;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.writeintent.DtoWriteIntentExtractor;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;
import org.praxisplatform.authz.opa.client.OpaAuthorizationProviderAdapter;
import org.praxisplatform.authz.opa.client.OpaClientTransport;
import org.praxisplatform.authz.opa.compiler.RegoV1PolicyCompiler;
import org.praxisplatform.authz.opa.governance.GovernedOpaReleaseCoordinator;
import org.praxisplatform.authz.opa.governance.PolicyCandidateVerificationCorpusCase;
import org.praxisplatform.authz.opa.revision.SameInstanceSearchRevisionGuard;
import org.praxisplatform.authz.outbox.JdbcAuditOutboxRelayExecutor;
import org.praxisplatform.authz.outbox.JdbcAuditOutboxRelayExecutor.RelayBatchResult;
import org.praxisplatform.authz.outbox.JdbcTransactionalAuditOutbox;
import org.praxisplatform.authz.outbox.JdbcTransactionalAuditOutbox.OutboxDeliveryStatus;
import org.praxisplatform.authz.outbox.JdbcTransactionalAuditOutbox.PersistedOutboxRecord;
import org.praxisplatform.authz.pilot.AfastamentoAuthzPilotBlueprint;
import org.praxisplatform.authz.seams.DeclarativeDecisionPointExecutionTemplate;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.WorkerDelegationToken;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Verifies Phase {@code P8} operational closure in {@code praxis-authz-starter}:
 * <ul>
 *   <li>{@link JdbcAuditOutboxRelayExecutor}: {@code PENDING -> DELIVERED | DEAD_LETTER} lifecycle and safe purge;</li>
 *   <li>{@link RuntimeDecisionPointRegistry} & {@link DeclarativeDecisionPointExecutionTemplate}: declarative
 *       execution by {@code pointKey} and fail-closed rejection of unregistered points;</li>
 *   <li>{@link GovernedPapAdminOperationsService}: opt-in activation ({@code G0}/{@code P32}) and administrative
 *       authority enforcement ({@code P28}/{@code P35}/{@code P55}).</li>
 * </ul>
 */
class P8OutboxRelayAndDeclarativeRegistryTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PraxisAuthzAutoConfiguration.class));

    @Test
    void verifyP8JdbcAuditOutboxRelayDeliveryRetryDeadLetterAndPurge() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:praxis_p8_relay_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
                "sa",
                ""
        );
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        TransactionTemplate txTemplate = new TransactionTemplate(new DataSourceTransactionManager(dataSource));

        JdbcTransactionalAuditOutbox outbox = new JdbcTransactionalAuditOutbox(
                jdbcTemplate,
                "praxis_authz_obligation_outbox",
                true,
                true
        );

        txTemplate.executeWithoutResult(status -> {
            assertTrue(outbox.appendAuditOutboxRecord("dp:1", "rev:1", Map.of("idempotencyEntryId", "outbox-ok")));
            assertTrue(outbox.appendAuditOutboxRecord("dp:1", "rev:1", Map.of("idempotencyEntryId", "outbox-retry")));
            assertTrue(outbox.appendAuditOutboxRecord("dp:1", "rev:1", Map.of("idempotencyEntryId", "outbox-dlq")));
        });

        AtomicBoolean retryShouldSucceedNow = new AtomicBoolean(false);
        JdbcAuditOutboxRelayExecutor relay = new JdbcAuditOutboxRelayExecutor(outbox, record -> {
            if ("outbox-ok".equals(record.entryId())) {
                return true;
            }
            if ("outbox-retry".equals(record.entryId())) {
                return retryShouldSucceedNow.get();
            }
            throw new IllegalStateException("Simulated SIEM transport failure");
        });

        Instant cycle1Time = Instant.parse("2026-11-09T11:00:00Z");
        RelayBatchResult cycle1 = relay.drainPendingBatch(10, 2, cycle1Time);
        assertEquals(3, cycle1.inspectedCount());
        assertEquals(1, cycle1.deliveredCount());
        assertEquals(2, cycle1.retriedPendingCount());
        assertEquals(0, cycle1.deadLetteredCount());

        // Cycle 2: outbox-retry succeeds on attempt 2; outbox-dlq fails attempt 2 and reaches maxAttempts=2 -> DEAD_LETTER
        retryShouldSucceedNow.set(true);
        Instant cycle2Time = Instant.parse("2026-11-09T11:05:00Z");
        RelayBatchResult cycle2 = relay.drainPendingBatch(10, 2, cycle2Time);
        assertEquals(2, cycle2.inspectedCount());
        assertEquals(1, cycle2.deliveredCount());
        assertEquals(0, cycle2.retriedPendingCount());
        assertEquals(1, cycle2.deadLetteredCount());

        Map<String, PersistedOutboxRecord> byId = outbox.listCommittedEntries().stream()
                .collect(java.util.stream.Collectors.toMap(PersistedOutboxRecord::entryId, r -> r));

        assertEquals(OutboxDeliveryStatus.DELIVERED, byId.get("outbox-ok").deliveryStatus());
        assertEquals(1, byId.get("outbox-ok").attemptCount());
        assertNotNull(byId.get("outbox-ok").deliveredAt());
        assertNull(byId.get("outbox-ok").lastErrorCode());

        assertEquals(OutboxDeliveryStatus.DELIVERED, byId.get("outbox-retry").deliveryStatus());
        assertEquals(2, byId.get("outbox-retry").attemptCount());

        assertEquals(OutboxDeliveryStatus.DEAD_LETTER, byId.get("outbox-dlq").deliveryStatus());
        assertEquals(2, byId.get("outbox-dlq").attemptCount());
        assertEquals("SINK_EXCEPTION:IllegalStateException", byId.get("outbox-dlq").lastErrorCode());

        // Purge DELIVERED rows before 11:02:00Z -> purges outbox-ok (11:00Z), preserves outbox-retry (11:05Z) and outbox-dlq (DEAD_LETTER)
        int purged = relay.purgeDeliveredBefore(Instant.parse("2026-11-09T11:02:00Z"));
        assertEquals(1, purged);
        List<PersistedOutboxRecord> remaining = outbox.listCommittedEntries();
        assertEquals(2, remaining.size());
        assertTrue(remaining.stream().anyMatch(r -> "outbox-retry".equals(r.entryId())));
        assertTrue(remaining.stream().anyMatch(r -> "outbox-dlq".equals(r.entryId()) && r.deliveryStatus() == OutboxDeliveryStatus.DEAD_LETTER));

        // P8-R01: Operator DLQ recovery requeues DEAD_LETTER back to PENDING (attemptCount = 0)
        assertEquals(0, outbox.listPendingEntries(10).size());
        int requeued = relay.requeueDeadLetterEntries(Set.of("outbox-dlq"));
        assertEquals(1, requeued);
        List<PersistedOutboxRecord> pendingAfterRequeue = outbox.listPendingEntries(10);
        assertEquals(1, pendingAfterRequeue.size());
        assertEquals("outbox-dlq", pendingAfterRequeue.getFirst().entryId());
        assertEquals(0, pendingAfterRequeue.getFirst().attemptCount());
    }

    @Test
    void verifyP8DeclarativeDecisionPointExecutionTemplateAndFailClosedRegistry() {
        AfastamentoAuthzPilotBlueprint blueprint = AfastamentoAuthzPilotBlueprint.createErgonAfastamentoBlueprint();
        RuntimeDecisionPointRegistry registry = new RuntimeDecisionPointRegistry(
                blueprint.admissionRecords(),
                blueprint.coordinates()
        );
        MethodBindingAdmissionRecord admissionRecord = blueprint.admissionRecords().getFirst();
        String pointKey = admissionRecord.decisionPoint().identity().pointKey();
        registry.registerAdmissionRecord(
                admissionRecord,
                blueprint.dualScopeSpec(),
                Set.of("ergon.afastamentos.lotacao_setor_id")
        );

        // P8-R02: Admission record with proxyEnforcedWithoutSelfInvocationBypass == false is rejected fail-closed (P41)
        MethodBindingAdmissionRecord unproxiedRecord = new MethodBindingAdmissionRecord(
                admissionRecord.serviceKey(),
                admissionRecord.decisionPoint(),
                admissionRecord.enforcementBinding(),
                admissionRecord.admittedChannels(),
                false, // unproxied self-invocation bypass risk!
                admissionRecord.fieldLineageEntries()
        );
        assertThrows(IllegalStateException.class, () ->
                registry.registerAdmissionRecord(unproxiedRecord, null, Set.of())
        );

        MetadataResourceAuthorizationSeam seam = new MetadataResourceAuthorizationSeam(
                new OpaAuthorizationProviderAdapter(blueprint.localOpaTransport(), new SameInstanceSearchRevisionGuard(1)),
                new FieldUseQueryGuard(),
                new DtoWriteIntentExtractor(),
                new FieldWriteAuthorizer(),
                new DetachedDtoMaskingProcessor(),
                new ObligationBarrierCoordinator(
                        new DefaultObligationHandlerRegistry(),
                        new org.praxisplatform.authz.enforcement.obligation.InMemoryTransactionalAuditOutbox()
                )
        );
        DeclarativeDecisionPointExecutionTemplate template = new DeclarativeDecisionPointExecutionTemplate(
                registry,
                seam,
                new GovernedChannelInvocationExecutor()
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

        // 1. Unregistered decisionPointKey fails closed immediately (P20, P34, P41)
        assertThrows(SecurityException.class, () ->
                template.authorizeSearchByPointKey(
                        "resource-operation/praxis-ergon-showcase/unregistered.resource/read",
                        Set.of(),
                        Map.of("subject.principalId", "usr-gestor-101"),
                        Map.of("subject.principalId", FactResolutionStatus.PRESENT),
                        Map.of(),
                        List.of(),
                        jpaAdapter,
                        "e.tenantId = :hardTenantId",
                        Map.of("hardTenantId", "tenant-gov-br"),
                        row -> true
                )
        );

        // 2. Registered pointKey resolves descriptor & FactContract automatically for SEARCH
        var searchCtx = template.authorizeSearchByPointKey(
                pointKey,
                Set.of("Accept"),
                Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L)),
                Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT),
                Map.of(),
                List.of(),
                jpaAdapter,
                "e.tenantId = :hardTenantId",
                Map.of("hardTenantId", "tenant-gov-br"),
                row -> true
        );
        assertEquals(DataScopeOutcome.FILTER, searchCtx.scopeOutcome());

        // 3. Registered pointKey enforces mandatory scope anchor protection and dual-scope custody on mutation
        Map<String, String> wireMap = Map.of(
                "/lotacaoSetorId", "ergon.afastamentos.lotacao_setor_id",
                "/substitutoServidorId", "ergon.afastamentos.substituto_servidor_id"
        );
        assertThrows(SecurityException.class, () ->
                template.authorizeMutationByPointKey(
                        pointKey,
                        "PATCH",
                        true,
                        "{\"lotacaoSetorId\": null}",
                        wireMap,
                        Set.of("/version"),
                        false,
                        true,
                        Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L), "resource.lotacaoSetorId", 100L),
                        Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT, "resource.lotacaoSetorId", FactResolutionStatus.PRESENT)
                )
        );

        // 4. Registered pointKey executes BulkDurableWorker per-item live TARGET check
        String activeDigest = blueprint.bundleArtifact().runtimeRelease().policySetDigest();
        WorkerDelegationToken workerToken = new WorkerDelegationToken(
                "bulk-worker-1",
                "usr-gestor-101",
                "tenant-gov-br",
                "praxis-bulk-worker",
                Instant.now().plusSeconds(300),
                activeDigest,
                Map.of("subject.principalId", "usr-gestor-101")
        );
        WriteIntent itemIntent = new WriteIntent(
                "PATCH",
                true,
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.STATEMENT_ATOMIC,
                List.of(new WriteFieldChange("/substitutoServidorId", "ergon.afastamentos.substituto_servidor_id", WriteChangeKind.SET, 7777))
        );
        var workerEnvelope = template.authorizeBulkWorkerItemByPointKey(
                pointKey,
                workerToken,
                "praxis-bulk-worker",
                activeDigest,
                Instant.now(),
                itemIntent,
                Map.of("subject.organizationUnitIds", List.of(100L), "resource.lotacaoSetorId", 100L),
                Map.of("subject.organizationUnitIds", FactResolutionStatus.PRESENT, "resource.lotacaoSetorId", FactResolutionStatus.PRESENT)
        );
        assertEquals(GateOutcome.ALLOW, workerEnvelope.gateOutcome());
    }

    @Test
    void verifyP8GovernedPapAdminOperationsOptInAndAuthorityGuards() {
        AfastamentoAuthzPilotBlueprint blueprint = AfastamentoAuthzPilotBlueprint.createErgonAfastamentoBlueprint();

        // 1. By default (admin-endpoints.enabled=false), GovernedPapAdminOperationsService is NOT registered (G0, P32)
        contextRunner
                .withBean(OpaClientTransport.class, blueprint::localOpaTransport)
                .withBean(HostRuntimePolicyCoordinates.class, blueprint::coordinates)
                .withBean(MethodBindingAdmissionRecord.class, () -> blueprint.admissionRecords().getFirst())
                .run(context -> assertFalse(context.containsBean("governedPapAdminOperationsService")));

        // 2. When explicitly enabled (praxis.authz.admin-endpoints.enabled=true), it enforces catalog and reconcile authorities
        contextRunner
                .withPropertyValues("praxis.authz.admin-endpoints.enabled=true")
                .withBean(OpaClientTransport.class, blueprint::localOpaTransport)
                .withBean(HostRuntimePolicyCoordinates.class, blueprint::coordinates)
                .withBean(MethodBindingAdmissionRecord.class, () -> blueprint.admissionRecords().getFirst())
                .run(context -> {
                    GovernedPapAdminOperationsService adminService = context.getBean(GovernedPapAdminOperationsService.class);

                    // Missing catalog authority -> denied (P35)
                    assertThrows(SecurityException.class, () ->
                            adminService.querySemanticCatalog(new PapCatalogQueryRequest(
                                    "usr-no-auth",
                                    Set.of(),
                                    Set.of("praxis-ergon-showcase"),
                                    "praxis-ergon-showcase"
                            ))
                    );

                    // Valid catalog authority -> returns admitted catalog
                    var catalogView = adminService.querySemanticCatalog(new PapCatalogQueryRequest(
                            "usr-pap-admin",
                            Set.of("praxis:authz:pap:catalog:read"),
                            Set.of("praxis-ergon-showcase"),
                            "praxis-ergon-showcase"
                    ));
                    assertEquals(1, catalogView.admittedDecisionPoints().size());

                    // Reconcile materialization through admin service
                    RegoV1PolicyCompiler compiler = context.getBean(RegoV1PolicyCompiler.class);
                    String expectedFp = compiler.compileUnit(
                            blueprint.policyDefinition(),
                            Map.of(blueprint.decisionPoint().identity().pointKey(), blueprint.decisionPoint()),
                            Map.of(blueprint.factContract().factContractId(), blueprint.factContract()),
                            Map.of(blueprint.queryProjection().projectionId(), blueprint.queryProjection())
                    ).unitManifest().digestChain().definitionFingerprint();

                    ProviderInputProjection posInput = new ProviderInputProjection(
                            ProviderInputProjection.SCHEMA_VERSION_V1,
                            blueprint.decisionPoint().identity().pointKey(),
                            "SEARCH",
                            blueprint.factContract().factContractDigest(),
                            new TemporalContext(Instant.now(), ZoneOffset.UTC),
                            Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L)),
                            Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT),
                            Set.of()
                    );
                    ProviderInputProjection negInput = new ProviderInputProjection(
                            ProviderInputProjection.SCHEMA_VERSION_V1,
                            blueprint.decisionPoint().identity().pointKey(),
                            "SEARCH",
                            blueprint.factContract().factContractDigest(),
                            new TemporalContext(Instant.now(), ZoneOffset.UTC),
                            Map.of("subject.principalId", "usr-intruso-999", "subject.organizationUnitIds", List.of(999L)),
                            Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT),
                            Set.of()
                    );
                    ConfigRuleMaterializationSnapshot snapshot = new ConfigRuleMaterializationSnapshot(
                            "mat-p8-1", "def-p8-1", 1, "tenant-gov-br", "prod",
                            "policy_engine", "opa-policy", "unit:pol-praxis-ergon-showcase-human-resources-afastamentos:v1",
                            "rel-p8-1", "applied", true, expectedFp,
                            "usr-author-1", "usr-approver-2", "usr-operator-1",
                            MaterializationResolutionState.ELIGIBLE_APPLIED_HEAD,
                            blueprint.policyDefinition(),
                            List.of(
                                    new PolicyCandidateVerificationCorpusCase(
                                            "pos-1", "Authorized manager", EvaluationMode.SEARCH, posInput, null,
                                            GateOutcome.ALLOW, "ALLOW_LOTACAO_GESTOR", DataScopeOutcome.FILTER),
                                    new PolicyCandidateVerificationCorpusCase(
                                            "neg-1", "Unauthorized user", EvaluationMode.SEARCH, negInput, null,
                                            GateOutcome.NOT_APPLICABLE, null, DataScopeOutcome.NONE)
                            ),
                            Instant.now()
                    );
                    String capDigest = blueprint.bundleArtifact().runtimeHead().opaCapabilitiesDigest();

                    // Missing reconcile authority -> denied (P28, P32)
                    assertThrows(SecurityException.class, () ->
                            adminService.reconcileMaterialization(snapshot, capDigest, "usr-operator-1", Set.of())
                    );

                    // P8-R04: Operator with valid authority but unauthorized tenant scope -> denied (P43, P54)
                    assertThrows(SecurityException.class, () ->
                            adminService.reconcileMaterialization(
                                    snapshot,
                                    capDigest,
                                    "usr-operator-1",
                                    Set.of(GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY),
                                    Set.of("other-tenant-id")
                            )
                    );

                    // Valid reconcile authority and tenant scope -> activates bundle and records head
                    var outcome = adminService.reconcileMaterialization(
                            snapshot,
                            capDigest,
                            "usr-operator-1",
                            Set.of(GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY),
                            Set.of("tenant-gov-br")
                    );
                    assertTrue(outcome.bundleActivated());

                    // P8-R04: Head inspection requires administrative authority and matching tenant scope
                    assertThrows(SecurityException.class, () ->
                            adminService.findActiveRuntimeHead(
                                    "tenant-gov-br",
                                    "prod",
                                    "unit:pol-praxis-ergon-showcase-human-resources-afastamentos:v1",
                                    "usr-no-auth",
                                    Set.of(),
                                    Set.of("tenant-gov-br")
                            )
                    );
                    assertTrue(adminService.findActiveRuntimeHead(
                            "tenant-gov-br",
                            "prod",
                            "unit:pol-praxis-ergon-showcase-human-resources-afastamentos:v1",
                            "usr-operator-1",
                            Set.of(GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY),
                            Set.of("tenant-gov-br")
                    ).isPresent());
                });
    }
}
