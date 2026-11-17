package org.praxisplatform.authz.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzAutoConfiguration;
import org.praxisplatform.authz.catalog.AdmittedInvocationChannel;
import org.praxisplatform.authz.channel.GovernedChannelInvocationExecutor;
import org.praxisplatform.authz.compatibility.HostRuntimePolicyCoordinates;
import org.praxisplatform.authz.contracts.authority.EffectiveAuthorityBinding;
import org.praxisplatform.authz.contracts.authority.ExecutionDispositionMode;
import org.praxisplatform.authz.contracts.context.ContextCompositionProfile;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactResolutionStage;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.context.TemporalContext;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.decisionpoint.PointAuthorityMode;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.contracts.envelope.DecisionEvidence;
import org.praxisplatform.authz.contracts.envelope.EnforcementDisposition;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.enforcement.context.ContextCompositionCoordinator;
import org.praxisplatform.authz.enforcement.context.TrustedFactSource;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.jpa.QueryAdapterFieldBinding;
import org.praxisplatform.authz.enforcement.jpa.RelationTraversalStrategy;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor.RowMaskingInput;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.enforcement.pipeline.EnforcementPipelineExecutor;
import org.praxisplatform.authz.enforcement.pipeline.NormalizedEnforcementOutcome;
import org.praxisplatform.authz.export.GovernedCollectionExportGuard;
import org.praxisplatform.authz.export.GovernedCollectionExportGuard.ExportFormat;
import org.praxisplatform.authz.export.GovernedCollectionExportGuard.SanitizedExportArtifact;
import org.praxisplatform.authz.opa.client.OpaClientTransport;
import org.praxisplatform.authz.pilot.WorkforceLeaveAuthzPilotBlueprint;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * End-to-end conformance test proving that both the Workforce {@code Afastamento} showcase pilot and a
 * second non-Workforce host ({@code P22}) execute the complete Spring Boot auto-configured pipeline
 * (SEARCH pushdown, detached masking without entity mutation {@code P40}, and dual-scope metadata).
 */
class CrossHostPilotReuseAndDualScopeEndToEndTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PraxisAuthzAutoConfiguration.class));

    @Test
    void p22_p40_workforcePilotAndSecondHostExecuteFullAutoConfiguredPipeline() {
        verifyHostBlueprintExecution(
                WorkforceLeaveAuthzPilotBlueprint.createWorkforceLeaveBlueprint(),
                "vinculo.lotacao.id"
        );

        // P22: Second host uses the exact same starter and contracts without any Workforce classes or conventions!
        verifyHostBlueprintExecution(
                WorkforceLeaveAuthzPilotBlueprint.createHostBlueprint(
                        "praxis-fleet-service",
                        "fleet.vehicle-assignments",
                        "fleet.assignments"
                ),
                "garage.depot.id"
        );
    }

    private void verifyHostBlueprintExecution(
            WorkforceLeaveAuthzPilotBlueprint blueprint,
            String jpaColumnPath
    ) {
        TrustedFactSource extractSource = new TrustedFactSource() {
            @Override
            public FactResolutionStage stage() {
                return FactResolutionStage.EXTRACT;
            }

            @Override
            public Map<String, ResolvedFactValue> resolveFacts(
                    ContextEvaluationPhase phase,
                    Map<String, FactDescriptor> descriptorsToResolve,
                    Map<String, ResolvedFactValue> alreadyResolved
            ) {
                return Map.of("subject.principalId", ResolvedFactValue.present("subject.principalId", "usr-gestor-101"));
            }
        };

        TrustedFactSource enrichSource = new TrustedFactSource() {
            @Override
            public FactResolutionStage stage() {
                return FactResolutionStage.ENRICH;
            }

            @Override
            public Map<String, ResolvedFactValue> resolveFacts(
                    ContextEvaluationPhase phase,
                    Map<String, FactDescriptor> descriptorsToResolve,
                    Map<String, ResolvedFactValue> alreadyResolved
            ) {
                return Map.of("subject.organizationUnitIds",
                        ResolvedFactValue.present("subject.organizationUnitIds", List.of(101L, 102L)));
            }
        };

        contextRunner
                .withBean(OpaClientTransport.class, blueprint::localOpaTransport)
                .withBean(HostRuntimePolicyCoordinates.class, blueprint::coordinates)
                .withBean("extractFactSource", TrustedFactSource.class, () -> extractSource)
                .withBean("enrichFactSource", TrustedFactSource.class, () -> enrichSource)
                .run(context -> {
                    EnforcementPipelineExecutor executor = context.getBean(EnforcementPipelineExecutor.class);
                    ContextCompositionCoordinator coordinator = context.getBean(ContextCompositionCoordinator.class);
                    DetachedDtoMaskingProcessor maskingProcessor = context.getBean(DetachedDtoMaskingProcessor.class);

                    ContextCompositionProfile admissionProfile = new ContextCompositionProfile(
                            ContextCompositionProfile.SCHEMA_VERSION_V1,
                            "prof-" + blueprint.serviceKey(),
                            blueprint.decisionPoint().identity().pointKey(),
                            ContextEvaluationPhase.ADMISSION,
                            blueprint.factContract().factContractId(),
                            blueprint.factContract().factContractDigest(),
                            Set.of("subject.principalId", "subject.organizationUnitIds"),
                            Set.of(),
                            200L,
                            true
                    );

                    String scopeAttrId = blueprint.queryProjection().fieldsByPath()
                            .get("resource.lotacaoSetorId").attributeId();
                    JpaDataScopeAdapter jpaAdapter = new JpaDataScopeAdapter(
                            blueprint.queryProjection(),
                            List.of(new QueryAdapterFieldBinding(
                                    blueprint.resourceKey(),
                                    "resource.lotacaoSetorId",
                                    scopeAttrId,
                                    jpaColumnPath,
                                    RelationTraversalStrategy.INNER_JOIN_SCALAR,
                                    true
                            ))
                    );

                    EffectiveAuthorityBinding authorityBinding = new EffectiveAuthorityBinding(
                            "AUTHORITATIVE",
                            ExecutionDispositionMode.AUTHORITATIVE_EXECUTION,
                            PointAuthorityMode.AUTHORITATIVE
                    );

                    NormalizedEnforcementOutcome outcome = executor.executeSearchPipeline(
                            blueprint.enforcementBinding(),
                            authorityBinding,
                            true,
                            true,
                            Map.of(),
                            coordinator,
                            blueprint.factContract(),
                            admissionProfile,
                            new TemporalContext(Instant.now(), ZoneId.of("UTC")),
                            Set.of("subject.principalId", "subject.organizationUnitIds"),
                            Map.of(),
                            jpaAdapter,
                            "e.tenantId = :hardTenantId",
                            Map.of("hardTenantId", "tenant-1"),
                            row -> true,
                            Map.of()
                    );

                    assertTrue(outcome.isPermitted());
                    assertEquals(DataScopeOutcome.FILTER, outcome.dataScopeCriterion().scopeOutcome());
                    assertTrue(outcome.dataScopeCriterion().composedWhereClause()
                            .contains("e." + jpaColumnPath + " IN (:dspParam1)"));

                    // P40: Detached masking redacts sensitive attribute without mutating original source map
                    String sensitiveAttrId = blueprint.factContract().descriptorsByPath()
                            .get("resource.cidCodigo").attributeId();
                    Map<String, Object> rawRow = Map.of("id", 500L, "cidCodigo", "F32.1");
                    DetachedDtoMaskingResult masked = maskingProcessor.projectAndMask(
                            rawRow,
                            List.of(new DtoFieldSchemaMetadata("cidCodigo", sensitiveAttrId, FactValueType.STRING, false)),
                            Set.of(),
                            List.of(new MaskDirective(
                                    sensitiveAttrId,
                                    "REDACT_CONSTANT",
                                    Map.of("replacement", "***CID-RESTRITO***")
                            ))
                    );
                    assertEquals("F32.1", rawRow.get("cidCodigo"));
                    assertEquals("***CID-RESTRITO***", masked.detachedProjection().get("cidCodigo"));

                    // P4-R03 (P21, P26, P29, P34, P41, P42): GovernedChannelInvocationExecutor
                    GovernedChannelInvocationExecutor channelExecutor =
                            context.getBean(GovernedChannelInvocationExecutor.class);
                    var admissionRecord = blueprint.admissionRecords().getFirst();

                    // P41: Direct unproxied self-invocation is blocked!
                    var snap = coordinator.composeSnapshot(
                            blueprint.factContract(),
                            admissionProfile,
                            new TemporalContext(Instant.now(), ZoneId.of("UTC")),
                            Set.of()
                    );
                    assertThrows(SecurityException.class, () ->
                            channelExecutor.invokeAdmittedChannel(
                                    admissionRecord,
                                    AdmittedInvocationChannel.PROXIED_INTERNAL_SERVICE,
                                    false, // unproxied self-invocation!
                                    snap,
                                    () -> outcome,
                                    o -> "OK"
                            )
                    );

                    // P42: Outer endpoint PERMIT cannot skip inner point DENY!
                    NormalizedEnforcementOutcome deniedInner = new NormalizedEnforcementOutcome(
                            EnforcementDisposition.DENY,
                            new DecisionEvidence(
                                    "ev-deny",
                                    admissionRecord.decisionPoint().identity().pointKey(),
                                    org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode.TARGET,
                                    blueprint.coordinates().runtimeRelease().runtimeRevision(),
                                    blueprint.coordinates().runtimeRelease().policySetDigest(),
                                    blueprint.factContract().factContractDigest(),
                                    GateOutcome.DENY,
                                    EnforcementDisposition.DENY,
                                    Set.of("DENIED_INNER_STAGE"),
                                    Map.of(),
                                    Set.of(),
                                    Set.of(),
                                    Instant.now()
                            ),
                            null,
                            null,
                            List.of()
                    );
                    assertThrows(SecurityException.class, () ->
                            channelExecutor.invokeAdmittedChannel(
                                    admissionRecord,
                                    AdmittedInvocationChannel.PROXIED_INTERNAL_SERVICE,
                                    true,
                                    snap,
                                    () -> deniedInner,
                                    o -> "SHOULD_NOT_REACH"
                            )
                    );

                    // P21 & P26: Scoped artifact keys differ by principal/scope and prevent delimiter collision, and cache hit still re-evaluates authorization!
                    String keySubjA = channelExecutor.computeScopedArtifactKey(
                            admissionRecord.decisionPoint().identity().pointKey(),
                            "usr-a", "org-101", "rev-1", "pol-1", "500");
                    String keySubjB = channelExecutor.computeScopedArtifactKey(
                            admissionRecord.decisionPoint().identity().pointKey(),
                            "usr-b", "org-202", "rev-1", "pol-1", "500");
                    String keyDelim1 = channelExecutor.computeScopedArtifactKey(
                            admissionRecord.decisionPoint().identity().pointKey(),
                            "usr|admin", "org-1", "rev-1", "pol-1", "500");
                    String keyDelim2 = channelExecutor.computeScopedArtifactKey(
                            admissionRecord.decisionPoint().identity().pointKey(),
                            "usr", "admin|org-1", "rev-1", "pol-1", "500");
                    assertNotEquals(keySubjA, keySubjB);
                    assertNotEquals(keyDelim1, keyDelim2);

                    AtomicInteger repoLoadCount = new AtomicInteger(0);
                    AtomicInteger authzEvalCount = new AtomicInteger(0);
                    channelExecutor.getByIdWithCacheHitAuthorization(
                            blueprint.resourceKey(),
                            500L,
                            id -> {
                                repoLoadCount.incrementAndGet();
                                return rawRow;
                            },
                            entity -> {
                                authzEvalCount.incrementAndGet();
                                return outcome;
                            }
                    );
                    channelExecutor.getByIdWithCacheHitAuthorization(
                            blueprint.resourceKey(),
                            500L,
                            id -> {
                                repoLoadCount.incrementAndGet();
                                return rawRow;
                            },
                            entity -> {
                                authzEvalCount.incrementAndGet();
                                return outcome;
                            }
                    );
                    assertEquals(1, repoLoadCount.get()); // loaded once from repository
                    assertEquals(2, authzEvalCount.get()); // P26: authorized on BOTH cache miss and cache hit!

                    // P4-R04 (P11, P12, P18, P25, P60): GovernedCollectionExportGuard
                    GovernedCollectionExportGuard exportGuard =
                            context.getBean(GovernedCollectionExportGuard.class);
                    String substitutoAttrId = admissionRecord.fieldLineageEntries().get(2).attributeId();
                    List<DtoFieldSchemaMetadata> exportSchemas = List.of(
                            new DtoFieldSchemaMetadata("substitutoServidorId", substitutoAttrId, FactValueType.INT64, false),
                            new DtoFieldSchemaMetadata("cidCodigo", sensitiveAttrId, FactValueType.STRING, false)
                    );
                    List<RowMaskingInput> exportRows = List.of(
                            new RowMaskingInput(
                                    Map.of("substitutoServidorId", "=cmd|'/C calc',100", "cidCodigo", "F32.1"),
                                    Set.of(),
                                    List.of()
                            ),
                            new RowMaskingInput(
                                    Map.of("substitutoServidorId", 9001L, "cidCodigo", "F32.1"),
                                    Set.of(),
                                    List.of()
                            )
                    );
                    OpaRuntimeHead validHead = blueprint.bundleArtifact().runtimeHead();

                    SanitizedExportArtifact csvExport = exportGuard.exportCollection(
                            ExportFormat.CSV,
                            validHead.runtimeRevision(),
                            validHead.policySetDigest(),
                            () -> validHead,
                            exportSchemas,
                            admissionRecord.fieldLineageEntries(),
                            exportRows
                    );
                    String csvText = new String(csvExport.bytes(), StandardCharsets.UTF_8);
                    // P11, P25, P60: cidCodigo has exportable=false in lineage catalog, so neither column nor value "F32.1" may appear in CSV bytes!
                    assertFalse(csvExport.exportedColumns().contains("cidCodigo"));
                    assertFalse(csvText.contains("F32.1"));
                    assertTrue(csvText.contains("9001"));
                    // Formula injection and comma delimiter in cell are neutralized and quoted per RFC 4180
                    assertTrue(csvText.contains("\"'=cmd|'/C calc',100\""));

                    // P18: Policy revoked or rotated during export stream -> fails closed!
                    OpaRuntimeHead revokedHead = new OpaRuntimeHead(
                            validHead.instanceId(),
                            "rev-revoked-99",
                            "etag-99",
                            99L,
                            validHead.policySetDigest(),
                            validHead.bundleArtifactDigest(),
                            validHead.compilerProfileVersion(),
                            validHead.opaCapabilitiesDigest()
                    );
                    assertThrows(SecurityException.class, () ->
                            exportGuard.exportCollection(
                                    ExportFormat.JSON,
                                    validHead.runtimeRevision(),
                                    validHead.policySetDigest(),
                                    () -> revokedHead,
                                    exportSchemas,
                                    admissionRecord.fieldLineageEntries(),
                                    exportRows
                            )
                    );
                });
    }
}
