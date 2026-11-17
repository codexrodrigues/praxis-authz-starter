package org.praxisplatform.authz.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.catalog.AdmittedInvocationChannel;
import org.praxisplatform.authz.catalog.FieldLineageCatalogEntry;
import org.praxisplatform.authz.catalog.MethodBindingAdmissionRecord;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.DataScopePlan;
import org.praxisplatform.authz.contracts.datascope.PushdownMode;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort;
import org.praxisplatform.authz.enforcement.writeintent.DtoWriteIntentExtractor;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;
import org.praxisplatform.authz.export.GovernedCollectionExportGuard;
import org.praxisplatform.authz.host.metadata.AuthzCallerContext;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider.CallerAvailabilityFactContext;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider.ResourceAvailabilityPolicyBinding;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector;
import org.praxisplatform.authz.host.metadata.ThreadLocalAuthzCallerContextProvider;
import org.praxisplatform.authz.pilot.WorkforceLeaveAuthzPilotBlueprint;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.authz.telemetry.SanitizedAuthorizationTelemetryPublisher;
import org.praxisplatform.config.ai.agent.bridge.DefaultMetadataGovernanceAgentAuthorizationBridge;
import org.praxisplatform.config.ai.agent.spi.AgentExecutionContext;
import org.praxisplatform.config.ai.agent.spi.AgentThreadContextPropagator;
import org.praxisplatform.config.ai.agent.spi.CompositeAgentThreadContextPropagator;
import org.praxisplatform.config.ai.agent.spi.DualProjectedPayload;
import org.praxisplatform.uischema.annotation.AiUsagePolicy;
import org.praxisplatform.uischema.annotation.AiVisibilityMode;
import org.praxisplatform.uischema.annotation.DomainClassification;
import org.praxisplatform.uischema.annotation.DomainGovernance;
import org.praxisplatform.uischema.capability.ResourceStateSnapshot;
import org.praxisplatform.uischema.extension.annotation.UISchema;

class AuthzAgentAuthorizationBridgeTest {

    public static class GovernedEmployeeRecordDto {
        @UISchema(label = "ID")
        public Long id;

        @UISchema(label = "Nome")
        @DomainGovernance(
                classification = DomainClassification.INTERNAL,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.ALLOW))
        public String fullName;

        @UISchema(label = "CPF")
        @DomainGovernance(
                classification = DomainClassification.CONFIDENTIAL,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.ALLOW))
        public String taxId;

        @UISchema(label = "Diagnostico")
        @DomainGovernance(
                classification = DomainClassification.RESTRICTED,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.DENY))
        public String medicalCode;

        public GovernedEmployeeRecordDto() {}
    }

    @Test
    void propagatesCallerContextSafelyToAsyncWorkerAndRestoresThreadLocal() throws Exception {
        ThreadLocalAuthzCallerContextProvider provider = new ThreadLocalAuthzCallerContextProvider();
        AuthzCallerContext caller = new AuthzCallerContext(
                "tenant-a",
                Map.of("subject.id", "alice", "subject.department", "hr"),
                Map.of(),
                Set.of("Authorization"),
                Map.of());

        CompositeAgentThreadContextPropagator composite = new CompositeAgentThreadContextPropagator(
                List.of(new AuthzAgentThreadContextPropagator(provider)));

        AgentThreadContextPropagator.Snapshot snapshot;
        try {
            provider.setContext(caller);
            snapshot = composite.captureAll();
        } finally {
            provider.clearContext();
        }

        AtomicReference<String> observedSubject = new AtomicReference<>();
        Thread worker = new Thread(() -> {
            try (AutoCloseable ignored = snapshot.attach()) {
                observedSubject.set(provider.currentCallerContext().subjectAndEnvironmentFacts().get("subject.id").toString());
            } catch (Exception ex) {
                throw new IllegalStateException(ex);
            } finally {
                assertTrue(provider.currentCallerContextOptional().isEmpty());
            }
        });
        worker.start();
        worker.join();

        assertEquals("alice", observedSubject.get());
        assertTrue(provider.currentCallerContextOptional().isEmpty());
    }

    @Test
    void enforcesOpaTargetMaskingAndFailsClosedOnDeny() {
        WorkforceLeaveAuthzPilotBlueprint blueprint = WorkforceLeaveAuthzPilotBlueprint.createHostBlueprint(
                "praxis-workforce-showcase",
                "hr.employees",
                "workforce.employees");
        MethodBindingAdmissionRecord baseRecord = blueprint.admissionRecords().getFirst();
        DecisionPointDescriptor descriptor = baseRecord.decisionPoint();
        String resourcePath = descriptor.canonicalPath();
        String registeredPointKey = descriptor.identity().pointKey();
        String fcDigest = blueprint.factContract().factContractDigest();
        String qpId = blueprint.queryProjection().projectionId();
        String qpDigest = blueprint.queryProjection().projectionDigest();
        String runtimeRev = blueprint.bundleArtifact().runtimeHead().runtimeRevision();
        String policyDigest = blueprint.bundleArtifact().runtimeHead().policySetDigest();

        List<FieldLineageCatalogEntry> lineage = List.of(
                new FieldLineageCatalogEntry(
                        "hr.employees.id", "concept:id", "schema://hr.employees/ResponseDTO",
                        "id", "READ_PROJECTION", "INTERNAL", "ALLOWED", true,
                        Set.of(FieldUseCategory.VALUE), List.of(), true),
                new FieldLineageCatalogEntry(
                        "hr.employees.full_name", "concept:name", "schema://hr.employees/ResponseDTO",
                        "fullName", "READ_PROJECTION", "INTERNAL", "ALLOWED", true,
                        Set.of(FieldUseCategory.VALUE), List.of(), true),
                new FieldLineageCatalogEntry(
                        "hr.employees.tax_id", "concept:taxId", "schema://hr.employees/ResponseDTO",
                        "taxId", "READ_PROJECTION", "CONFIDENTIAL", "ALLOWED", true,
                        Set.of(FieldUseCategory.VALUE), List.of(), true),
                new FieldLineageCatalogEntry(
                        "hr.employees.medical_code", "concept:health", "schema://hr.employees/ResponseDTO",
                        "medicalCode", "READ_PROJECTION", "HEALTH_SENSITIVE", "DENIED", false,
                        Set.of(FieldUseCategory.VALUE), List.of(), true));

        MethodBindingAdmissionRecord admissionRecord = new MethodBindingAdmissionRecord(
                baseRecord.serviceKey(),
                descriptor,
                baseRecord.enforcementBinding(),
                Set.of(AdmittedInvocationChannel.PROXIED_INTERNAL_SERVICE),
                true,
                lineage);

        RuntimeDecisionPointRegistry registry = new RuntimeDecisionPointRegistry(
                List.of(admissionRecord),
                blueprint.coordinates());

        AtomicReference<GateOutcome> nextOutcome = new AtomicReference<>(GateOutcome.ALLOW);
        AuthorizationProviderPort opaStub = new AuthorizationProviderPort() {
            @Override
            public ProviderEvaluationEnvelope evaluateTarget(
                    ProviderInputProjection input, org.praxisplatform.authz.contracts.binding.WriteIntent writeIntent) {
                GateOutcome outcome = nextOutcome.get();
                List<MaskDirective> masks = outcome == GateOutcome.ALLOW
                        ? List.of(new MaskDirective("hr.employees.tax_id", "REDACT_CONSTANT", Map.of("replacement", "***.***.***-25")))
                        : List.of();
                return new ProviderEvaluationEnvelope(
                        ProviderEvaluationEnvelope.SCHEMA_VERSION_V1,
                        "opa", "eval-1", registeredPointKey, EvaluationMode.TARGET,
                        "first-deny", runtimeRev, policyDigest, fcDigest, outcome,
                        List.of(), List.of(), masks, List.of(), List.of(), List.of(), List.of(),
                        Instant.now(), 100L);
            }

            @Override
            public SearchProviderEvaluationResult evaluateSearch(ProviderInputProjection input) {
                GateOutcome outcome = nextOutcome.get();
                ProviderEvaluationEnvelope env = new ProviderEvaluationEnvelope(
                        ProviderEvaluationEnvelope.SCHEMA_VERSION_V1,
                        "opa", "search-1", registeredPointKey, EvaluationMode.SEARCH,
                        "first-deny", runtimeRev, policyDigest, fcDigest, outcome,
                        List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
                        Instant.now(), 100L);
                DataScopePlan plan = new DataScopePlan(
                        DataScopePlan.FORMAT_V1,
                        "plan-1",
                        registeredPointKey,
                        "hr.employees",
                        runtimeRev,
                        policyDigest,
                        fcDigest,
                        qpId,
                        qpDigest,
                        outcome == GateOutcome.ALLOW ? DataScopeOutcome.ALL : DataScopeOutcome.NONE,
                        PushdownMode.FULL_PUSHDOWN,
                        null);
                return new SearchProviderEvaluationResult(env, plan);
            }
        };

        DetachedDtoMaskingProcessor maskingProcessor = new DetachedDtoMaskingProcessor();
        GovernedExportAndAiToolAuthorizationSeam seam = new GovernedExportAndAiToolAuthorizationSeam(
                registry,
                opaStub,
                new FieldUseQueryGuard(),
                maskingProcessor,
                new ObligationBarrierCoordinator(),
                new GovernedCollectionExportGuard(maskingProcessor),
                new SanitizedAuthorizationTelemetryPublisher(List.of(), 10));

        ThreadLocalAuthzCallerContextProvider callerProvider = new ThreadLocalAuthzCallerContextProvider();
        callerProvider.setContext(new AuthzCallerContext(
                "tenant-a",
                Map.of(
                        "subject.principalId", "alice",
                        "subject.organizationUnitIds", List.of(100L),
                        "resource.lotacaoSetorId", 100L),
                Map.of(
                        "subject.principalId", FactResolutionStatus.PRESENT,
                        "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                        "resource.lotacaoSetorId", FactResolutionStatus.PRESENT),
                Set.of(),
                Map.of()));

        MetadataResourceAuthorizationSeam metadataSeam = new MetadataResourceAuthorizationSeam(
                opaStub,
                new FieldUseQueryGuard(),
                new DtoWriteIntentExtractor(),
                new FieldWriteAuthorizer(),
                new DetachedDtoMaskingProcessor(),
                new ObligationBarrierCoordinator());
        AuthzResourceOperationAvailabilityProvider availabilityProvider =
                new AuthzResourceOperationAvailabilityProvider(metadataSeam);
        availabilityProvider.registerResourceBinding(new ResourceAvailabilityPolicyBinding(
                "hr.employees",
                descriptor,
                fcDigest,
                null,
                Map.of(),
                () -> new CallerAvailabilityFactContext(
                        Map.of(
                                "subject.principalId", "alice",
                                "subject.organizationUnitIds", List.of(100L)),
                        Map.of(
                                "subject.principalId", FactResolutionStatus.PRESENT,
                                "subject.organizationUnitIds", FactResolutionStatus.PRESENT),
                        false,
                        false,
                        "tenant-a"),
                snapshot -> snapshot.metadata(),
                id -> Optional.of(ResourceStateSnapshot.of("ACTIVE", Map.of("resource.lotacaoSetorId", 100L))),
                null,
                null));

        AuthzAgentAuthorizationBridge bridge = new AuthzAgentAuthorizationBridge(
                new DefaultMetadataGovernanceAgentAuthorizationBridge(),
                seam,
                registry,
                callerProvider,
                new MetadataDtoGovernanceIntrospector(),
                availabilityProvider,
                Map.of(resourcePath, registeredPointKey));

        AgentExecutionContext execContext = new AgentExecutionContext(
                UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
                "tenant-a", "alice", "prod", "alice", Set.of("ROLE_USER"),
                null, null, Map.of(), Map.of());

        Map<String, Object> rawRecord = Map.of(
                "id", 1001L,
                "fullName", "Carlos Silva",
                "taxId", "52998224725",
                "medicalCode", "ICD-Z00");

        assertTrue(bridge.canReadResource(execContext, resourcePath));
        assertTrue(bridge.canInvokeAction(execContext, resourcePath, "schedule-leave", 1001L));

        DualProjectedPayload allowed = bridge.projectRecord(
                execContext, resourcePath, GovernedEmployeeRecordDto.class, rawRecord);

        assertEquals("ICD-Z00", allowed.uiRecord().get("medicalCode"));
        assertFalse(allowed.modelSafeRecord().containsKey("medicalCode"));
        assertEquals("Carlos Silva", allowed.modelSafeRecord().get("fullName"));
        assertEquals("***.***.***-25", allowed.modelSafeRecord().get("taxId"));
        assertTrue(allowed.maskedForAiFields().contains("medicalCode"));
        assertTrue(allowed.maskedForAiFields().contains("taxId"));
        assertTrue(callerProvider.currentCallerContextOptional().isPresent());

        nextOutcome.set(GateOutcome.DENY);
        assertFalse(bridge.canReadResource(execContext, resourcePath));
        assertFalse(bridge.canInvokeAction(execContext, resourcePath, "schedule-leave", 1001L));
        assertThrows(SecurityException.class, () -> bridge.projectRecord(
                execContext, resourcePath, GovernedEmployeeRecordDto.class, rawRecord));

        callerProvider.clearContext();
    }
}
