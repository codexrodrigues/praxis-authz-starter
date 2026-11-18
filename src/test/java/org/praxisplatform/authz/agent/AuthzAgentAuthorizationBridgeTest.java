package org.praxisplatform.authz.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzAgentBridgeAutoConfiguration;
import org.praxisplatform.config.autoconfig.OperationalAgentAutoConfiguration;
import org.praxisplatform.config.ai.agent.spi.AgentAuthorizationBridge;
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
import org.praxisplatform.uischema.action.ActionRequirement;
import org.praxisplatform.uischema.action.ActionRiskLevel;
import org.praxisplatform.uischema.action.ActionScope;
import org.praxisplatform.uischema.annotation.AiUsagePolicy;
import org.praxisplatform.uischema.annotation.AiVisibilityMode;
import org.praxisplatform.uischema.annotation.ApiResource;
import org.praxisplatform.uischema.annotation.DomainClassification;
import org.praxisplatform.uischema.annotation.DomainGovernance;
import org.praxisplatform.uischema.annotation.DomainGovernancePreset;
import org.praxisplatform.uischema.annotation.WorkflowAction;
import org.praxisplatform.uischema.capability.ResourceStateSnapshot;
import org.praxisplatform.uischema.concurrency.ResourceRepresentationResult;
import org.praxisplatform.uischema.controller.base.AbstractResourceQueryController;
import org.praxisplatform.uischema.dto.CursorPage;
import org.praxisplatform.uischema.dto.OptionDTO;
import org.praxisplatform.uischema.extension.annotation.UISchema;
import org.praxisplatform.uischema.filter.dto.GenericFilterDTO;
import org.praxisplatform.uischema.options.OptionSourceDescriptor;
import org.praxisplatform.uischema.options.OptionSourceFilterRequest;
import org.praxisplatform.uischema.options.OptionSourceRegistry;
import org.praxisplatform.uischema.service.base.BaseResourceQueryService;
import org.praxisplatform.uischema.stats.StatsFieldRegistry;
import org.praxisplatform.uischema.stats.StatsSupportMode;
import org.praxisplatform.uischema.stats.dto.ComparisonStatsRequest;
import org.praxisplatform.uischema.stats.dto.ComparisonStatsResponse;
import org.praxisplatform.uischema.stats.dto.DistributionStatsRequest;
import org.praxisplatform.uischema.stats.dto.DistributionStatsResponse;
import org.praxisplatform.uischema.stats.dto.GroupByStatsRequest;
import org.praxisplatform.uischema.stats.dto.GroupByStatsResponse;
import org.praxisplatform.uischema.stats.dto.TimeSeriesStatsRequest;
import org.praxisplatform.uischema.stats.dto.TimeSeriesStatsResponse;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

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

    public static class RestrictedActionInputDto {
        @UISchema(label = "Observacao", editableForAuthorities = {"ROLE_WRITE", "ROLE_ADMIN"})
        public String note;

        @UISchema(label = "Codigo de alcada", editableForAuthorities = {"ROLE_ADMIN"})
        public String approvalCode;
    }

    public static class RestrictedItemDto {
        public Long id;
        @UISchema(label = "Nome")
        public String name;
        public Long getId() { return id; }
        public String getName() { return name; }
    }

    public static class EmptyFilterDto implements GenericFilterDTO {
    }

    @ApiResource(value = "/api/workforce/restricted-approvals", resourceKey = "wf.restricted-approvals", title = "Aprovacoes")
    static class RestrictedWorkflowController extends AbstractResourceQueryController<RestrictedItemDto, Long, EmptyFilterDto> {
        private final BaseResourceQueryService<RestrictedItemDto, Long, EmptyFilterDto> service = new BaseResourceQueryService<>() {
            @Override public String getIdFieldName() { return "id"; }
            @Override public Sort getDefaultSort() { return Sort.by("id"); }
            @Override public Optional<String> getDatasetVersion() { return Optional.empty(); }
            @Override public StatsSupportMode getGroupByStatsSupportMode() { return StatsSupportMode.DISABLED; }
            @Override public StatsSupportMode getTimeSeriesStatsSupportMode() { return StatsSupportMode.DISABLED; }
            @Override public StatsSupportMode getDistributionStatsSupportMode() { return StatsSupportMode.DISABLED; }
            @Override public StatsFieldRegistry getStatsFieldRegistry() { return null; }
            @Override public OptionSourceRegistry getOptionSourceRegistry() { return null; }
            @Override public boolean hasOptionSource(String key) { return false; }
            @Override public OptionSourceDescriptor resolveOptionSource(String key) { return null; }
            @Override public List<RestrictedItemDto> findAll() { return List.of(); }
            @Override public List<RestrictedItemDto> findAllById(Collection<Long> ids) { return List.of(); }
            @Override public ResourceRepresentationResult<RestrictedItemDto> findById(Long id) { return null; }
            @Override public Page<RestrictedItemDto> filter(EmptyFilterDto f, Pageable p, Collection<Long> ids) { return Page.empty(); }
            @Override public CursorPage<RestrictedItemDto> filterByCursor(EmptyFilterDto f, Sort s, String a, String c, int l) { return null; }
            @Override public java.util.OptionalLong locate(EmptyFilterDto f, Sort s, Long id) { return java.util.OptionalLong.empty(); }
            @Override public Page<OptionDTO<Long>> filterOptions(EmptyFilterDto f, Pageable p) { return Page.empty(); }
            @Override public List<OptionDTO<Long>> byIdsOptions(Collection<Long> ids) { return List.of(); }
            @Override public Page<OptionDTO<Object>> filterOptionSourceOptions(String k, OptionSourceFilterRequest<EmptyFilterDto> r, Pageable p) { return Page.empty(); }
            @Override public List<OptionDTO<Object>> byIdsOptionSourceOptions(String k, Collection<Object> ids) { return List.of(); }
            @Override public GroupByStatsResponse groupByStats(GroupByStatsRequest<EmptyFilterDto> r) { return null; }
            @Override public TimeSeriesStatsResponse timeSeriesStats(TimeSeriesStatsRequest<EmptyFilterDto> r) { return null; }
            @Override public DistributionStatsResponse distributionStats(DistributionStatsRequest<EmptyFilterDto> r) { return null; }
            @Override public ComparisonStatsResponse comparisonStats(ComparisonStatsRequest<EmptyFilterDto> r) { return null; }
        };

        @PostMapping("/{id}/actions/approve-restricted")
        @WorkflowAction(
                id = "approve-restricted",
                title = "Aprovar com alcada",
                scope = ActionScope.ITEM,
                requiredAuthorities = {"ROLE_ADMIN"},
                resourceVersion = ActionRequirement.OPTIONAL,
                riskLevel = ActionRiskLevel.HIGH)
        public ResponseEntity<RestrictedItemDto> approveRestricted(
                @PathVariable Long id,
                @RequestBody RestrictedActionInputDto input) {
            return ResponseEntity.ok(new RestrictedItemDto());
        }

        @Override protected BaseResourceQueryService<RestrictedItemDto, Long, EmptyFilterDto> getService() { return service; }
        @Override protected Long getResponseId(RestrictedItemDto dto) { return dto.id; }
    }

    @Test
    void autoConfigurationOrderingWiresControllerIndexedMetadataFallbackAndEnforcesFields() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        OperationalAgentAutoConfiguration.class,
                        PraxisAuthzAgentBridgeAutoConfiguration.class))
                .withBean(ObjectMapper.class, () -> new ObjectMapper().findAndRegisterModules())
                .withBean(RestrictedWorkflowController.class, RestrictedWorkflowController::new)
                .run(context -> {
                    assertNull(context.getStartupFailure());
                    AgentAuthorizationBridge primary = context.getBean(AgentAuthorizationBridge.class);
                    assertInstanceOf(AuthzAgentAuthorizationBridge.class, primary);

                    AgentExecutionContext readerCtx = new AgentExecutionContext(
                            UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
                            "tenant-a", "reader", "prod", "reader", Set.of("ROLE_READER"),
                            null, null, Map.of(), Map.of());
                    AgentExecutionContext adminCtx = new AgentExecutionContext(
                            UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
                            "tenant-a", "admin", "prod", "admin", Set.of("ROLE_ADMIN"),
                            null, null, Map.of(), Map.of());

                    String resourcePath = "/api/workforce/restricted-approvals";
                    assertFalse(primary.canInvokeAction(readerCtx, resourcePath, "approve-restricted", 1L));
                    assertFalse(primary.canModifyFields(readerCtx, resourcePath, RestrictedActionInputDto.class, Set.of("approvalCode")));

                    assertTrue(primary.canInvokeAction(adminCtx, resourcePath, "approve-restricted", 1L));
                    assertTrue(primary.canModifyFields(adminCtx, resourcePath, RestrictedActionInputDto.class, Set.of("approvalCode")));
                });
    }

    public static class RedTeamPresetGovernedDto {
        @UISchema(label = "ID")
        public Long id;

        @UISchema(label = "Nome")
        @DomainGovernance(
                classification = DomainClassification.INTERNAL,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.ALLOW))
        public String fullName;

        @UISchema(label = "CPF")
        @DomainGovernance(preset = DomainGovernancePreset.LGPD_PERSONAL_ID)
        public String personalTaxId;

        @UISchema(label = "Diagnostico")
        @DomainGovernance(preset = DomainGovernancePreset.LGPD_SENSITIVE_DATA)
        public String sensitiveHealthCode;
    }

    @Test
    void introspectorMapsAllowMaskDenyModesAndOpaSeamNeverUnmasksMetadataMaskedFields() {
        MetadataDtoGovernanceIntrospector introspector = new MetadataDtoGovernanceIntrospector();
        List<FieldLineageCatalogEntry> entries = introspector.deriveDtoFieldLineageCatalogEntries(
                "hr.employees", RedTeamPresetGovernedDto.class, "READ_PROJECTION", null);

        Map<String, String> modesByWire = new java.util.LinkedHashMap<>();
        for (FieldLineageCatalogEntry entry : entries) {
            modesByWire.put(entry.wirePath(), entry.aiUsageMode());
        }
        assertEquals("SCHEMA_METADATA_ONLY", modesByWire.get("id"));
        assertEquals("ALLOWED", modesByWire.get("fullName"));
        assertEquals("MASKED_ONLY", modesByWire.get("personalTaxId"));
        assertEquals("DENIED", modesByWire.get("sensitiveHealthCode"));

        WorkforceLeaveAuthzPilotBlueprint blueprint = WorkforceLeaveAuthzPilotBlueprint.createHostBlueprint(
                "praxis-workforce-showcase", "hr.employees", "workforce.employees");
        MethodBindingAdmissionRecord baseRecord = blueprint.admissionRecords().getFirst();
        DecisionPointDescriptor descriptor = baseRecord.decisionPoint();
        String registeredPointKey = descriptor.identity().pointKey();
        String runtimeRev = blueprint.bundleArtifact().runtimeHead().runtimeRevision();
        String policyDigest = blueprint.bundleArtifact().runtimeHead().policySetDigest();
        String fcDigest = blueprint.factContract().factContractDigest();

        // Simulate OPA policy admitting fullName and tax_id as ALLOWED without OPA-level MaskDirective;
        // AuthzAgentAuthorizationBridge must pass metadataDelegate's already-masked modelSafeRecord so raw tax_id is never restored.
        List<FieldLineageCatalogEntry> permissiveOpaLineage = List.of(
                new FieldLineageCatalogEntry(
                        "hr.employees.full_name", "concept:name", "schema://hr.employees/ResponseDTO",
                        "fullName", "READ_PROJECTION", "INTERNAL", "ALLOWED", true,
                        Set.of(FieldUseCategory.VALUE), List.of(), true),
                new FieldLineageCatalogEntry(
                        "hr.employees.personal_tax_id", "concept:taxId", "schema://hr.employees/ResponseDTO",
                        "personalTaxId", "READ_PROJECTION", "PII_RESTRICTED", "ALLOWED", true,
                        Set.of(FieldUseCategory.VALUE), List.of(), true));
        MethodBindingAdmissionRecord admissionRecord = new MethodBindingAdmissionRecord(
                baseRecord.serviceKey(), descriptor, baseRecord.enforcementBinding(),
                Set.of(AdmittedInvocationChannel.PROXIED_INTERNAL_SERVICE), true, permissiveOpaLineage);
        RuntimeDecisionPointRegistry registry = new RuntimeDecisionPointRegistry(
                List.of(admissionRecord), blueprint.coordinates());

        AuthorizationProviderPort permissiveOpa = new AuthorizationProviderPort() {
            @Override
            public ProviderEvaluationEnvelope evaluateTarget(
                    ProviderInputProjection input, org.praxisplatform.authz.contracts.binding.WriteIntent writeIntent) {
                return new ProviderEvaluationEnvelope(
                        ProviderEvaluationEnvelope.SCHEMA_VERSION_V1,
                        "opa", "eval-allow-all", registeredPointKey, EvaluationMode.TARGET,
                        "first-deny", runtimeRev, policyDigest, fcDigest, GateOutcome.ALLOW,
                        List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
                        Instant.now(), 100L);
            }

            @Override
            public SearchProviderEvaluationResult evaluateSearch(ProviderInputProjection input) {
                throw new UnsupportedOperationException();
            }
        };

        DetachedDtoMaskingProcessor maskingProcessor = new DetachedDtoMaskingProcessor();
        GovernedExportAndAiToolAuthorizationSeam seam = new GovernedExportAndAiToolAuthorizationSeam(
                registry, permissiveOpa, new FieldUseQueryGuard(), maskingProcessor,
                new ObligationBarrierCoordinator(), new GovernedCollectionExportGuard(maskingProcessor),
                new SanitizedAuthorizationTelemetryPublisher(List.of(), 10));

        AuthzAgentAuthorizationBridge bridge = new AuthzAgentAuthorizationBridge(
                new DefaultMetadataGovernanceAgentAuthorizationBridge(),
                seam, registry, null, introspector, null,
                Map.of(descriptor.canonicalPath(), registeredPointKey));

        AgentExecutionContext execContext = new AgentExecutionContext(
                UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
                "tenant-a", "alice", "prod", "alice", Set.of("ROLE_USER"),
                null, null, Map.of(), Map.of());

        DualProjectedPayload projected = bridge.projectRecord(
                execContext,
                descriptor.canonicalPath() + "/",
                RedTeamPresetGovernedDto.class,
                Map.of(
                        "id", 1L,
                        "fullName", "Mariana Souza",
                        "personalTaxId", "52998224725",
                        "sensitiveHealthCode", "CID-Z99"));

        assertEquals("52998224725", projected.uiRecord().get("personalTaxId"));
        assertEquals("Mariana Souza", projected.modelSafeRecord().get("fullName"));
        assertFalse(projected.modelSafeRecord().containsKey("sensitiveHealthCode"));
        assertTrue(projected.modelSafeRecord().containsKey("personalTaxId"));
        assertFalse(projected.modelSafeRecord().get("personalTaxId").toString().contains("52998224725"));
    }
}
