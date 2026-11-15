package org.praxisplatform.authz.seams;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode;
import org.praxisplatform.authz.contracts.binding.TransactionCardinality;
import org.praxisplatform.authz.contracts.binding.WriteChangeKind;
import org.praxisplatform.authz.contracts.binding.WriteFieldChange;
import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.context.TemporalContext;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.DataScopePlan;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.decisionpoint.PointAuthorityMode;
import org.praxisplatform.authz.contracts.envelope.EnforcementDisposition;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.contracts.obligation.ObligationFulfillmentBarrier;
import org.praxisplatform.authz.contracts.obligation.ObligationFulfillmentResult;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;
import org.praxisplatform.authz.enforcement.context.UntrustedRequestHeaderGuard;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.jpa.CompiledDataScopeCriterion;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor.RowMaskingInput;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort.SearchProviderEvaluationResult;
import org.praxisplatform.authz.enforcement.writeintent.DtoWriteIntentExtractor;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteViolationException;
import org.praxisplatform.authz.host.metadata.AuthzAccessDeniedException;
import org.praxisplatform.authz.host.metadata.AuthzProviderUnavailableException;
import org.praxisplatform.authz.telemetry.SanitizedAuthorizationTelemetryPublisher;

/**
 * Canonical integration seam bridging {@code praxis-metadata-starter} resource services and
 * controllers ({@code AbstractBaseQueryResourceService}, {@code AbstractBaseResourceService},
 * {@code GovernedResourceCommandExecutor}, {@code BulkDurableWorker}, and
 * {@code ResourceOperationAvailabilityEvaluator}) to the 15-step authorization pipeline
 * ({@code P01..P19}, {@code P23}, {@code P34}, {@code P35}, {@code P40}, {@code P50}).
 */
public final class MetadataResourceAuthorizationSeam {

    /** Compiled query authorization context returned to {@code AbstractBaseQueryResourceService}. */
    public record AuthorizedQueryScopeContext(
            String decisionPointKey,
            String runtimeRevision,
            String policySetDigest,
            DataScopeOutcome scopeOutcome,
            DataScopePlan dataScopePlan,
            CompiledDataScopeCriterion compiledJpaDataScope,
            Set<String> valueDeniedAttributeIds,
            List<MaskDirective> maskDirectives,
            List<FieldUseEffectDirective> combinedFieldUseDirectives
    ) {
        public AuthorizedQueryScopeContext {
            combinedFieldUseDirectives = combinedFieldUseDirectives == null
                    ? List.of()
                    : List.copyOf(combinedFieldUseDirectives);
        }

        public AuthorizedQueryScopeContext(
                String decisionPointKey,
                String runtimeRevision,
                String policySetDigest,
                DataScopeOutcome scopeOutcome,
                DataScopePlan dataScopePlan,
                CompiledDataScopeCriterion compiledJpaDataScope,
                Set<String> valueDeniedAttributeIds,
                List<MaskDirective> maskDirectives
        ) {
            this(
                    decisionPointKey,
                    runtimeRevision,
                    policySetDigest,
                    scopeOutcome,
                    dataScopePlan,
                    compiledJpaDataScope,
                    valueDeniedAttributeIds,
                    maskDirectives,
                    List.of()
            );
        }

        public AuthorizedQueryScopeContext(
                String decisionPointKey,
                String runtimeRevision,
                String policySetDigest,
                DataScopeOutcome scopeOutcome,
                CompiledDataScopeCriterion compiledJpaDataScope,
                Set<String> valueDeniedAttributeIds,
                List<MaskDirective> maskDirectives
        ) {
            this(
                    decisionPointKey,
                    runtimeRevision,
                    policySetDigest,
                    scopeOutcome,
                    null,
                    compiledJpaDataScope,
                    valueDeniedAttributeIds,
                    maskDirectives,
                    List.of()
            );
        }
    }

    /**
     * Live {@code TARGET} read/preview evaluation result carrying active OPA {@link MaskDirective}s,
     * dynamically value-denied attributes, and dynamically field-write-denied attributes for
     * non-persistent reactive determinations, assisted {@code DuplicateDraft} cloning, and AI
     * context projections ({@code Fase P10.6}, {@code Fase P10.17}, {@code P11}, {@code P12}, {@code P47}, {@code P50}).
     *
     * @param decisionPointKey canonical decision point key
     * @param runtimeRevision active OPA runtime revision
     * @param policySetDigest active policy set digest
     * @param valueDeniedAttributeIds attribute IDs dynamically denied for {@link FieldUseCategory#VALUE}
     * @param maskDirectives active OPA mask directives for the target item
     * @param fieldWriteDeniedAttributeIds attribute IDs dynamically denied for {@code FIELD_WRITE}
     */
    public record TargetReadProjectionEvaluation(
            String decisionPointKey,
            String runtimeRevision,
            String policySetDigest,
            Set<String> valueDeniedAttributeIds,
            List<MaskDirective> maskDirectives,
            Set<String> fieldWriteDeniedAttributeIds
    ) {
        public TargetReadProjectionEvaluation {
            valueDeniedAttributeIds = valueDeniedAttributeIds == null ? Set.of() : Set.copyOf(valueDeniedAttributeIds);
            maskDirectives = maskDirectives == null ? List.of() : List.copyOf(maskDirectives);
            fieldWriteDeniedAttributeIds = fieldWriteDeniedAttributeIds == null
                    ? Set.of()
                    : Set.copyOf(fieldWriteDeniedAttributeIds);
        }

        public TargetReadProjectionEvaluation(
                String decisionPointKey,
                String runtimeRevision,
                String policySetDigest,
                Set<String> valueDeniedAttributeIds,
                List<MaskDirective> maskDirectives
        ) {
            this(
                    decisionPointKey,
                    runtimeRevision,
                    policySetDigest,
                    valueDeniedAttributeIds,
                    maskDirectives,
                    Set.of()
            );
        }

        /**
         * Merges this evaluation with a secondary operation evaluation, combining all denied
         * attribute IDs and mask directives ({@code Fase P10.17-A}).
         */
        public TargetReadProjectionEvaluation mergeWith(TargetReadProjectionEvaluation secondary) {
            if (secondary == null) {
                return this;
            }
            Set<String> mergedValueDenied = new LinkedHashSet<>(this.valueDeniedAttributeIds);
            mergedValueDenied.addAll(secondary.valueDeniedAttributeIds());
            List<MaskDirective> mergedMasks = new ArrayList<>(this.maskDirectives);
            mergedMasks.addAll(secondary.maskDirectives());
            Set<String> mergedFieldWriteDenied = new LinkedHashSet<>(this.fieldWriteDeniedAttributeIds);
            mergedFieldWriteDenied.addAll(secondary.fieldWriteDeniedAttributeIds());
            return new TargetReadProjectionEvaluation(
                    secondary.decisionPointKey(),
                    secondary.runtimeRevision(),
                    secondary.policySetDigest(),
                    mergedValueDenied,
                    mergedMasks,
                    mergedFieldWriteDenied
            );
        }
    }

    /** Pre-hydration write authorization context returned to {@code AbstractBaseResourceService} before {@code hydrate*} and {@code PraxisRulesEngine}. */
    public record AuthorizedPreMutationContext(
            String decisionPointKey,
            String runtimeRevision,
            String policySetDigest,
            WriteIntent writeIntent,
            ProviderEvaluationEnvelope targetEnvelope,
            Set<String> valueDeniedAttributeIds,
            List<MaskDirective> maskDirectives,
            List<ObligationDirective> obligations
    ) {}

    /** Authenticated delegation token required by {@code BulkDurableWorker} (rejecting raw HTTP header maps per {@code P02}, {@code P15}, {@code P18}). */
    public record WorkerDelegationToken(
            String workerServiceId,
            String delegatedPrincipalId,
            String tenantId,
            String audience,
            Instant expiresAt,
            String pinnedPolicySetDigest,
            Map<String, Object> minimalSubjectFacts
    ) {
        public WorkerDelegationToken {
            Objects.requireNonNull(workerServiceId, "workerServiceId is required");
            Objects.requireNonNull(delegatedPrincipalId, "delegatedPrincipalId is required");
            Objects.requireNonNull(tenantId, "tenantId is required");
            Objects.requireNonNull(audience, "audience is required");
            Objects.requireNonNull(expiresAt, "expiresAt is required");
            Objects.requireNonNull(pinnedPolicySetDigest, "pinnedPolicySetDigest is required");
            minimalSubjectFacts = minimalSubjectFacts == null ? Map.of() : Map.copyOf(minimalSubjectFacts);
        }
    }

    /** Advisory operation availability projection for HATEOAS {@code _links} and {@code /capabilities} ({@code P10}, {@code P17}). */
    public record AdvisoryOperationAvailability(
            String decisionPointKey,
            boolean allowedInDiscovery,
            boolean advisoryOnly,
            boolean requiresRuntimeRevalidation,
            String observedPolicyRevision
    ) {}

    private final AuthorizationProviderPort providerPort;
    private final FieldUseQueryGuard fieldUseQueryGuard;
    private final DtoWriteIntentExtractor writeIntentExtractor;
    private final FieldWriteAuthorizer fieldWriteAuthorizer;
    private final DetachedDtoMaskingProcessor maskingProcessor;
    private final ObligationBarrierCoordinator obligationCoordinator;
    private final SanitizedAuthorizationTelemetryPublisher telemetryPublisher;

    public MetadataResourceAuthorizationSeam(
            AuthorizationProviderPort providerPort,
            FieldUseQueryGuard fieldUseQueryGuard,
            DtoWriteIntentExtractor writeIntentExtractor,
            FieldWriteAuthorizer fieldWriteAuthorizer,
            DetachedDtoMaskingProcessor maskingProcessor,
            ObligationBarrierCoordinator obligationCoordinator
    ) {
        this(
                providerPort,
                fieldUseQueryGuard,
                writeIntentExtractor,
                fieldWriteAuthorizer,
                maskingProcessor,
                obligationCoordinator,
                null
        );
    }

    public MetadataResourceAuthorizationSeam(
            AuthorizationProviderPort providerPort,
            FieldUseQueryGuard fieldUseQueryGuard,
            DtoWriteIntentExtractor writeIntentExtractor,
            FieldWriteAuthorizer fieldWriteAuthorizer,
            DetachedDtoMaskingProcessor maskingProcessor,
            ObligationBarrierCoordinator obligationCoordinator,
            SanitizedAuthorizationTelemetryPublisher telemetryPublisher
    ) {
        this.providerPort = Objects.requireNonNull(providerPort, "providerPort is required");
        this.fieldUseQueryGuard = Objects.requireNonNull(fieldUseQueryGuard, "fieldUseQueryGuard is required");
        this.writeIntentExtractor = Objects.requireNonNull(writeIntentExtractor, "writeIntentExtractor is required");
        this.fieldWriteAuthorizer = Objects.requireNonNull(fieldWriteAuthorizer, "fieldWriteAuthorizer is required");
        this.maskingProcessor = Objects.requireNonNull(maskingProcessor, "maskingProcessor is required");
        this.obligationCoordinator = Objects.requireNonNull(obligationCoordinator, "obligationCoordinator is required");
        this.telemetryPublisher = telemetryPublisher;
    }

    /**
     * Seam for {@code AbstractBaseQueryResourceService}: guards untrusted headers, validates
     * {@code FIELD_USE} categories ({@code FILTER}, {@code SORT}, {@code GROUP}, {@code AGGREGATE}, {@code JOIN}),
     * evaluates {@code SEARCH} on OPA, and compiles the {@link CompiledDataScopeCriterion} ({@code hardScopeJpql AND policyJpql}).
     */
    public AuthorizedQueryScopeContext authorizeAndCompileJpaQueryScope(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            Set<String> incomingHeaderNames,
            Map<String, Object> trustedSubjectFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses,
            Map<FieldUseCategory, Set<String>> requestedQueryFieldUses,
            List<FieldUseEffectDirective> staticFieldUseDirectives,
            JpaDataScopeAdapter jpaDataScopeAdapter,
            String hardScopeJpql,
            Map<String, Object> hardScopeParameters,
            Predicate<Map<String, ResolvedFactValue>> targetParityOracle
    ) {
        if (incomingHeaderNames != null && !incomingHeaderNames.isEmpty()) {
            Map<String, String> headerProbe = new LinkedHashMap<>();
            for (String h : incomingHeaderNames) {
                headerProbe.put(h, "__untrusted_client_header_probe__");
            }
            UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                    headerProbe,
                    toAuthoritativeSubjectFactMap(trustedSubjectFacts, trustedFactStatuses)
            );
        }
        List<FieldUseEffectDirective> initialDirectives = staticFieldUseDirectives == null ? List.of() : staticFieldUseDirectives;
        fieldUseQueryGuard.guardQueryFieldUses(requestedQueryFieldUses, initialDirectives);

        ProviderInputProjection searchInput = new ProviderInputProjection(
                ProviderInputProjection.SCHEMA_VERSION_V1,
                decisionPoint.identity().pointKey(),
                "SEARCH",
                factContractDigest,
                new TemporalContext(Instant.now(), ZoneOffset.UTC),
                trustedSubjectFacts,
                trustedFactStatuses,
                Set.of()
        );

        SearchProviderEvaluationResult searchResult = providerPort.evaluateSearch(searchInput);
        ProviderEvaluationEnvelope envelope = searchResult.admissionEnvelope();
        publishTelemetryIfConfigured(trustedSubjectFacts, decisionPoint, envelope);
        if (envelope.gateOutcome() != GateOutcome.ALLOW) {
            fulfillDenyObligations(decisionPoint.identity().pointKey(), envelope);
            throw toGateFailureException(
                    "AUTHZ_QUERY_SEAM_DENIED",
                    decisionPoint.identity().pointKey(),
                    envelope.gateOutcome(),
                    "AUTHZ_QUERY_SEAM_DENIED: " + envelope.gateOutcome()
            );
        }

        List<FieldUseEffectDirective> combinedDirectives = new ArrayList<>(initialDirectives);
        combinedDirectives.addAll(envelope.combinedFieldUseEffects());
        try {
            fieldUseQueryGuard.guardQueryFieldUses(requestedQueryFieldUses, combinedDirectives);
        } catch (RuntimeException ex) {
            fulfillDenyObligations(decisionPoint.identity().pointKey(), envelope);
            throw ex;
        }

        DataScopePlan plan = searchResult.dataScopePlan();
        if (plan == null || plan.scopeOutcome() == DataScopeOutcome.NONE) {
            return new AuthorizedQueryScopeContext(
                    decisionPoint.identity().pointKey(),
                    envelope.runtimeRevision(),
                    envelope.policySetDigest(),
                    DataScopeOutcome.NONE,
                    plan,
                    null,
                    fieldUseQueryGuard.extractValueDeniedAttributeIds(combinedDirectives),
                    envelope.combinedMaskDirectives(),
                    List.copyOf(combinedDirectives)
            );
        }

        CompiledDataScopeCriterion compiledScope = jpaDataScopeAdapter.compile(
                plan,
                hardScopeJpql,
                hardScopeParameters,
                targetParityOracle
        );

        return new AuthorizedQueryScopeContext(
                decisionPoint.identity().pointKey(),
                envelope.runtimeRevision(),
                envelope.policySetDigest(),
                plan.scopeOutcome(),
                plan,
                compiledScope,
                fieldUseQueryGuard.extractValueDeniedAttributeIds(combinedDirectives),
                envelope.combinedMaskDirectives(),
                List.copyOf(combinedDirectives)
        );
    }

    /**
     * Evaluates query field-use eligibility ({@code FILTER}, {@code SORT}, {@code GROUP},
     * {@code AGGREGATE}, {@code JOIN}) against both static {@code @DomainGovernance} baseline
     * directives and live {@code SEARCH} evaluation {@link FieldUseEffectDirective}s without
     * requiring a JPA {@link JpaDataScopeAdapter} ({@code Fase P10.18-B}, {@code P13}, {@code P14}, {@code P50}).
     *
     * @param decisionPoint search decision point descriptor
     * @param factContractDigest fact contract digest
     * @param trustedSubjectFacts authoritative subject and environment facts
     * @param trustedFactStatuses fact resolution statuses
     * @param requestedQueryFieldUses requested attributes by {@link FieldUseCategory}
     * @param staticFieldUseDirectives static baseline field-use directives
     * @return immutable combined list of static and dynamic {@link FieldUseEffectDirective}s
     * @throws org.praxisplatform.authz.enforcement.fielduse.FieldUseViolationException if any requested attribute is denied for its category
     * @throws SecurityException if the {@code SEARCH} gate outcome is not {@link GateOutcome#ALLOW}
     */
    public List<FieldUseEffectDirective> validateSearchQueryFieldUses(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            Map<String, Object> trustedSubjectFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses,
            Map<FieldUseCategory, Set<String>> requestedQueryFieldUses,
            List<FieldUseEffectDirective> staticFieldUseDirectives
    ) {
        List<FieldUseEffectDirective> initialDirectives =
                staticFieldUseDirectives == null ? List.of() : staticFieldUseDirectives;
        Map<FieldUseCategory, Set<String>> effectiveUses =
                requestedQueryFieldUses == null ? Map.of() : requestedQueryFieldUses;
        fieldUseQueryGuard.guardQueryFieldUses(effectiveUses, initialDirectives);

        ProviderInputProjection searchInput = new ProviderInputProjection(
                ProviderInputProjection.SCHEMA_VERSION_V1,
                decisionPoint.identity().pointKey(),
                "SEARCH",
                factContractDigest,
                new TemporalContext(Instant.now(), ZoneOffset.UTC),
                trustedSubjectFacts,
                trustedFactStatuses,
                Set.of()
        );

        SearchProviderEvaluationResult searchResult = providerPort.evaluateSearch(searchInput);
        ProviderEvaluationEnvelope envelope = searchResult.admissionEnvelope();
        publishTelemetryIfConfigured(trustedSubjectFacts, decisionPoint, envelope);
        if (envelope.gateOutcome() != GateOutcome.ALLOW) {
            fulfillDenyObligations(decisionPoint.identity().pointKey(), envelope);
            throw toGateFailureException(
                    "AUTHZ_QUERY_SEAM_DENIED",
                    decisionPoint.identity().pointKey(),
                    envelope.gateOutcome(),
                    "AUTHZ_QUERY_SEAM_DENIED: " + envelope.gateOutcome()
            );
        }

        List<FieldUseEffectDirective> combinedDirectives = new ArrayList<>(initialDirectives);
        combinedDirectives.addAll(envelope.combinedFieldUseEffects());
        try {
            fieldUseQueryGuard.guardQueryFieldUses(effectiveUses, combinedDirectives);
            Set<String> valueDenied = fieldUseQueryGuard.extractValueDeniedAttributeIds(combinedDirectives);
            if (!valueDenied.isEmpty()) {
                for (Map.Entry<FieldUseCategory, Set<String>> entry : effectiveUses.entrySet()) {
                    if (entry.getKey() == null || entry.getValue() == null) {
                        continue;
                    }
                    Set<String> violations = new LinkedHashSet<>();
                    for (String attr : entry.getValue()) {
                        if (valueDenied.contains(attr)) {
                            violations.add(attr);
                        }
                    }
                    if (!violations.isEmpty()) {
                        throw new org.praxisplatform.authz.enforcement.fielduse.FieldUseViolationException(
                                entry.getKey(),
                                violations,
                                "Field use category " + entry.getKey() + " is denied for VALUE-denied attributes: " + violations
                        );
                    }
                }
            }
        } catch (RuntimeException ex) {
            fulfillDenyObligations(decisionPoint.identity().pointKey(), envelope);
            throw ex;
        }
        return List.copyOf(combinedDirectives);
    }

    /**
     * Evaluates a live {@code TARGET} read/preview projection against the active
     * {@link AuthorizationProviderPort} without persisting state or writing commit outbox entries,
     * returning the active OPA {@link MaskDirective}s and dynamically value-denied attributes
     * ({@code Fase P10.6}, {@code P11}, {@code P12}, {@code P47}, {@code P50}).
     */
    public TargetReadProjectionEvaluation evaluateTargetReadProjection(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            Map<String, Object> trustedTargetFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses
    ) {
        Objects.requireNonNull(decisionPoint, "decisionPoint is required");
        Objects.requireNonNull(factContractDigest, "factContractDigest is required");
        String pointKey = decisionPoint.identity().pointKey();
        if (trustedTargetFacts == null || trustedTargetFacts.isEmpty()) {
            throw new SecurityException("AUTHZ_TARGET_ENTITY_ACCESS_DENIED: Target entity facts are required on '"
                    + pointKey + "'");
        }
        Map<String, FactResolutionStatus> statuses = new LinkedHashMap<>();
        if (trustedFactStatuses != null) {
            statuses.putAll(trustedFactStatuses);
        }
        for (String key : trustedTargetFacts.keySet()) {
            statuses.putIfAbsent(key, FactResolutionStatus.PRESENT);
        }
        WriteIntent readIntent = new WriteIntent(
                "GET",
                false,
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.STATEMENT_ATOMIC,
                List.of()
        );
        ProviderInputProjection targetInput = new ProviderInputProjection(
                ProviderInputProjection.SCHEMA_VERSION_V1,
                pointKey,
                "TARGET",
                factContractDigest,
                new TemporalContext(Instant.now(), ZoneOffset.UTC),
                trustedTargetFacts,
                statuses,
                Set.of()
        );
        ProviderEvaluationEnvelope envelope = providerPort.evaluateTarget(targetInput, readIntent);
        publishTelemetryIfConfigured(trustedTargetFacts, decisionPoint, envelope);
        if (envelope.gateOutcome() != GateOutcome.ALLOW) {
            fulfillDenyObligations(pointKey, envelope);
            throw toGateFailureException(
                    "AUTHZ_TARGET_ENTITY_ACCESS_DENIED",
                    pointKey,
                    envelope.gateOutcome(),
                    "AUTHZ_TARGET_ENTITY_ACCESS_DENIED: Target entity access denied ("
                            + envelope.gateOutcome() + ") on '" + pointKey + "'"
            );
        }
        Set<String> fieldWriteDenied = new LinkedHashSet<>();
        if (envelope.combinedFieldWriteEffects() != null) {
            for (var dir : envelope.combinedFieldWriteEffects()) {
                if (dir != null
                        && dir.effect() == org.praxisplatform.authz.contracts.envelope.RuleEffect.DENY
                        && dir.attributeId() != null) {
                    fieldWriteDenied.add(dir.attributeId());
                }
            }
        }
        return new TargetReadProjectionEvaluation(
                pointKey,
                envelope.runtimeRevision(),
                envelope.policySetDigest(),
                fieldUseQueryGuard.extractValueDeniedAttributeIds(envelope.combinedFieldUseEffects()),
                envelope.combinedMaskDirectives(),
                fieldWriteDenied
        );
    }

    /**
     * Seam for projecting and masking query result rows into detached DTO maps without mutating
     * managed JPA entities ({@code P09}, {@code P12}, {@code P40}).
     */
    public List<DetachedDtoMaskingResult> projectAndMaskQueryResults(
            AuthorizedQueryScopeContext queryContext,
            List<?> rawEntities,
            Collection<DtoFieldSchemaMetadata> fieldSchemas
    ) {
        if (queryContext.scopeOutcome() == DataScopeOutcome.NONE || rawEntities.isEmpty()) {
            return List.of();
        }
        List<RowMaskingInput> inputs = new ArrayList<>(rawEntities.size());
        for (Object entity : rawEntities) {
            inputs.add(new RowMaskingInput(
                    entity,
                    queryContext.valueDeniedAttributeIds(),
                    queryContext.maskDirectives()
            ));
        }
        return maskingProcessor.projectAndMaskPage(inputs, fieldSchemas);
    }

    /**
     * Seam for {@code AbstractBaseResourceService} BEFORE {@code hydrate*} and {@code PraxisRulesEngine}
     * ({@code STEP_06}..{@code STEP_11}, {@code P13}, {@code P14}, {@code P40}).
     */
    public AuthorizedPreMutationContext authorizePreHydrationMutation(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            String operationVerb,
            boolean partialPatch,
            String rawJsonPayload,
            Map<String, String> attributeIdByWirePath,
            Set<String> ignoredTechnicalWirePaths,
            Set<String> mandatoryScopeAnchorAttributes,
            DualScopeDelegationSpec dualScopeSpec,
            boolean callerMatchesCedente,
            boolean callerMatchesCessionario,
            Map<String, Object> trustedTargetFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses
    ) {
        WriteIntent writeIntent = writeIntentExtractor.extractFromJson(
                operationVerb,
                partialPatch,
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.STATEMENT_ATOMIC,
                rawJsonPayload,
                attributeIdByWirePath,
                ignoredTechnicalWirePaths
        );

        ProviderInputProjection targetInput = new ProviderInputProjection(
                ProviderInputProjection.SCHEMA_VERSION_V1,
                decisionPoint.identity().pointKey(),
                "TARGET",
                factContractDigest,
                new TemporalContext(Instant.now(), ZoneOffset.UTC),
                trustedTargetFacts,
                trustedFactStatuses,
                Set.of()
        );

        ProviderEvaluationEnvelope envelope = providerPort.evaluateTarget(targetInput, writeIntent);
        publishTelemetryIfConfigured(trustedTargetFacts, decisionPoint, envelope);
        Set<String> anchors = mandatoryScopeAnchorAttributes == null ? Set.of() : mandatoryScopeAnchorAttributes;
        if (envelope.gateOutcome() != GateOutcome.ALLOW) {
            fulfillDenyObligations(decisionPoint.identity().pointKey(), envelope);
            for (WriteFieldChange change : writeIntent.changes()) {
                if (anchors.contains(change.attributeId())
                        && (change.changeKind() == WriteChangeKind.CLEAR_EXPLICIT_NULL
                                || change.changeKind() == WriteChangeKind.REMOVE)) {
                    throw new SecurityException("AUTHZ_SCOPE_ANCHOR_CLEAR_FORBIDDEN: Mandatory scope anchor '"
                            + change.attributeId() + "' cannot be cleared or omitted (CC06/P13/P14)");
                }
            }
            throw toGateFailureException(
                    "AUTHZ_MUTATION_SEAM_DENIED",
                    decisionPoint.identity().pointKey(),
                    envelope.gateOutcome(),
                    "AUTHZ_MUTATION_SEAM_DENIED: " + envelope.gateOutcome()
            );
        }

        try {
            fieldWriteAuthorizer.enforceFieldWriteDirectives(writeIntent, envelope.combinedFieldWriteEffects(), true);

            for (WriteFieldChange change : writeIntent.changes()) {
                if (anchors.contains(change.attributeId())
                        && (change.changeKind() == WriteChangeKind.CLEAR_EXPLICIT_NULL
                                || change.changeKind() == WriteChangeKind.REMOVE)) {
                    throw new SecurityException("AUTHZ_SCOPE_ANCHOR_CLEAR_FORBIDDEN: Mandatory scope anchor '"
                            + change.attributeId() + "' cannot be cleared or omitted (CC06/P13/P14)");
                }
            }
            if (dualScopeSpec != null) {
                if (operationVerb != null
                        && operationVerb.toUpperCase(java.util.Locale.ROOT).startsWith("DELETE")
                        && !callerMatchesCedente
                        && !dualScopeSpec.cedenteExclusiveWriteAttributes().isEmpty()) {
                    throw new FieldWriteViolationException(
                            dualScopeSpec.cedenteExclusiveWriteAttributes(),
                            "AUTHZ_DUAL_SCOPE_DELETE_REQUIRES_CEDENTE:" + dualScopeSpec.mode(),
                            "Deleting an entity with cedente-exclusive attributes requires origin/cedente custody (R-07/P17)");
                }
                WriteIntent businessWriteIntent = new WriteIntent(
                        writeIntent.operationVerb(),
                        writeIntent.partialPatch(),
                        BatchAuthorizationMode.REJECT_ALL,
                        TransactionCardinality.STATEMENT_ATOMIC,
                        writeIntent.changes().stream()
                                .filter(c -> !anchors.contains(c.attributeId()))
                                .toList()
                );
                fieldWriteAuthorizer.enforceDualScopeCustody(
                        businessWriteIntent,
                        dualScopeSpec,
                        callerMatchesCedente,
                        callerMatchesCessionario
                );
            }
        } catch (RuntimeException ex) {
            fulfillDenyObligations(decisionPoint.identity().pointKey(), envelope);
            throw ex;
        }

        List<ObligationFulfillmentResult> beforeExecutionResults = obligationCoordinator.fulfillAtBarrier(
                decisionPoint.identity().pointKey(),
                envelope.runtimeRevision(),
                EnforcementDisposition.PERMIT,
                ObligationFulfillmentBarrier.BEFORE_EXECUTION,
                envelope.combinedObligationDirectives(),
                Map.of("policySetDigest", envelope.policySetDigest())
        );
        if (beforeExecutionResults.stream().anyMatch(r -> !r.fulfilled())) {
            fulfillDenyObligations(decisionPoint.identity().pointKey(), envelope);
            throw new SecurityException("AUTHZ_OBLIGATION_BEFORE_EXECUTION_FAILED: Mandatory BEFORE_EXECUTION obligation failed (CC10/P19)");
        }

        return new AuthorizedPreMutationContext(
                decisionPoint.identity().pointKey(),
                envelope.runtimeRevision(),
                envelope.policySetDigest(),
                writeIntent,
                envelope,
                fieldUseQueryGuard.extractValueDeniedAttributeIds(envelope.combinedFieldUseEffects()),
                envelope.combinedMaskDirectives(),
                envelope.combinedObligationDirectives()
        );
    }

    /**
     * Seam for {@code AbstractBaseResourceService} AFTER {@code STEP_12} business-rule execution:
     * fulfills {@code BEFORE_COMMIT_OUTBOX} obligations (into {@code JdbcTransactionalAuditOutbox}),
     * projects the detached masked response DTO at {@code STEP_14}, and fulfills
     * {@code BEFORE_DISCLOSURE} obligations at {@code STEP_15} ({@code CC10}, {@code P19}, {@code P40}).
     */
    public DetachedDtoMaskingResult completePostMutationAndMask(
            AuthorizedPreMutationContext preMutationContext,
            Object savedUnmaskedEntity,
            Collection<DtoFieldSchemaMetadata> fieldSchemas
    ) {
        List<ObligationFulfillmentResult> outboxResults = obligationCoordinator.fulfillAtBarrier(
                preMutationContext.decisionPointKey(),
                preMutationContext.runtimeRevision(),
                EnforcementDisposition.PERMIT,
                ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX,
                preMutationContext.obligations(),
                Map.of("policySetDigest", preMutationContext.policySetDigest())
        );
        if (outboxResults.stream().anyMatch(r -> !r.fulfilled())) {
            throw new SecurityException("AUTHZ_OBLIGATION_OUTBOX_BARRIER_FAILED: Mandatory BEFORE_COMMIT_OUTBOX obligation failed (P19)");
        }

        DetachedDtoMaskingResult maskedDto = maskingProcessor.projectAndMask(
                savedUnmaskedEntity,
                fieldSchemas,
                preMutationContext.valueDeniedAttributeIds(),
                preMutationContext.maskDirectives()
        );

        List<ObligationFulfillmentResult> beforeDisclosureResults = obligationCoordinator.fulfillAtBarrier(
                preMutationContext.decisionPointKey(),
                preMutationContext.runtimeRevision(),
                EnforcementDisposition.PERMIT,
                ObligationFulfillmentBarrier.BEFORE_DISCLOSURE,
                preMutationContext.obligations(),
                Map.of("policySetDigest", preMutationContext.policySetDigest())
        );
        if (beforeDisclosureResults.stream().anyMatch(r -> !r.fulfilled())) {
            throw new SecurityException("AUTHZ_OBLIGATION_BEFORE_DISCLOSURE_FAILED: Mandatory BEFORE_DISCLOSURE obligation failed (CC10/P19)");
        }

        return maskedDto;
    }

    /**
     * Seam for {@code AbstractBaseResourceService.afterDelete(ID, E)} AFTER {@code STEP_12}
     * deletion admission and {@code repository.delete(entity)}: fulfills mandatory
     * {@code BEFORE_COMMIT_OUTBOX} obligations inside the active {@code @Transactional} boundary
     * when no response DTO is disclosed ({@code STEP_14}, {@code CC10}, {@code P19}, {@code P22}).
     *
     * @param preMutationContext pre-mutation context returned by {@link #authorizePreHydrationMutation}
     */
    public void completePostDeleteOutbox(AuthorizedPreMutationContext preMutationContext) {
        Objects.requireNonNull(preMutationContext, "preMutationContext is required");
        List<ObligationFulfillmentResult> outboxResults = obligationCoordinator.fulfillAtBarrier(
                preMutationContext.decisionPointKey(),
                preMutationContext.runtimeRevision(),
                EnforcementDisposition.PERMIT,
                ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX,
                preMutationContext.obligations(),
                Map.of("policySetDigest", preMutationContext.policySetDigest())
        );
        if (outboxResults.stream().anyMatch(r -> !r.fulfilled())) {
            throw new SecurityException("AUTHZ_OBLIGATION_OUTBOX_BARRIER_FAILED: Mandatory BEFORE_COMMIT_OUTBOX obligation failed on DELETE (P19)");
        }
    }

    /**
     * Seam for {@code BulkDurableWorker}: validates an authenticated {@link WorkerDelegationToken}
     * (without relying on HTTP headers or inherited ThreadLocals) and revalidates authority against
     * the current active policy digest ({@code P02}, {@code P15}, {@code P18}).
     */
    public void authorizeBulkDurableWorkerItem(
            WorkerDelegationToken delegationToken,
            String expectedAudience,
            String currentActivePolicySetDigest,
            Instant now
    ) {
        Objects.requireNonNull(delegationToken, "delegationToken is required");
        if (!delegationToken.audience().equals(expectedAudience)) {
            throw new SecurityException("AUTHZ_WORKER_AUDIENCE_MISMATCH: Expected '"
                    + expectedAudience + "' but got '" + delegationToken.audience() + "' (P02/P15)");
        }
        if (!now.isBefore(delegationToken.expiresAt())) {
            throw new SecurityException("AUTHZ_WORKER_DELEGATION_EXPIRED: Worker delegation token expired at "
                    + delegationToken.expiresAt() + " (P15/P18)");
        }
        if (!delegationToken.pinnedPolicySetDigest().equals(currentActivePolicySetDigest)) {
            throw new SecurityException("AUTHZ_WORKER_POLICY_REVOKED_OR_ROTATED: Worker pinned digest '"
                    + delegationToken.pinnedPolicySetDigest() + "' no longer matches active digest '"
                    + currentActivePolicySetDigest + "' (P15/P18)");
        }
    }

    /**
     * Seam for {@code BulkDurableWorker} per-item execution: validates the {@link WorkerDelegationToken}
     * and performs a live OPA {@code TARGET} re-evaluation for the specific item and {@link WriteIntent}
     * so mid-batch grant revocations or item-level denials fail closed immediately ({@code P02}, {@code P15}, {@code P18}).
     */
    public ProviderEvaluationEnvelope authorizeBulkDurableWorkerItem(
            WorkerDelegationToken delegationToken,
            String expectedAudience,
            String currentActivePolicySetDigest,
            Instant now,
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            WriteIntent itemWriteIntent,
            Map<String, Object> itemTargetFacts,
            Map<String, FactResolutionStatus> itemFactStatuses
    ) {
        authorizeBulkDurableWorkerItem(delegationToken, expectedAudience, currentActivePolicySetDigest, now);
        Map<String, Object> mergedFacts = new LinkedHashMap<>(delegationToken.minimalSubjectFacts());
        if (itemTargetFacts != null) {
            mergedFacts.putAll(itemTargetFacts);
        }
        Map<String, FactResolutionStatus> mergedStatuses = new LinkedHashMap<>();
        for (String key : mergedFacts.keySet()) {
            mergedStatuses.put(key, FactResolutionStatus.PRESENT);
        }
        if (itemFactStatuses != null) {
            mergedStatuses.putAll(itemFactStatuses);
        }
        ProviderInputProjection targetInput = new ProviderInputProjection(
                ProviderInputProjection.SCHEMA_VERSION_V1,
                decisionPoint.identity().pointKey(),
                "TARGET",
                factContractDigest,
                new TemporalContext(now, ZoneOffset.UTC),
                mergedFacts,
                mergedStatuses,
                Set.of()
        );
        ProviderEvaluationEnvelope envelope = providerPort.evaluateTarget(targetInput, itemWriteIntent);
        publishTelemetryIfConfigured(mergedFacts, decisionPoint, envelope);
        if (envelope.gateOutcome() != GateOutcome.ALLOW) {
            fulfillDenyObligations(decisionPoint.identity().pointKey(), envelope);
            throw toGateFailureException(
                    "AUTHZ_WORKER_ITEM_TARGET_DENIED",
                    decisionPoint.identity().pointKey(),
                    envelope.gateOutcome(),
                    "AUTHZ_WORKER_ITEM_TARGET_DENIED: Bulk worker item denied with " + envelope.gateOutcome() + " (P15/P18)"
            );
        }
        try {
            fieldWriteAuthorizer.enforceFieldWriteDirectives(itemWriteIntent, envelope.combinedFieldWriteEffects(), true);
        } catch (RuntimeException ex) {
            fulfillDenyObligations(decisionPoint.identity().pointKey(), envelope);
            throw ex;
        }
        return envelope;
    }

    private void publishTelemetryIfConfigured(
            Map<String, Object> facts,
            DecisionPointDescriptor decisionPoint,
            ProviderEvaluationEnvelope envelope
    ) {
        if (telemetryPublisher == null) {
            return;
        }
        Object rawTenant = facts == null ? null : facts.get("subject.tenantId");
        String tenantId = (rawTenant instanceof String s && !s.isBlank()) ? s : "default-tenant";
        telemetryPublisher.recordEnvelope(tenantId, "runtime", PointAuthorityMode.AUTHORITATIVE, envelope);
    }

    private void fulfillDenyObligations(String decisionPointKey, ProviderEvaluationEnvelope envelope) {
        List<ObligationDirective> obligations = envelope.combinedObligationDirectives();
        if (obligations == null || obligations.isEmpty()) {
            return;
        }
        Map<String, Object> ctx = Map.of("policySetDigest", envelope.policySetDigest());
        obligationCoordinator.fulfillAtBarrier(
                decisionPointKey,
                envelope.runtimeRevision(),
                EnforcementDisposition.DENY,
                ObligationFulfillmentBarrier.BEFORE_EXECUTION,
                obligations,
                ctx
        );
        obligationCoordinator.fulfillAtBarrier(
                decisionPointKey,
                envelope.runtimeRevision(),
                EnforcementDisposition.DENY,
                ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX,
                obligations,
                ctx
        );
        obligationCoordinator.fulfillAtBarrier(
                decisionPointKey,
                envelope.runtimeRevision(),
                EnforcementDisposition.DENY,
                ObligationFulfillmentBarrier.BEFORE_DISCLOSURE,
                obligations,
                ctx
        );
    }

    private static Map<String, ResolvedFactValue> toAuthoritativeSubjectFactMap(
            Map<String, Object> trustedFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses
    ) {
        if (trustedFacts == null || trustedFacts.isEmpty()) {
            return Map.of();
        }
        Map<String, ResolvedFactValue> resolved = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : trustedFacts.entrySet()) {
            FactResolutionStatus status = trustedFactStatuses != null
                    ? trustedFactStatuses.getOrDefault(entry.getKey(), FactResolutionStatus.PRESENT)
                    : FactResolutionStatus.PRESENT;
            if (status == FactResolutionStatus.PRESENT && entry.getValue() != null) {
                resolved.put(entry.getKey(), ResolvedFactValue.present(entry.getKey(), entry.getValue()));
            }
        }
        return resolved;
    }

    /**
     * Sanitized evaluation result for contextual discovery ({@code /actions}, {@code /surfaces},
     * {@code /capabilities}, and HATEOAS {@code _links}) ({@code Fase P10.4}, {@code Fase P10.16-B},
     * {@code P10}, {@code P17}).
     *
     * @param advisory advisory metadata safe for public discovery responses
     * @param denialReason canonical machine-readable reason when {@code !advisory.currentlyPermitted()}
     * @param operationId canonical operation, action, or surface identifier
     * @param evaluationScope {@code "ITEM"} or {@code "COLLECTION"}
     * @param denialCategory structured denial category when {@code denialReason != null}
     * @param dualScopeCustodyRole value-free custody partition role ({@code "CEDENTE_AND_CESSIONARIO"},
     *                             {@code "CEDENTE_ONLY"}, {@code "CESSIONARIO_ONLY"}, or {@code "NONE"})
     * @param forbiddenWriteAttributeIds canonical {@code attributeId}s that caused a write denial
     * @param policyReasonCodes matched policy unit reason codes from {@link ProviderEvaluationEnvelope}
     */
    public record OperationAvailabilityEvaluation(
            AdvisoryOperationAvailability advisory,
            String denialReason,
            String operationId,
            String evaluationScope,
            String denialCategory,
            String dualScopeCustodyRole,
            List<String> forbiddenWriteAttributeIds,
            List<String> policyReasonCodes
    ) {
        /** Compact constructor enforcing immutable diagnostic lists. */
        public OperationAvailabilityEvaluation {
            forbiddenWriteAttributeIds = forbiddenWriteAttributeIds == null
                    ? List.of()
                    : List.copyOf(forbiddenWriteAttributeIds);
            policyReasonCodes = policyReasonCodes == null
                    ? List.of()
                    : List.copyOf(policyReasonCodes);
        }

        /** Backward-compatible 2-argument constructor. */
        public OperationAvailabilityEvaluation(
                AdvisoryOperationAvailability advisory,
                String denialReason
        ) {
            this(
                    advisory,
                    denialReason,
                    null,
                    null,
                    classifyDenialCategory(denialReason),
                    null,
                    List.of(),
                    List.of()
            );
        }

        /**
         * Classifies a machine-readable {@code denialReason} into a canonical value-free
         * diagnostic category for UI tooltips and {@code /praxis/cockpit} ({@code Fase P10.16-B}).
         */
        public static String classifyDenialCategory(String denialReason) {
            if (denialReason == null || denialReason.isBlank()) {
                return null;
            }
            return switch (denialReason) {
                case "caller-context-missing", "AUTHZ_CALLER_CONTEXT_MISSING", "AUTHZ_CONTEXT_MISSING" -> "CALLER_CONTEXT_MISSING";
                case "resource-state-not-found", "resource-state-unavailable" -> "RESOURCE_STATE_UNAVAILABLE";
                case "hard-scope-tenant-mismatch" -> "TENANT_HARD_SCOPE_MISMATCH";
                case "dual-scope-cedente-custody-required", "dual-scope-custody-denied" -> "DUAL_SCOPE_CUSTODY_DENIED";
                case "policy-gate-denied", "AUTHZ_POLICY_DENIED" -> "POLICY_GATE_DENIED";
                case "field-write-denied" -> "FIELD_WRITE_DENIED";
                default -> "AUTHORIZATION_DENIED";
            };
        }

        /**
         * Returns a sanitized metadata map suitable for {@code AvailabilityDecision} without
         * leaking principal IDs, tokens, or protected resource state ({@code Fase P10.16-B},
         * {@code P10}, {@code P17}).
         *
         * @return immutable metadata map
         */
        public Map<String, Object> toSanitizedDecisionMetadata() {
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("decisionPointKey", advisory.decisionPointKey());
            if (operationId != null && !operationId.isBlank()) {
                metadata.put("operationId", operationId);
            }
            if (evaluationScope != null && !evaluationScope.isBlank()) {
                metadata.put("evaluationScope", evaluationScope);
            }
            metadata.put("advisoryOnly", advisory.advisoryOnly());
            metadata.put("requiresRuntimeRevalidation", advisory.requiresRuntimeRevalidation());
            metadata.put("revalidatedOnExecution", advisory.requiresRuntimeRevalidation());
            if (advisory.observedPolicyRevision() != null) {
                metadata.put("observedPolicyRevision", advisory.observedPolicyRevision());
            }
            if (denialCategory != null && !denialCategory.isBlank()) {
                metadata.put("denialCategory", denialCategory);
            }
            if (dualScopeCustodyRole != null && !dualScopeCustodyRole.isBlank()) {
                metadata.put("dualScopeCustodyRole", dualScopeCustodyRole);
            }
            if (!forbiddenWriteAttributeIds.isEmpty()) {
                metadata.put("forbiddenWriteAttributeIds", forbiddenWriteAttributeIds);
            }
            if (!policyReasonCodes.isEmpty()) {
                metadata.put("policyReasonCodes", policyReasonCodes);
            }
            return Map.copyOf(metadata);
        }
    }

    /**
     * Seam for {@code ResourceOperationAvailabilityEvaluator}: produces an advisory availability
     * projection for UI/HATEOAS discovery while requiring server-side revalidation on execution ({@code P10}, {@code P17}).
     */
    public AdvisoryOperationAvailability evaluateAdvisoryAvailability(
            String decisionPointKey,
            boolean currentlyPermitted,
            String observedPolicyRevision
    ) {
        return new AdvisoryOperationAvailability(
                decisionPointKey,
                currentlyPermitted,
                true,
                true,
                observedPolicyRevision
        );
    }

    /**
     * Evaluates live contextual availability of a collection or item operation/action/surface
     * against the active {@link AuthorizationProviderPort}, {@link FieldWriteAuthorizer}, and
     * {@link DualScopeDelegationSpec} ({@code Fase P10.4}, {@code P10}, {@code P16}, {@code P17}).
     *
     * <p>Collection-scoped evaluations never accept or leak item-scoped facts or {@code resourceId}.
     * Item-scoped evaluations fail closed when item target facts are absent.</p>
     *
     * @param decisionPoint governed decision point descriptor
     * @param factContractDigest canonical fact contract digest
     * @param operationId canonical operation, action, or surface identifier
     * @param itemScope {@code true} when evaluating an {@code ITEM}-scoped operation/action/surface
     * @param modifiedAttributeIds canonical {@code attributeId}s modified by this operation/command (empty for read/delete)
     * @param dualScopeSpec optional dual-scope custody specification
     * @param callerMatchesCedente whether the caller holds {@code Cedente} custody
     * @param callerMatchesCessionario whether the caller holds {@code Cessionário} custody
     * @param trustedSubjectFacts authoritative subject facts
     * @param trustedSubjectFactStatuses subject fact resolution statuses
     * @param trustedItemTargetFacts authoritative item target facts (ignored when {@code !itemScope})
     * @param trustedItemTargetFactStatuses item fact resolution statuses (ignored when {@code !itemScope})
     * @return sanitized {@link OperationAvailabilityEvaluation}
     */
    public OperationAvailabilityEvaluation evaluateOperationAvailability(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            String operationId,
            boolean itemScope,
            Set<String> modifiedAttributeIds,
            DualScopeDelegationSpec dualScopeSpec,
            boolean callerMatchesCedente,
            boolean callerMatchesCessionario,
            Map<String, Object> trustedSubjectFacts,
            Map<String, FactResolutionStatus> trustedSubjectFactStatuses,
            Map<String, Object> trustedItemTargetFacts,
            Map<String, FactResolutionStatus> trustedItemTargetFactStatuses
    ) {
        Objects.requireNonNull(decisionPoint, "decisionPoint is required");
        Objects.requireNonNull(factContractDigest, "factContractDigest is required");
        String pointKey = decisionPoint.identity().pointKey();
        String normalizedOp = operationId == null ? "" : operationId.trim().toLowerCase(java.util.Locale.ROOT);
        String scopeLabel = itemScope ? "ITEM" : "COLLECTION";
        String custodyRole = resolveDualScopeCustodyRole(dualScopeSpec, callerMatchesCedente, callerMatchesCessionario);

        if (itemScope && (trustedItemTargetFacts == null || trustedItemTargetFacts.isEmpty())) {
            return new OperationAvailabilityEvaluation(
                    evaluateAdvisoryAvailability(pointKey, false, "unobserved"),
                    "resource-state-unavailable",
                    operationId,
                    scopeLabel,
                    OperationAvailabilityEvaluation.classifyDenialCategory("resource-state-unavailable"),
                    custodyRole,
                    List.of(),
                    List.of()
            );
        }

        // Dual-scope custody pre-check on delete or operations touching cedente/cessionario attributes
        Set<String> targetAttrs = modifiedAttributeIds == null ? Set.of() : modifiedAttributeIds;
        List<WriteFieldChange> syntheticChanges = new ArrayList<>(targetAttrs.size());
        for (String attrId : targetAttrs) {
            syntheticChanges.add(new WriteFieldChange(
                    "/" + attrId,
                    attrId,
                    WriteChangeKind.SET,
                    "__discovery_probe__"
            ));
        }
        boolean readOnlyDiscoveryOp = syntheticChanges.isEmpty()
                && ("view".equals(normalizedOp)
                || "detail".equals(normalizedOp)
                || "filter".equals(normalizedOp)
                || "export".equals(normalizedOp));
        String syntheticVerb = normalizedOp.startsWith("delete")
                ? "DELETE"
                : (readOnlyDiscoveryOp ? "GET" : (itemScope ? "PATCH" : "POST"));
        WriteIntent syntheticWriteIntent = new WriteIntent(
                syntheticVerb,
                itemScope && !readOnlyDiscoveryOp && !normalizedOp.startsWith("delete"),
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.STATEMENT_ATOMIC,
                syntheticChanges
        );

        if (dualScopeSpec != null) {
            if (normalizedOp.startsWith("delete")
                    && !callerMatchesCedente
                    && !dualScopeSpec.cedenteExclusiveWriteAttributes().isEmpty()) {
                return new OperationAvailabilityEvaluation(
                        evaluateAdvisoryAvailability(pointKey, false, "dual-scope-precheck"),
                        "dual-scope-cedente-custody-required",
                        operationId,
                        scopeLabel,
                        OperationAvailabilityEvaluation.classifyDenialCategory("dual-scope-cedente-custody-required"),
                        custodyRole,
                        List.copyOf(dualScopeSpec.cedenteExclusiveWriteAttributes()),
                        List.of()
                );
            }
            if ("duplicate-draft".equals(normalizedOp)
                    && itemScope
                    && !callerMatchesCedente
                    && !callerMatchesCessionario) {
                return new OperationAvailabilityEvaluation(
                        evaluateAdvisoryAvailability(pointKey, false, "dual-scope-precheck"),
                        "dual-scope-custody-denied",
                        operationId,
                        scopeLabel,
                        OperationAvailabilityEvaluation.classifyDenialCategory("dual-scope-custody-denied"),
                        custodyRole,
                        List.of(),
                        List.of()
                );
            }
            if (!syntheticChanges.isEmpty()) {
                try {
                    fieldWriteAuthorizer.enforceDualScopeCustody(
                            syntheticWriteIntent,
                            dualScopeSpec,
                            callerMatchesCedente,
                            callerMatchesCessionario
                    );
                } catch (FieldWriteViolationException ex) {
                    return new OperationAvailabilityEvaluation(
                            evaluateAdvisoryAvailability(pointKey, false, "dual-scope-precheck"),
                            "dual-scope-custody-denied",
                            operationId,
                            scopeLabel,
                            OperationAvailabilityEvaluation.classifyDenialCategory("dual-scope-custody-denied"),
                            custodyRole,
                            List.copyOf(ex.getForbiddenAttributeIds()),
                            List.of()
                    );
                }
            }
        }

        if (!itemScope) {
            // COLLECTION scope: never leak item state or resourceId into policy context
            Map<String, Object> safeSubjectFacts = trustedSubjectFacts == null ? Map.of() : trustedSubjectFacts;
            ProviderInputProjection collectionInput = new ProviderInputProjection(
                    ProviderInputProjection.SCHEMA_VERSION_V1,
                    pointKey,
                    "SEARCH",
                    factContractDigest,
                    new TemporalContext(Instant.now(), ZoneOffset.UTC),
                    safeSubjectFacts,
                    trustedSubjectFactStatuses == null ? Map.of() : trustedSubjectFactStatuses,
                    Set.of()
            );
            SearchProviderEvaluationResult searchResult = providerPort.evaluateSearch(collectionInput);
            ProviderEvaluationEnvelope envelope = searchResult.admissionEnvelope();
            List<String> reasonCodes = extractPolicyReasonCodes(envelope);
            publishTelemetryIfConfigured(safeSubjectFacts, decisionPoint, envelope);
            if (envelope.gateOutcome() != GateOutcome.ALLOW
                    || searchResult.dataScopePlan() == null
                    || searchResult.dataScopePlan().scopeOutcome() == DataScopeOutcome.NONE) {
                return new OperationAvailabilityEvaluation(
                        evaluateAdvisoryAvailability(pointKey, false, envelope.runtimeRevision()),
                        "policy-gate-denied",
                        operationId,
                        scopeLabel,
                        OperationAvailabilityEvaluation.classifyDenialCategory("policy-gate-denied"),
                        custodyRole,
                        List.of(),
                        reasonCodes
                );
            }
            if (!syntheticChanges.isEmpty()) {
                try {
                    fieldWriteAuthorizer.enforceFieldWriteDirectives(
                            syntheticWriteIntent,
                            envelope.combinedFieldWriteEffects(),
                            true
                    );
                } catch (FieldWriteViolationException ex) {
                    return new OperationAvailabilityEvaluation(
                            evaluateAdvisoryAvailability(pointKey, false, envelope.runtimeRevision()),
                            "field-write-denied",
                            operationId,
                            scopeLabel,
                            OperationAvailabilityEvaluation.classifyDenialCategory("field-write-denied"),
                            custodyRole,
                            List.copyOf(ex.getForbiddenAttributeIds()),
                            reasonCodes
                    );
                }
            }
            return new OperationAvailabilityEvaluation(
                    evaluateAdvisoryAvailability(pointKey, true, envelope.runtimeRevision()),
                    null,
                    operationId,
                    scopeLabel,
                    null,
                    custodyRole,
                    List.of(),
                    reasonCodes
            );
        }

        // ITEM scope: combine subject facts + item target facts
        Map<String, Object> mergedFacts = new LinkedHashMap<>();
        Map<String, FactResolutionStatus> mergedStatuses = new LinkedHashMap<>();
        if (trustedSubjectFacts != null) {
            mergedFacts.putAll(trustedSubjectFacts);
        }
        if (trustedSubjectFactStatuses != null) {
            mergedStatuses.putAll(trustedSubjectFactStatuses);
        }
        mergedFacts.putAll(trustedItemTargetFacts);
        if (trustedItemTargetFactStatuses != null) {
            mergedStatuses.putAll(trustedItemTargetFactStatuses);
        } else {
            for (String key : trustedItemTargetFacts.keySet()) {
                mergedStatuses.putIfAbsent(key, FactResolutionStatus.PRESENT);
            }
        }

        ProviderInputProjection targetInput = new ProviderInputProjection(
                ProviderInputProjection.SCHEMA_VERSION_V1,
                pointKey,
                "TARGET",
                factContractDigest,
                new TemporalContext(Instant.now(), ZoneOffset.UTC),
                mergedFacts,
                mergedStatuses,
                Set.of()
        );
        ProviderEvaluationEnvelope envelope = providerPort.evaluateTarget(targetInput, syntheticWriteIntent);
        List<String> reasonCodes = extractPolicyReasonCodes(envelope);
        publishTelemetryIfConfigured(mergedFacts, decisionPoint, envelope);
        if (envelope.gateOutcome() != GateOutcome.ALLOW) {
            return new OperationAvailabilityEvaluation(
                    evaluateAdvisoryAvailability(pointKey, false, envelope.runtimeRevision()),
                    "policy-gate-denied",
                    operationId,
                    scopeLabel,
                    OperationAvailabilityEvaluation.classifyDenialCategory("policy-gate-denied"),
                    custodyRole,
                    List.of(),
                    reasonCodes
            );
        }
        if (!syntheticChanges.isEmpty()) {
            try {
                fieldWriteAuthorizer.enforceFieldWriteDirectives(
                        syntheticWriteIntent,
                        envelope.combinedFieldWriteEffects(),
                        true
                );
            } catch (FieldWriteViolationException ex) {
                return new OperationAvailabilityEvaluation(
                        evaluateAdvisoryAvailability(pointKey, false, envelope.runtimeRevision()),
                        "field-write-denied",
                        operationId,
                        scopeLabel,
                        OperationAvailabilityEvaluation.classifyDenialCategory("field-write-denied"),
                        custodyRole,
                        List.copyOf(ex.getForbiddenAttributeIds()),
                        reasonCodes
                );
            }
        }
        return new OperationAvailabilityEvaluation(
                evaluateAdvisoryAvailability(pointKey, true, envelope.runtimeRevision()),
                null,
                operationId,
                scopeLabel,
                null,
                custodyRole,
                List.of(),
                reasonCodes
        );
    }

    private static String resolveDualScopeCustodyRole(
            DualScopeDelegationSpec dualScopeSpec,
            boolean callerMatchesCedente,
            boolean callerMatchesCessionario
    ) {
        if (dualScopeSpec == null) {
            return null;
        }
        if (callerMatchesCedente && callerMatchesCessionario) {
            return "CEDENTE_AND_CESSIONARIO";
        }
        if (callerMatchesCedente) {
            return "CEDENTE_ONLY";
        }
        if (callerMatchesCessionario) {
            return "CESSIONARIO_ONLY";
        }
        return "NONE";
    }

    private static List<String> extractPolicyReasonCodes(ProviderEvaluationEnvelope envelope) {
        if (envelope == null || envelope.unitContributions() == null || envelope.unitContributions().isEmpty()) {
            return List.of();
        }
        return envelope.unitContributions().stream()
                .map(org.praxisplatform.authz.contracts.envelope.PolicyUnitContributionTrace::reasonCode)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
    }

    private static RuntimeException toGateFailureException(
            String reasonCode,
            String decisionPointKey,
            GateOutcome gateOutcome,
            String message
    ) {
        if (gateOutcome == GateOutcome.TECHNICAL_ERROR || gateOutcome == GateOutcome.INCONCLUSIVE) {
            return new AuthzProviderUnavailableException(reasonCode, decisionPointKey, gateOutcome, message);
        }
        return new AuthzAccessDeniedException(reasonCode, decisionPointKey, gateOutcome, message);
    }

    /**
     * Verifies at execution time that a previously emitted advisory HATEOAS link cannot bypass a
     * revoked or rotated policy decision ({@code P10}, {@code P17}).
     */
    public void enforceAuthoritativeExecutionAgainstStaleLink(
            AdvisoryOperationAvailability clientSubmittedAdvisoryLink,
            boolean livePolicyPermitsNow
    ) {
        if (!livePolicyPermitsNow) {
            throw new SecurityException("AUTHZ_STALE_HATEOAS_LINK_REJECTED: Advisory discovery link for '"
                    + (clientSubmittedAdvisoryLink != null ? clientSubmittedAdvisoryLink.decisionPointKey() : "<unknown>")
                    + "' does not grant authority after policy/context change (P10/P17)");
        }
    }
}
