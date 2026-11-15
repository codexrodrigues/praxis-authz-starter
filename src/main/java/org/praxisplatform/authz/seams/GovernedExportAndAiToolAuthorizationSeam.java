package org.praxisplatform.authz.seams;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import org.praxisplatform.authz.catalog.FieldLineageCatalogEntry;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.context.TemporalContext;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.contracts.envelope.EnforcementDisposition;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.contracts.obligation.ObligationFulfillmentBarrier;
import org.praxisplatform.authz.contracts.obligation.ObligationFulfillmentResult;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor.RowMaskingInput;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort;
import org.praxisplatform.authz.export.GovernedCollectionExportGuard;
import org.praxisplatform.authz.export.GovernedCollectionExportGuard.ExportFormat;
import org.praxisplatform.authz.export.GovernedCollectionExportGuard.SanitizedExportArtifact;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry.RegisteredDecisionPointContext;
import org.praxisplatform.authz.telemetry.SanitizedAuthorizationTelemetryPublisher;

/**
 * Canonical authorization seam governing collection exports ({@code CSV}, {@code JSON},
 * {@code EXCEL_TSV}) and AI tool / authoring metadata access ({@code P11}, {@code P12},
 * {@code P17}, {@code P18}, {@code P19}, {@code P21}, {@code P36}, {@code P44}, {@code P45},
 * {@code P47}, {@code P50}, {@code P56}, {@code P57}, {@code P60}, {@code P62}).
 *
 * <p>Combines static and ancestor-inherited {@code @DomainGovernance(exportable = false)} and
 * {@code @AiUsagePolicy} lineage constraints with live per-row OPA {@code TARGET} evaluations,
 * detached DTO masking, and 3-barrier obligation fulfillment ({@code BEFORE_EXECUTION},
 * {@code BEFORE_COMMIT_OUTBOX}, {@code BEFORE_DISCLOSURE}).</p>
 */
public final class GovernedExportAndAiToolAuthorizationSeam {

    /** Sanitized AI tool payload projection with zero forbidden or un-governed field values ({@code P11}, {@code P47}, {@code P57}, {@code P62}). */
    public record SanitizedAiToolProjection(
            String decisionPointKey,
            String runtimeRevision,
            String policySetDigest,
            List<String> allowedWireColumns,
            Set<String> suppressedAiAttributeIds,
            Map<String, Object> detachedPayload
    ) {
        public SanitizedAiToolProjection {
            Objects.requireNonNull(decisionPointKey, "decisionPointKey is required");
            Objects.requireNonNull(runtimeRevision, "runtimeRevision is required");
            Objects.requireNonNull(policySetDigest, "policySetDigest is required");
            allowedWireColumns = allowedWireColumns == null ? List.of() : List.copyOf(allowedWireColumns);
            suppressedAiAttributeIds = suppressedAiAttributeIds == null ? Set.of() : Set.copyOf(suppressedAiAttributeIds);
            detachedPayload = detachedPayload == null ? Map.of() : Map.copyOf(detachedPayload);
        }
    }

    /** Value-free governance metadata view for AI authoring and discovery ({@code P62}). */
    public record AiGovernanceMetadataView(
            String attributeId,
            String conceptId,
            String wirePath,
            String sensitivityClassification,
            String aiUsageMode,
            boolean exportable,
            Set<FieldUseCategory> allowedUseCategories
    ) {}

    private final RuntimeDecisionPointRegistry registry;
    private final AuthorizationProviderPort providerPort;
    private final FieldUseQueryGuard fieldUseQueryGuard;
    private final DetachedDtoMaskingProcessor maskingProcessor;
    private final ObligationBarrierCoordinator obligationCoordinator;
    private final GovernedCollectionExportGuard exportGuard;
    private final SanitizedAuthorizationTelemetryPublisher telemetryPublisher;

    public GovernedExportAndAiToolAuthorizationSeam(
            RuntimeDecisionPointRegistry registry,
            AuthorizationProviderPort providerPort,
            FieldUseQueryGuard fieldUseQueryGuard,
            DetachedDtoMaskingProcessor maskingProcessor,
            ObligationBarrierCoordinator obligationCoordinator,
            GovernedCollectionExportGuard exportGuard,
            SanitizedAuthorizationTelemetryPublisher telemetryPublisher
    ) {
        this.registry = Objects.requireNonNull(registry, "registry is required");
        this.providerPort = Objects.requireNonNull(providerPort, "providerPort is required");
        this.fieldUseQueryGuard = Objects.requireNonNull(fieldUseQueryGuard, "fieldUseQueryGuard is required");
        this.maskingProcessor = Objects.requireNonNull(maskingProcessor, "maskingProcessor is required");
        this.obligationCoordinator = Objects.requireNonNull(obligationCoordinator, "obligationCoordinator is required");
        this.exportGuard = Objects.requireNonNull(exportGuard, "exportGuard is required");
        this.telemetryPublisher = Objects.requireNonNull(telemetryPublisher, "telemetryPublisher is required");
    }

    /**
     * Authorizes and executes a governed collection export ({@code CSV}, {@code JSON}, {@code EXCEL_TSV})
     * by {@code decisionPointKey}:
     * <ol>
     *   <li>Evaluates live {@code TARGET} authorization per candidate row and verifies coherent
     *       {@code runtimeRevision} / {@code policySetDigest} across all rows ({@code P12}, {@code P17}, {@code P18});</li>
     *   <li>Fulfills deduplicated {@code BEFORE_EXECUTION} obligations ({@code CC10}, {@code P19});</li>
     *   <li>Delegates to {@link GovernedCollectionExportGuard} to verify live head freshness ({@code P18}),
     *       suppress static/inherited {@code exportable = false} columns ({@code P56}, {@code P60}), and
     *       apply detached per-row masking ({@code P11}, {@code P25});</li>
     *   <li>Fulfills deduplicated {@code BEFORE_COMMIT_OUTBOX} and {@code BEFORE_DISCLOSURE} obligations
     *       before returning the serialized bytes ({@code CC10}, {@code P19}).</li>
     * </ol>
     */
    public <T> SanitizedExportArtifact authorizeAndExecuteCollectionExportByPointKey(
            String decisionPointKey,
            String tenantId,
            String environment,
            ExportFormat format,
            Supplier<OpaRuntimeHead> liveHeadSupplier,
            List<DtoFieldSchemaMetadata> fieldSchemas,
            List<T> candidateRows,
            Function<T, Map<String, Object>> rowTargetFactsExtractor,
            Map<String, FactResolutionStatus> baseFactStatuses
    ) {
        RegisteredDecisionPointContext registered = registry.requireRegisteredPoint(decisionPointKey);
        DecisionPointDescriptor dp = registered.decisionPoint();
        if (!dp.evaluationModes().contains(EvaluationMode.TARGET)) {
            throw new SecurityException("AUTHZ_EVALUATION_MODE_NOT_ADMITTED: Decision point '"
                    + decisionPointKey + "' must admit EvaluationMode.TARGET for per-row export governance (P11/P12)");
        }
        Objects.requireNonNull(liveHeadSupplier, "liveHeadSupplier is required");
        Objects.requireNonNull(fieldSchemas, "fieldSchemas is required");
        Objects.requireNonNull(candidateRows, "candidateRows is required");
        Objects.requireNonNull(rowTargetFactsExtractor, "rowTargetFactsExtractor is required");

        OpaRuntimeHead initialHead = liveHeadSupplier.get();
        if (initialHead == null) {
            throw new SecurityException("AUTHZ_EXPORT_NO_ACTIVE_HEAD: Cannot execute export without active OPA runtime head (P18)");
        }

        List<RowMaskingInput> authorizedRowInputs = new ArrayList<>(candidateRows.size());
        Set<ObligationDirective> deduplicatedObligations = new LinkedHashSet<>();

        for (T row : candidateRows) {
            Map<String, Object> rowFacts = rowTargetFactsExtractor.apply(row);
            Map<String, FactResolutionStatus> statuses = buildFactStatuses(rowFacts, baseFactStatuses);
            ProviderInputProjection input = new ProviderInputProjection(
                    ProviderInputProjection.SCHEMA_VERSION_V1,
                    decisionPointKey,
                    "TARGET",
                    registered.factContract().factContractDigest(),
                    new TemporalContext(Instant.now(), ZoneOffset.UTC),
                    rowFacts,
                    statuses,
                    Set.of()
            );
            ProviderEvaluationEnvelope envelope = providerPort.evaluateTarget(input, null);
            telemetryPublisher.recordEnvelope(
                    tenantId,
                    environment,
                    registered.enforcementBinding().pointAuthorityMode(),
                    envelope
            );
            // P17 & P18: Forbid mixed revisions across rows of the same export unit
            if (!initialHead.runtimeRevision().equals(envelope.runtimeRevision())
                    || !initialHead.policySetDigest().equals(envelope.policySetDigest())) {
                throw new SecurityException("AUTHZ_EXPORT_ROW_REVISION_DRIFT: Row evaluated under revision '"
                        + envelope.runtimeRevision() + "' instead of export unit revision '"
                        + initialHead.runtimeRevision() + "' (P17/P18)");
            }
            if (envelope.gateOutcome() != GateOutcome.ALLOW) {
                fulfillDenyObligations(decisionPointKey, envelope);
                throw new SecurityException("AUTHZ_EXPORT_ROW_DENIED: Row export denied with outcome "
                        + envelope.gateOutcome() + " on '" + decisionPointKey + "' (P11/P12)");
            }
            Set<String> dynamicDenied = fieldUseQueryGuard.extractValueDeniedAttributeIds(envelope.combinedFieldUseEffects());
            List<MaskDirective> masks = envelope.combinedMaskDirectives();
            authorizedRowInputs.add(new RowMaskingInput(row, dynamicDenied, masks));
            deduplicatedObligations.addAll(envelope.combinedObligationDirectives());
        }

        List<ObligationDirective> distinctObligations = deduplicatedObligations.stream()
                .map(dir -> {
                    Map<String, Object> enrichedParams = new LinkedHashMap<>(dir.parameters());
                    enrichedParams.put("exportedRowCount", candidateRows.size());
                    enrichedParams.put("exportFormat", format.name());
                    enrichedParams.put("policySetDigest", initialHead.policySetDigest());
                    return new ObligationDirective(
                            dir.obligationType(),
                            dir.trigger(),
                            dir.fulfillmentBarrier(),
                            enrichedParams
                    );
                })
                .toList();
        Map<String, Object> barrierContext = Map.of(
                "policySetDigest", initialHead.policySetDigest(),
                "exportedRowCount", candidateRows.size()
        );

        enforceBarrier(
                decisionPointKey,
                initialHead.runtimeRevision(),
                EnforcementDisposition.PERMIT,
                ObligationFulfillmentBarrier.BEFORE_EXECUTION,
                distinctObligations,
                barrierContext
        );

        SanitizedExportArtifact artifact = exportGuard.exportCollection(
                format,
                initialHead.runtimeRevision(),
                initialHead.policySetDigest(),
                liveHeadSupplier,
                fieldSchemas,
                registered.admissionRecord().fieldLineageEntries(),
                authorizedRowInputs
        );

        enforceBarrier(
                decisionPointKey,
                initialHead.runtimeRevision(),
                EnforcementDisposition.PERMIT,
                ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX,
                distinctObligations,
                barrierContext
        );
        enforceBarrier(
                decisionPointKey,
                initialHead.runtimeRevision(),
                EnforcementDisposition.PERMIT,
                ObligationFulfillmentBarrier.BEFORE_DISCLOSURE,
                distinctObligations,
                barrierContext
        );

        return artifact;
    }

    /**
     * Authorizes and projects a detached payload for an AI tool or LLM grounding request by
     * {@code decisionPointKey}, enforcing both live OPA {@code TARGET} decisions and static +
     * ancestor-inherited {@code aiUsageMode} lineage restrictions ({@code P11}, {@code P36},
     * {@code P44}, {@code P45}, {@code P47}, {@code P56}, {@code P57}, {@code P62}).
     */
    public SanitizedAiToolProjection authorizeAndProjectAiToolPayloadByPointKey(
            String decisionPointKey,
            String tenantId,
            String environment,
            Object rawTargetEntityOrDto,
            Collection<DtoFieldSchemaMetadata> fieldSchemas,
            Map<String, Object> trustedTargetFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses
    ) {
        RegisteredDecisionPointContext registered = registry.requireRegisteredPoint(decisionPointKey);
        DecisionPointDescriptor dp = registered.decisionPoint();
        if (!dp.evaluationModes().contains(EvaluationMode.TARGET)) {
            throw new SecurityException("AUTHZ_EVALUATION_MODE_NOT_ADMITTED: Decision point '"
                    + decisionPointKey + "' does not admit EvaluationMode.TARGET for AI tool projection (P11/P62)");
        }
        Objects.requireNonNull(rawTargetEntityOrDto, "rawTargetEntityOrDto is required");
        Objects.requireNonNull(fieldSchemas, "fieldSchemas is required");

        Map<String, FactResolutionStatus> statuses = buildFactStatuses(trustedTargetFacts, trustedFactStatuses);
        ProviderInputProjection input = new ProviderInputProjection(
                ProviderInputProjection.SCHEMA_VERSION_V1,
                decisionPointKey,
                "TARGET",
                registered.factContract().factContractDigest(),
                new TemporalContext(Instant.now(), ZoneOffset.UTC),
                trustedTargetFacts,
                statuses,
                Set.of()
        );

        ProviderEvaluationEnvelope envelope = providerPort.evaluateTarget(input, null);
        telemetryPublisher.recordEnvelope(
                tenantId,
                environment,
                registered.enforcementBinding().pointAuthorityMode(),
                envelope
        );
        if (envelope.gateOutcome() != GateOutcome.ALLOW) {
            fulfillDenyObligations(decisionPointKey, envelope);
            throw new SecurityException("AUTHZ_AI_TOOL_SEAM_DENIED: AI tool invocation denied with "
                    + envelope.gateOutcome() + " on '" + decisionPointKey + "' (P11/P62)");
        }

        Map<String, Object> barrierContext = Map.of("policySetDigest", envelope.policySetDigest());
        enforceBarrier(
                decisionPointKey,
                envelope.runtimeRevision(),
                EnforcementDisposition.PERMIT,
                ObligationFulfillmentBarrier.BEFORE_EXECUTION,
                envelope.combinedObligationDirectives(),
                barrierContext
        );

        // P45, P47, P56, P57, P62: Resolve attributes forbidden to AI (including unmapped, un-governed, or METADATA_ONLY fields and their descendants)
        Set<String> aiForbiddenAttributes = resolveAiValueForbiddenAttributes(
                registered.admissionRecord().fieldLineageEntries(),
                fieldSchemas
        );
        Set<String> combinedDenied = new LinkedHashSet<>(
                fieldUseQueryGuard.extractValueDeniedAttributeIds(envelope.combinedFieldUseEffects())
        );
        combinedDenied.addAll(aiForbiddenAttributes);

        DetachedDtoMaskingResult masked = maskingProcessor.projectAndMask(
                rawTargetEntityOrDto,
                fieldSchemas,
                combinedDenied,
                envelope.combinedMaskDirectives()
        );

        enforceBarrier(
                decisionPointKey,
                envelope.runtimeRevision(),
                EnforcementDisposition.PERMIT,
                ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX,
                envelope.combinedObligationDirectives(),
                barrierContext
        );
        enforceBarrier(
                decisionPointKey,
                envelope.runtimeRevision(),
                EnforcementDisposition.PERMIT,
                ObligationFulfillmentBarrier.BEFORE_DISCLOSURE,
                envelope.combinedObligationDirectives(),
                barrierContext
        );

        List<String> allowedWireColumns = new ArrayList<>();
        Map<String, Object> cleanPayload = new LinkedHashMap<>();
        for (DtoFieldSchemaMetadata schema : fieldSchemas) {
            if (!combinedDenied.contains(schema.attributeId())) {
                OptionalValue extracted = extractNestedValue(masked.detachedProjection(), schema.wireFieldName());
                if (extracted.present()) {
                    allowedWireColumns.add(schema.wireFieldName());
                    cleanPayload.put(schema.wireFieldName(), extracted.value());
                }
            }
        }

        return new SanitizedAiToolProjection(
                decisionPointKey,
                envelope.runtimeRevision(),
                envelope.policySetDigest(),
                allowedWireColumns,
                combinedDenied,
                cleanPayload
        );
    }

    /**
     * Authorizes metadata-only governance classification inspection for AI policy authoring without
     * exposing any runtime attribute values or widening {@code aiUsageMode} ({@code P35}, {@code P43}, {@code P62}).
     */
    public List<AiGovernanceMetadataView> inspectGovernanceMetadataForAiAuthoring(
            String decisionPointKey,
            String callerPrincipalId,
            Set<String> callerAuthorities,
            Set<String> allowedTenantIds,
            String requestedTenantId,
            String requiredCatalogAuthority
    ) {
        if (callerPrincipalId == null || callerPrincipalId.isBlank()) {
            throw new SecurityException("AUTHZ_AI_METADATA_UNAUTHENTICATED: Caller principal is required (P62)");
        }
        if (callerAuthorities == null || !callerAuthorities.contains(requiredCatalogAuthority)) {
            throw new SecurityException("AUTHZ_AI_METADATA_AUTHORITY_DENIED: Caller '" + callerPrincipalId
                    + "' lacks authority '" + requiredCatalogAuthority + "' (P35/P62)");
        }
        if (allowedTenantIds == null || requestedTenantId == null || !allowedTenantIds.contains(requestedTenantId)) {
            throw new SecurityException("AUTHZ_AI_METADATA_TENANT_SCOPE_DENIED: Caller '" + callerPrincipalId
                    + "' is not authorized for tenant '" + requestedTenantId + "' (P43/P62)");
        }
        RegisteredDecisionPointContext registered = registry.requireRegisteredPoint(decisionPointKey);
        List<AiGovernanceMetadataView> views = new ArrayList<>();
        for (FieldLineageCatalogEntry entry : registered.admissionRecord().fieldLineageEntries()) {
            views.add(new AiGovernanceMetadataView(
                    entry.attributeId(),
                    entry.conceptId(),
                    entry.wirePath(),
                    entry.sensitivityClassification(),
                    entry.aiUsageMode(),
                    entry.exportable(),
                    entry.allowedUseCategories()
            ));
        }
        return List.copyOf(views);
    }

    private void fulfillDenyObligations(String decisionPointKey, ProviderEvaluationEnvelope envelope) {
        List<ObligationDirective> obligations = envelope.combinedObligationDirectives();
        if (obligations == null || obligations.isEmpty()) {
            return;
        }
        Map<String, Object> ctx = Map.of("policySetDigest", envelope.policySetDigest());
        enforceBarrier(
                decisionPointKey,
                envelope.runtimeRevision(),
                EnforcementDisposition.DENY,
                ObligationFulfillmentBarrier.BEFORE_EXECUTION,
                obligations,
                ctx
        );
        enforceBarrier(
                decisionPointKey,
                envelope.runtimeRevision(),
                EnforcementDisposition.DENY,
                ObligationFulfillmentBarrier.BEFORE_COMMIT_OUTBOX,
                obligations,
                ctx
        );
        enforceBarrier(
                decisionPointKey,
                envelope.runtimeRevision(),
                EnforcementDisposition.DENY,
                ObligationFulfillmentBarrier.BEFORE_DISCLOSURE,
                obligations,
                ctx
        );
    }

    private void enforceBarrier(
            String decisionPointKey,
            String runtimeRevision,
            EnforcementDisposition disposition,
            ObligationFulfillmentBarrier barrier,
            List<ObligationDirective> obligations,
            Map<String, Object> barrierContext
    ) {
        if (obligations == null || obligations.isEmpty()) {
            return;
        }
        List<ObligationFulfillmentResult> results = obligationCoordinator.fulfillAtBarrier(
                decisionPointKey,
                runtimeRevision,
                disposition,
                barrier,
                obligations,
                barrierContext
        );
        if (results.stream().anyMatch(r -> !r.fulfilled())) {
            throw new SecurityException("AUTHZ_OBLIGATION_BARRIER_FAILED: Mandatory obligation at barrier "
                    + barrier + " failed for '" + decisionPointKey + "' (CC10/P19)");
        }
    }

    private static Map<String, FactResolutionStatus> buildFactStatuses(
            Map<String, Object> facts,
            Map<String, FactResolutionStatus> explicitStatuses
    ) {
        Map<String, FactResolutionStatus> map = new LinkedHashMap<>();
        if (facts != null) {
            for (String k : facts.keySet()) {
                map.put(k, FactResolutionStatus.PRESENT);
            }
        }
        if (explicitStatuses != null) {
            map.putAll(explicitStatuses);
        }
        return map;
    }

    private static Set<String> resolveAiValueForbiddenAttributes(
            List<FieldLineageCatalogEntry> entries,
            Collection<DtoFieldSchemaMetadata> fieldSchemas
    ) {
        Map<String, List<FieldLineageCatalogEntry>> byAttr = new LinkedHashMap<>();
        for (FieldLineageCatalogEntry entry : entries) {
            byAttr.computeIfAbsent(entry.attributeId(), k -> new ArrayList<>()).add(entry);
        }
        Set<String> forbidden = new LinkedHashSet<>();
        for (FieldLineageCatalogEntry entry : entries) {
            if (isAiValueForbiddenOnEntry(entry) || hasAiValueForbiddenAncestor(entry, byAttr, new LinkedHashSet<>())) {
                forbidden.add(entry.attributeId());
            }
        }
        // P47 & P57: Any schema field without an explicit lineage catalog entry fails closed and is forbidden to AI
        for (DtoFieldSchemaMetadata schema : fieldSchemas) {
            if (!byAttr.containsKey(schema.attributeId())) {
                forbidden.add(schema.attributeId());
            }
        }
        return forbidden;
    }

    private static boolean isAiValueForbiddenOnEntry(FieldLineageCatalogEntry entry) {
        // P57: Missing/heuristic governance is never admitted permissively for AI usage
        if (!entry.explicitGovernanceDeclared()) {
            return true;
        }
        String mode = entry.aiUsageMode().trim().toUpperCase(Locale.ROOT);
        // P57 & P62: Fail-closed allowlist — only explicit ALLOWED / VALUE_ALLOWED permits value disclosure to AI;
        // DENIED, FORBIDDEN, SCHEMA_METADATA_ONLY, METADATA_ONLY, or any unrecognized mode forbids AI value access.
        return !("ALLOWED".equals(mode) || "VALUE_ALLOWED".equals(mode));
    }

    private static boolean hasAiValueForbiddenAncestor(
            FieldLineageCatalogEntry current,
            Map<String, List<FieldLineageCatalogEntry>> byAttr,
            Set<String> visited
    ) {
        if (!visited.add(current.attributeId())) {
            return false;
        }
        for (String parentId : current.upstreamAttributeRefs()) {
            List<FieldLineageCatalogEntry> parents = byAttr.getOrDefault(parentId, List.of());
            if (parents.isEmpty()) {
                // P45 / P47 / P56: Unresolved or missing upstream lineage parent fails closed
                return true;
            }
            for (FieldLineageCatalogEntry parent : parents) {
                if (isAiValueForbiddenOnEntry(parent) || hasAiValueForbiddenAncestor(parent, byAttr, visited)) {
                    return true;
                }
            }
        }
        return false;
    }

    private record OptionalValue(boolean present, Object value) {}

    @SuppressWarnings("unchecked")
    private static OptionalValue extractNestedValue(Map<String, Object> projection, String wireFieldName) {
        if (projection.containsKey(wireFieldName)) {
            return new OptionalValue(true, projection.get(wireFieldName));
        }
        String normalized = wireFieldName.startsWith("/") ? wireFieldName.substring(1) : wireFieldName;
        String[] segments = normalized.contains("/") ? normalized.split("/") : normalized.split("\\.");
        if (segments.length <= 1) {
            return new OptionalValue(false, null);
        }
        Object current = projection;
        for (String seg : segments) {
            if (!(current instanceof Map<?, ?> rawMap)) {
                return new OptionalValue(false, null);
            }
            Map<String, Object> map = (Map<String, Object>) rawMap;
            if (!map.containsKey(seg)) {
                return new OptionalValue(false, null);
            }
            current = map.get(seg);
        }
        return new OptionalValue(true, current);
    }
}
