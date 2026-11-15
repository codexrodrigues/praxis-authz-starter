package org.praxisplatform.authz.host.metadata;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.AiGovernanceMetadataView;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.SanitizedAiToolProjection;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.TargetReadProjectionEvaluation;
import org.praxisplatform.uischema.determination.ReactiveDeterminationDefinition;
import org.praxisplatform.uischema.determination.ReactiveDeterminationDefinitionProvider;
import org.praxisplatform.uischema.determination.ReactiveDeterminationInputBinding;
import org.praxisplatform.uischema.determination.ReactiveDeterminationOutputBinding;

/**
 * Governed implementation of {@code praxis-metadata-starter}'s
 * {@link ReactiveDeterminationDefinitionProvider} and runtime execution bridge for
 * non-persistent {@code POST} reactive determinations and AI Context / Tool Grounding
 * projections ({@code P05}, {@code P11}, {@code P12}, {@code P13}, {@code P14},
 * {@code P46}, {@code P47}, {@code P49}, {@code P50}, {@code P57}, {@code P62}).
 *
 * <p>Enforces three complementary layers of governance:</p>
 * <ol>
 *   <li><b>Bootstrap Contract Validation ({@link #definitions()}):</b> Verifies that no
 *       {@link ReactiveDeterminationDefinition} binds an {@code input} or {@code output} JSON
 *       pointer to an attribute whose {@link FieldUseCategory#VALUE} is statically denied in
 *       {@link IntrospectedDtoGovernanceContract#baselineFieldUseDirectives()};</li>
 *   <li><b>Runtime Non-Persistent Determination Execution
 *       ({@link #evaluateGovernedDetermination}):</b> Evaluates {@code TARGET} scope via
 *       {@link AuthzGovernedResourceServiceSupport} (preventing cross-entity
 *       or out-of-scope probing via form determination endpoints), runs the determination logic
 *       against the raw unmasked candidate entity ({@code STEP_12}/{@code STEP_13}), applies
 *       detached DTO masking ({@link DetachedDtoMaskingProcessor}) to the determination response
 *       payload ({@code STEP_15}), never writes premature {@code BEFORE_COMMIT_OUTBOX} entries,
 *       and deterministically cleans up {@code ThreadLocal} contexts;</li>
 *   <li><b>AI Context &amp; Tool Grounding Projection ({@link #projectGovernedAiContext}):</b>
 *       Evaluates live {@code TARGET} authorization and suppresses all attributes marked
 *       {@code aiAllowed = false} or {@code LGPD_SENSITIVE_DATA} in
 *       {@link IntrospectedDtoGovernanceContract#aiContextDeniedAttributeIds()} ({@code P47},
 *       {@code P57}, {@code P62}), returning a {@link SanitizedAiToolProjection} with zero
 *       sensitive values leaked to LLM contexts or tool responses.</li>
 * </ol>
 */
public final class AuthzGovernedReactiveDeterminationProvider implements ReactiveDeterminationDefinitionProvider {

    private final ReactiveDeterminationDefinitionProvider delegate;
    private final AuthzGovernedResourceServiceSupport serviceSupport;
    private final IntrospectedDtoGovernanceContract governanceContract;
    private final DetachedDtoMaskingProcessor maskingProcessor;

    public AuthzGovernedReactiveDeterminationProvider(
            ReactiveDeterminationDefinitionProvider delegate,
            AuthzGovernedResourceServiceSupport serviceSupport,
            IntrospectedDtoGovernanceContract governanceContract
    ) {
        this.delegate = Objects.requireNonNull(delegate, "delegate is required");
        this.serviceSupport = Objects.requireNonNull(serviceSupport, "serviceSupport is required");
        this.governanceContract = Objects.requireNonNull(governanceContract, "governanceContract is required");
        this.maskingProcessor = new DetachedDtoMaskingProcessor();
    }

    @Override
    public Collection<ReactiveDeterminationDefinition> definitions() {
        Collection<ReactiveDeterminationDefinition> rawDefinitions = delegate.definitions();
        if (rawDefinitions == null || rawDefinitions.isEmpty()) {
            return List.of();
        }
        Set<String> staticallyValueDenied = collectStaticallyDeniedValueAttributes();
        List<ReactiveDeterminationDefinition> validated = new ArrayList<>(rawDefinitions.size());
        for (ReactiveDeterminationDefinition def : rawDefinitions) {
            if (def == null) {
                continue;
            }
            validateDefinitionPointers(def, staticallyValueDenied);
            validated.add(def);
        }
        return List.copyOf(validated);
    }

    /**
     * Executes a governed non-persistent reactive determination ({@code POST} preview endpoint),
     * automatically applying the live OPA {@link MaskDirective}s and dynamic
     * {@code valueDeniedAttributeIds} returned by the {@code TARGET} evaluation ({@code P10.6-R05}).
     */
    public Map<String, Object> evaluateGovernedDetermination(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            Map<String, Object> trustedTargetFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses,
            Supplier<Object> rawDraftDeterminationSupplier
    ) {
        return evaluateGovernedDetermination(
                decisionPoint,
                factContractDigest,
                trustedTargetFacts,
                trustedFactStatuses,
                rawDraftDeterminationSupplier,
                List.of()
        );
    }

    /**
     * Executes a governed non-persistent reactive determination ({@code POST} preview endpoint):
     * <ol>
     *   <li>Verifies {@code TARGET} scope via {@link AuthzGovernedResourceServiceSupport}
     *       so out-of-scope cross-entity references or target records fail closed with
     *       {@link SecurityException} ({@code P05}, {@code P12});</li>
     *   <li>Invokes {@code rawDraftDeterminationSupplier} on the raw unmasked entity/candidate
     *       (preserving {@code P13}/{@code P14} rule &amp; calculation fidelity);</li>
     *   <li>Applies detached DTO masking ({@link DetachedDtoMaskingProcessor}) using both live
     *       OPA {@link MaskDirective}s and any caller-supplied directives to the returned
     *       response map/DTO so masked or value-denied attributes are never disclosed raw to the
     *       form client ({@code P50});</li>
     *   <li>Guarantees zero {@code BEFORE_COMMIT_OUTBOX} mutations and cleans up transient
     *       {@code ThreadLocal} contexts in {@code finally}.</li>
     * </ol>
     */
    public Map<String, Object> evaluateGovernedDetermination(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            Map<String, Object> trustedTargetFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses,
            Supplier<Object> rawDraftDeterminationSupplier,
            List<MaskDirective> maskDirectives
    ) {
        return evaluateGovernedDetermination(
                decisionPoint,
                factContractDigest,
                trustedTargetFacts,
                trustedFactStatuses,
                rawDraftDeterminationSupplier,
                Set.of(),
                maskDirectives
        );
    }

    /**
     * Executes a governed non-persistent reactive determination merging any primary-resource
     * {@code extraValueDeniedAttributeIds} and {@code maskDirectives} with the live {@code TARGET}
     * evaluation of {@code decisionPoint} ({@code Fase P10.18-A}, {@code P05}, {@code P12}, {@code P50}).
     */
    public Map<String, Object> evaluateGovernedDetermination(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            Map<String, Object> trustedTargetFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses,
            Supplier<Object> rawDraftDeterminationSupplier,
            Set<String> extraValueDeniedAttributeIds,
            List<MaskDirective> maskDirectives
    ) {
        Objects.requireNonNull(decisionPoint, "decisionPoint is required");
        Objects.requireNonNull(rawDraftDeterminationSupplier, "rawDraftDeterminationSupplier is required");
        try {
            TargetReadProjectionEvaluation targetEval = serviceSupport.authorizeTargetEntityProjection(
                    decisionPoint,
                    factContractDigest,
                    trustedTargetFacts,
                    trustedFactStatuses
            );
            Object rawResult = rawDraftDeterminationSupplier.get();
            if (rawResult == null) {
                return Map.of();
            }
            Set<String> effectiveValueDenied = new LinkedHashSet<>(collectStaticallyDeniedValueAttributes());
            effectiveValueDenied.addAll(targetEval.valueDeniedAttributeIds());
            if (extraValueDeniedAttributeIds != null && !extraValueDeniedAttributeIds.isEmpty()) {
                effectiveValueDenied.addAll(extraValueDeniedAttributeIds);
            }

            List<MaskDirective> effectiveMasks = new ArrayList<>(targetEval.maskDirectives());
            if (maskDirectives != null && !maskDirectives.isEmpty()) {
                effectiveMasks.addAll(maskDirectives);
            }

            DetachedDtoMaskingResult masked = maskingProcessor.projectAndMask(
                    rawResult,
                    governanceContract.fieldSchemas(),
                    effectiveValueDenied,
                    effectiveMasks
            );
            if (rawResult instanceof Map<?, ?> rawMap) {
                Map<String, Object> merged = new LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
                    String key = String.valueOf(entry.getKey());
                    boolean isGoverned = governanceContract.fieldSchemas().stream()
                            .anyMatch(s -> s.wireFieldName().equals(key) || s.attributeId().equals(key));
                    if (isGoverned) {
                        if (masked.detachedProjection().containsKey(key)) {
                            merged.put(key, masked.detachedProjection().get(key));
                        }
                    } else {
                        merged.put(key, entry.getValue());
                    }
                }
                return Map.copyOf(merged);
            }
            return masked.detachedProjection();
        } finally {
            serviceSupport.clearTransientRequestContexts();
        }
    }

    /**
     * Authorizes and projects a detached payload for an AI tool, copilot, or RAG grounding
     * consumer directly from an {@link IntrospectedDtoGovernanceContract}-governed DTO or entity,
     * deriving {@code runtimeRevision}, {@code policySetDigest}, and {@link MaskDirective}s
     * directly from the live OPA {@code TARGET} evaluation ({@code P10.6-R05}, {@code P11},
     * {@code P46}, {@code P47}, {@code P57}, {@code P62}).
     */
    public SanitizedAiToolProjection projectGovernedAiContext(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            Object rawTargetEntityOrDto,
            Map<String, Object> trustedTargetFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses
    ) {
        return projectGovernedAiContext(
                decisionPoint,
                factContractDigest,
                null,
                null,
                rawTargetEntityOrDto,
                trustedTargetFacts,
                trustedFactStatuses,
                Set.of(),
                List.of()
        );
    }

    /**
     * Authorizes and projects a detached payload for an AI tool, copilot, or RAG grounding
     * consumer directly from an {@link IntrospectedDtoGovernanceContract}-governed DTO or entity
     * ({@code P11}, {@code P46}, {@code P47}, {@code P57}, {@code P62}).
     *
     * <p>Enforces live {@code TARGET} authorization and suppresses all attributes in
     * {@link IntrospectedDtoGovernanceContract#aiContextDeniedAttributeIds()} (such as
     * {@code @DomainGovernance(aiAllowed = false)} or {@code LGPD_SENSITIVE_DATA}) even when the
     * caller is permitted to view a masked representation in the human UI.</p>
     */
    public SanitizedAiToolProjection projectGovernedAiContext(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            String runtimeRevision,
            String policySetDigest,
            Object rawTargetEntityOrDto,
            Map<String, Object> trustedTargetFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses,
            List<MaskDirective> maskDirectives
    ) {
        return projectGovernedAiContext(
                decisionPoint,
                factContractDigest,
                runtimeRevision,
                policySetDigest,
                rawTargetEntityOrDto,
                trustedTargetFacts,
                trustedFactStatuses,
                Set.of(),
                maskDirectives
        );
    }

    /**
     * Authorizes and projects a detached payload for an AI tool, copilot, or RAG grounding
     * consumer merging any primary-resource {@code extraValueDeniedAttributeIds} and
     * {@code maskDirectives} with the live {@code TARGET} evaluation of {@code decisionPoint}
     * ({@code Fase P10.18-A}, {@code P11}, {@code P46}, {@code P47}, {@code P57}, {@code P62}).
     */
    public SanitizedAiToolProjection projectGovernedAiContext(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            String runtimeRevision,
            String policySetDigest,
            Object rawTargetEntityOrDto,
            Map<String, Object> trustedTargetFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses,
            Set<String> extraValueDeniedAttributeIds,
            List<MaskDirective> maskDirectives
    ) {
        Objects.requireNonNull(decisionPoint, "decisionPoint is required");
        Objects.requireNonNull(rawTargetEntityOrDto, "rawTargetEntityOrDto is required");
        try {
            TargetReadProjectionEvaluation targetEval = serviceSupport.authorizeTargetEntityProjection(
                    decisionPoint,
                    factContractDigest,
                    trustedTargetFacts,
                    trustedFactStatuses
            );
            Set<String> suppressedAiAttributes = new LinkedHashSet<>(governanceContract.aiContextDeniedAttributeIds());
            suppressedAiAttributes.addAll(collectStaticallyDeniedValueAttributes());
            suppressedAiAttributes.addAll(targetEval.valueDeniedAttributeIds());
            if (extraValueDeniedAttributeIds != null && !extraValueDeniedAttributeIds.isEmpty()) {
                suppressedAiAttributes.addAll(extraValueDeniedAttributeIds);
            }

            List<MaskDirective> effectiveMasks = new ArrayList<>(targetEval.maskDirectives());
            if (maskDirectives != null && !maskDirectives.isEmpty()) {
                effectiveMasks.addAll(maskDirectives);
            }

            DetachedDtoMaskingResult masked = maskingProcessor.projectAndMask(
                    rawTargetEntityOrDto,
                    governanceContract.fieldSchemas(),
                    suppressedAiAttributes,
                    effectiveMasks
            );
            List<String> allowedWireColumns = new ArrayList<>(masked.detachedProjection().keySet());
            String resolvedRev = runtimeRevision != null && !runtimeRevision.isBlank()
                    ? runtimeRevision
                    : targetEval.runtimeRevision();
            String resolvedDigest = policySetDigest != null && !policySetDigest.isBlank()
                    ? policySetDigest
                    : targetEval.policySetDigest();
            return new SanitizedAiToolProjection(
                    decisionPoint.identity().pointKey(),
                    resolvedRev == null ? "rev-unknown" : resolvedRev,
                    resolvedDigest == null ? "sha256:unknown" : resolvedDigest,
                    allowedWireColumns,
                    suppressedAiAttributes,
                    masked.detachedProjection()
            );
        } finally {
            serviceSupport.clearTransientRequestContexts();
        }
    }

    /**
     * Returns value-free AI authoring and discovery governance metadata derived from the
     * introspected DTO contract ({@code P62}).
     */
    public List<AiGovernanceMetadataView> projectAiGovernanceMetadata() {
        Set<String> aiDenied = governanceContract.aiContextDeniedAttributeIds();
        Set<String> nonExportable = governanceContract.nonExportableFieldNames();
        List<AiGovernanceMetadataView> views = new ArrayList<>(governanceContract.fieldSchemas().size());

        for (DtoFieldSchemaMetadata schema : governanceContract.fieldSchemas()) {
            boolean isAiDenied = aiDenied.contains(schema.attributeId()) || aiDenied.contains(schema.wireFieldName());
            boolean isExportable = !nonExportable.contains(schema.attributeId())
                    && !nonExportable.contains(schema.wireFieldName());
            Set<FieldUseCategory> allowedCategories = new LinkedHashSet<>(List.of(FieldUseCategory.values()));
            for (FieldUseEffectDirective dir : governanceContract.baselineFieldUseDirectives()) {
                if (dir.effect() == RuleEffect.DENY
                        && (dir.attributeId().equals(schema.attributeId())
                                || dir.attributeId().equals(schema.wireFieldName()))) {
                    allowedCategories.remove(dir.category());
                }
            }
            views.add(new AiGovernanceMetadataView(
                    schema.attributeId(),
                    schema.attributeId(),
                    "/" + schema.wireFieldName(),
                    isAiDenied ? "RESTRICTED_SENSITIVE" : "GOVERNED",
                    isAiDenied ? "NONE" : "ALLOWED",
                    isExportable,
                    Set.copyOf(allowedCategories)
            ));
        }
        return List.copyOf(views);
    }

    private void validateDefinitionPointers(
            ReactiveDeterminationDefinition def,
            Set<String> staticallyValueDenied
    ) {
        if (def.sourcePaths() != null) {
            for (String sourcePath : def.sourcePaths()) {
                assertPointerAllowed(def.id(), "sourcePath", sourcePath, staticallyValueDenied);
            }
        }
        if (def.inputs() != null) {
            for (ReactiveDeterminationInputBinding input : def.inputs()) {
                if (input != null) {
                    assertPointerAllowed(def.id(), "input.fieldPath", input.fieldPath(), staticallyValueDenied);
                    assertPointerAllowed(def.id(), "input.requestPath", input.requestPath(), staticallyValueDenied);
                }
            }
        }
        if (def.outputs() != null) {
            for (ReactiveDeterminationOutputBinding output : def.outputs()) {
                if (output != null) {
                    assertPointerAllowed(def.id(), "output.responsePath", output.responsePath(), staticallyValueDenied);
                    assertPointerAllowed(def.id(), "output.fieldPath", output.fieldPath(), staticallyValueDenied);
                }
            }
        }
    }

    private void assertPointerAllowed(
            String determinationId,
            String bindingRole,
            String jsonPointer,
            Set<String> staticallyValueDenied
    ) {
        if (jsonPointer == null || jsonPointer.isBlank()) {
            return;
        }
        String mappedAttr = governanceContract.wirePointerToAttributeIdMap().get(jsonPointer);
        String fieldName = jsonPointer.startsWith("/") ? jsonPointer.substring(1) : jsonPointer;
        int lastSlash = jsonPointer.lastIndexOf('/');
        String leafName = lastSlash >= 0 ? jsonPointer.substring(lastSlash + 1) : fieldName;
        String leafMappedAttr = governanceContract.wirePointerToAttributeIdMap().get("/" + leafName);
        if ((mappedAttr != null && staticallyValueDenied.contains(mappedAttr))
                || (leafMappedAttr != null && staticallyValueDenied.contains(leafMappedAttr))
                || staticallyValueDenied.contains(fieldName)
                || staticallyValueDenied.contains(leafName)) {
            throw new IllegalArgumentException(
                    "AUTHZ_DETERMINATION_FORBIDDEN_LINEAGE_BINDING: ReactiveDetermination '"
                            + determinationId + "' cannot bind " + bindingRole + " '" + jsonPointer
                            + "' to value-denied attribute '"
                            + (mappedAttr != null ? mappedAttr : (leafMappedAttr != null ? leafMappedAttr : leafName)) + "'"
            );
        }
    }

    private Set<String> collectStaticallyDeniedValueAttributes() {
        Set<String> denied = new LinkedHashSet<>();
        for (FieldUseEffectDirective dir : governanceContract.baselineFieldUseDirectives()) {
            if (dir.category() == FieldUseCategory.VALUE && dir.effect() == RuleEffect.DENY) {
                denied.add(dir.attributeId());
            }
        }
        return Set.copyOf(denied);
    }
}
