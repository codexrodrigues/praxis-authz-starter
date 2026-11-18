package org.praxisplatform.authz.host.metadata;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.AdvisoryOperationAvailability;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.OperationAvailabilityEvaluation;
import org.praxisplatform.uischema.action.ActionAvailabilityContext;
import org.praxisplatform.uischema.action.ActionAvailabilityRule;
import org.praxisplatform.uischema.action.ActionDefinition;
import org.praxisplatform.uischema.action.ActionScope;
import org.praxisplatform.uischema.capability.AvailabilityDecision;
import org.praxisplatform.uischema.capability.ResourceOperationAvailabilityContext;
import org.praxisplatform.uischema.capability.ResourceOperationAvailabilityProvider;
import org.praxisplatform.uischema.capability.ResourceStateSnapshot;
import org.praxisplatform.uischema.capability.ResourceStateSnapshotProvider;
import org.praxisplatform.uischema.surface.SurfaceAvailabilityContext;
import org.praxisplatform.uischema.surface.SurfaceAvailabilityRule;
import org.praxisplatform.uischema.surface.SurfaceDefinition;
import org.praxisplatform.uischema.surface.SurfaceKind;
import org.praxisplatform.uischema.surface.SurfaceScope;

/**
 * Direct host bridge implementing {@link ResourceOperationAvailabilityProvider},
 * {@link ActionAvailabilityRule}, and {@link SurfaceAvailabilityRule} from
 * {@code praxis-metadata-starter} backed by {@link MetadataResourceAuthorizationSeam}
 * ({@code Fases P10.4..P10.9}, {@code P10}, {@code P16}, {@code P17}).
 *
 * <p>Guarantees that {@code GET /{resource}/capabilities}, {@code GET /{resource}/{id}/capabilities},
 * {@code GET /{resource}/actions}, {@code GET /schemas/actions}, {@code GET /schemas/surfaces},
 * {@code duplicate-draft}, HATEOAS {@code _links}, and {@code GovernedResourceCommandExecutor}
 * pre-checks share one deterministic OPA + {@link DualScopeDelegationSpec} decision boundary
 * without leaking item state into {@code COLLECTION} operations or exposing private security facts
 * in public discovery metadata.</p>
 */
public final class AuthzResourceOperationAvailabilityProvider
        implements ResourceOperationAvailabilityProvider, ActionAvailabilityRule, SurfaceAvailabilityRule {

    /**
     * Authoritative caller fact context resolved once per availability evaluation.
     *
     * @param trustedSubjectFacts authoritative subject facts ({@code subject.*})
     * @param trustedSubjectFactStatuses resolution statuses for {@code trustedSubjectFacts}
     * @param callerMatchesCedente whether the caller holds {@code Cedente} custody
     * @param callerMatchesCessionario whether the caller holds {@code Cessionário} custody
     * @param tenantId optional authoritative caller tenant ID for cross-tenant snapshot guards
     */
    public record CallerAvailabilityFactContext(
            Map<String, Object> trustedSubjectFacts,
            Map<String, FactResolutionStatus> trustedSubjectFactStatuses,
            boolean callerMatchesCedente,
            boolean callerMatchesCessionario,
            String tenantId,
            Set<String> allowedHardScopeValues,
            boolean sharedUnrestrictedScope,
            boolean readOnlyConsolidation
    ) {
        /** Compact constructor enforcing non-null maps. */
        public CallerAvailabilityFactContext {
            trustedSubjectFacts = trustedSubjectFacts == null ? Map.of() : Map.copyOf(trustedSubjectFacts);
            trustedSubjectFactStatuses = trustedSubjectFactStatuses == null
                    ? Map.of()
                    : Map.copyOf(trustedSubjectFactStatuses);
            allowedHardScopeValues = allowedHardScopeValues == null ? null : Set.copyOf(allowedHardScopeValues);
            readOnlyConsolidation = readOnlyConsolidation
                    || Boolean.TRUE.equals(trustedSubjectFacts.get(AuthzCallerContext.FACT_READ_ONLY_CONSOLIDATION_SCOPE))
                    || Boolean.TRUE.equals(trustedSubjectFacts.get("subject.readOnlyConsolidationScope"));
        }

        /** Backward-compatible 7-argument constructor. */
        public CallerAvailabilityFactContext(
                Map<String, Object> trustedSubjectFacts,
                Map<String, FactResolutionStatus> trustedSubjectFactStatuses,
                boolean callerMatchesCedente,
                boolean callerMatchesCessionario,
                String tenantId,
                Set<String> allowedHardScopeValues,
                boolean sharedUnrestrictedScope
        ) {
            this(
                    trustedSubjectFacts,
                    trustedSubjectFactStatuses,
                    callerMatchesCedente,
                    callerMatchesCessionario,
                    tenantId,
                    allowedHardScopeValues,
                    sharedUnrestrictedScope,
                    false
            );
        }

        /** Builds caller availability context resolving multi-org hard-scope values from {@code spec}. */
        public static CallerAvailabilityFactContext fromGovernanceSpec(
                AuthzResourceGovernanceSpec<?> spec,
                AuthzCallerContext callerCtx,
                boolean callerMatchesOrigin,
                boolean callerMatchesDestination
        ) {
            Objects.requireNonNull(spec, "spec is required");
            Objects.requireNonNull(callerCtx, "callerCtx is required");
            HardScopeResolver.HardScopeSelection selection = spec.resolveHardScopeSelection(callerCtx);
            Set<String> allowed = null;
            boolean shared = selection.isSharedUnrestricted();
            if (!shared) {
                if (selection.isDenied()) {
                    allowed = Set.of();
                } else {
                    Set<String> values = new java.util.LinkedHashSet<>();
                    for (Object value : selection.multiValues()) {
                        if (value != null) {
                            values.add(String.valueOf(value));
                        }
                    }
                    allowed = Set.copyOf(values);
                }
            }
            return new CallerAvailabilityFactContext(
                    callerCtx.subjectAndEnvironmentFacts(),
                    callerCtx.factStatuses(),
                    callerMatchesOrigin,
                    callerMatchesDestination,
                    callerCtx.tenantId(),
                    allowed,
                    shared,
                    selection.readOnlyConsolidation()
            );
        }

        /** Backward-compatible 5-argument constructor. */
        public CallerAvailabilityFactContext(
                Map<String, Object> trustedSubjectFacts,
                Map<String, FactResolutionStatus> trustedSubjectFactStatuses,
                boolean callerMatchesCedente,
                boolean callerMatchesCessionario,
                String tenantId
        ) {
            this(
                    trustedSubjectFacts,
                    trustedSubjectFactStatuses,
                    callerMatchesCedente,
                    callerMatchesCessionario,
                    tenantId,
                    null,
                    false
            );
        }

        /** Backward-compatible 4-argument constructor. */
        public CallerAvailabilityFactContext(
                Map<String, Object> trustedSubjectFacts,
                Map<String, FactResolutionStatus> trustedSubjectFactStatuses,
                boolean callerMatchesCedente,
                boolean callerMatchesCessionario
        ) {
            this(trustedSubjectFacts, trustedSubjectFactStatuses, callerMatchesCedente, callerMatchesCessionario, null);
        }
    }

    /**
     * Resource-level availability policy registration binding a {@code resourceKey} to its
     * governed {@link DecisionPointDescriptor}, {@link DualScopeDelegationSpec}, and operation
     * target attribute mappings.
     *
     * @param resourceKey canonical {@code @ApiResource(resourceKey = ...)}
     * @param decisionPoint governed decision point descriptor
     * @param factContractDigest canonical fact contract digest
     * @param dualScopeSpec optional dual-scope custody specification
     * @param operationModifiedAttributes map from operation/action/surface ID to modified {@code attributeId}s
     * @param callerContextSupplier supplier of authoritative caller facts and custody flags
     * @param snapshotTargetFactExtractor function extracting {@code resource.*} facts from a {@link ResourceStateSnapshot}
     * @param itemSnapshotResolver optional per-resource resolver loading {@link ResourceStateSnapshot} by raw ID
     * @param itemCedenteEvaluator optional per-item evaluator of {@code Cedente} custody
     * @param itemCessionarioEvaluator optional per-item evaluator of {@code Cessionário} custody
     * @param actionDecisionPoints optional per-action {@link DecisionPointDescriptor} overrides
     * @param surfaceDecisionPoints optional per-surface {@link DecisionPointDescriptor} overrides
     */
    public record ResourceAvailabilityPolicyBinding(
            String resourceKey,
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            DualScopeDelegationSpec dualScopeSpec,
            Map<String, Set<String>> operationModifiedAttributes,
            Supplier<CallerAvailabilityFactContext> callerContextSupplier,
            Function<ResourceStateSnapshot, Map<String, Object>> snapshotTargetFactExtractor,
            Function<Object, Optional<ResourceStateSnapshot>> itemSnapshotResolver,
            BiFunction<CallerAvailabilityFactContext, ResourceStateSnapshot, Boolean> itemCedenteEvaluator,
            BiFunction<CallerAvailabilityFactContext, ResourceStateSnapshot, Boolean> itemCessionarioEvaluator,
            Map<String, DecisionPointDescriptor> actionDecisionPoints,
            Map<String, DecisionPointDescriptor> surfaceDecisionPoints,
            Function<ResourceStateSnapshot, Map<String, FactResolutionStatus>> snapshotTargetFactStatusExtractor
    ) {
        /** Compact constructor enforcing required fields. */
        public ResourceAvailabilityPolicyBinding {
            Objects.requireNonNull(resourceKey, "resourceKey is required");
            Objects.requireNonNull(decisionPoint, "decisionPoint is required");
            Objects.requireNonNull(factContractDigest, "factContractDigest is required");
            operationModifiedAttributes = operationModifiedAttributes == null
                    ? Map.of()
                    : Map.copyOf(operationModifiedAttributes);
            Objects.requireNonNull(callerContextSupplier, "callerContextSupplier is required");
            Objects.requireNonNull(snapshotTargetFactExtractor, "snapshotTargetFactExtractor is required");
            actionDecisionPoints = actionDecisionPoints == null
                    ? Map.of()
                    : Map.copyOf(actionDecisionPoints);
            surfaceDecisionPoints = surfaceDecisionPoints == null
                    ? Map.of()
                    : Map.copyOf(surfaceDecisionPoints);
        }

        /** Backward-compatible 12-argument constructor. */
        public ResourceAvailabilityPolicyBinding(
                String resourceKey,
                DecisionPointDescriptor decisionPoint,
                String factContractDigest,
                DualScopeDelegationSpec dualScopeSpec,
                Map<String, Set<String>> operationModifiedAttributes,
                Supplier<CallerAvailabilityFactContext> callerContextSupplier,
                Function<ResourceStateSnapshot, Map<String, Object>> snapshotTargetFactExtractor,
                Function<Object, Optional<ResourceStateSnapshot>> itemSnapshotResolver,
                BiFunction<CallerAvailabilityFactContext, ResourceStateSnapshot, Boolean> itemCedenteEvaluator,
                BiFunction<CallerAvailabilityFactContext, ResourceStateSnapshot, Boolean> itemCessionarioEvaluator,
                Map<String, DecisionPointDescriptor> actionDecisionPoints,
                Map<String, DecisionPointDescriptor> surfaceDecisionPoints
        ) {
            this(
                    resourceKey,
                    decisionPoint,
                    factContractDigest,
                    dualScopeSpec,
                    operationModifiedAttributes,
                    callerContextSupplier,
                    snapshotTargetFactExtractor,
                    itemSnapshotResolver,
                    itemCedenteEvaluator,
                    itemCessionarioEvaluator,
                    actionDecisionPoints,
                    surfaceDecisionPoints,
                    null
            );
        }

        /** Backward-compatible 10-argument constructor. */
        public ResourceAvailabilityPolicyBinding(
                String resourceKey,
                DecisionPointDescriptor decisionPoint,
                String factContractDigest,
                DualScopeDelegationSpec dualScopeSpec,
                Map<String, Set<String>> operationModifiedAttributes,
                Supplier<CallerAvailabilityFactContext> callerContextSupplier,
                Function<ResourceStateSnapshot, Map<String, Object>> snapshotTargetFactExtractor,
                Function<Object, Optional<ResourceStateSnapshot>> itemSnapshotResolver,
                BiFunction<CallerAvailabilityFactContext, ResourceStateSnapshot, Boolean> itemCedenteEvaluator,
                BiFunction<CallerAvailabilityFactContext, ResourceStateSnapshot, Boolean> itemCessionarioEvaluator
        ) {
            this(
                    resourceKey,
                    decisionPoint,
                    factContractDigest,
                    dualScopeSpec,
                    operationModifiedAttributes,
                    callerContextSupplier,
                    snapshotTargetFactExtractor,
                    itemSnapshotResolver,
                    itemCedenteEvaluator,
                    itemCessionarioEvaluator,
                    Map.of(),
                    Map.of()
            );
        }

        /** Backward-compatible 7-argument constructor. */
        public ResourceAvailabilityPolicyBinding(
                String resourceKey,
                DecisionPointDescriptor decisionPoint,
                String factContractDigest,
                DualScopeDelegationSpec dualScopeSpec,
                Map<String, Set<String>> operationModifiedAttributes,
                Supplier<CallerAvailabilityFactContext> callerContextSupplier,
                Function<ResourceStateSnapshot, Map<String, Object>> snapshotTargetFactExtractor
        ) {
            this(
                    resourceKey,
                    decisionPoint,
                    factContractDigest,
                    dualScopeSpec,
                    operationModifiedAttributes,
                    callerContextSupplier,
                    snapshotTargetFactExtractor,
                    null,
                    null,
                    null,
                    Map.of(),
                    Map.of()
            );
        }

        /**
         * Resolves the effective {@link DecisionPointDescriptor} for a generic {@code operationId}
         * ({@code Fase P10.10}).
         */
        public DecisionPointDescriptor resolveDecisionPoint(String operationId) {
            if (operationId != null) {
                DecisionPointDescriptor actionDp = actionDecisionPoints.get(operationId);
                if (actionDp != null) {
                    return actionDp;
                }
                DecisionPointDescriptor surfaceDp = surfaceDecisionPoints.get(operationId);
                if (surfaceDp != null) {
                    return surfaceDp;
                }
            }
            return decisionPoint;
        }

        /**
         * Resolves the effective {@link DecisionPointDescriptor} specifically for a {@code @WorkflowAction}
         * ({@code P10.10-R01}).
         */
        public DecisionPointDescriptor resolveActionDecisionPoint(String actionId) {
            if (actionId != null) {
                DecisionPointDescriptor actionDp = actionDecisionPoints.get(actionId);
                if (actionDp != null) {
                    return actionDp;
                }
            }
            return decisionPoint;
        }

        /**
         * Resolves the effective {@link DecisionPointDescriptor} specifically for a {@code @UiSurface}
         * ({@code P10.10-R01}).
         */
        public DecisionPointDescriptor resolveSurfaceDecisionPoint(String surfaceId) {
            if (surfaceId != null) {
                DecisionPointDescriptor surfaceDp = surfaceDecisionPoints.get(surfaceId);
                if (surfaceDp != null) {
                    return surfaceDp;
                }
            }
            return decisionPoint;
        }
    }

    /**
     * Policy governing how {@link AuthzResourceOperationAvailabilityProvider} handles a
     * {@code resourceKey} that has no registered {@link ResourceAvailabilityPolicyBinding} and
     * no functional resolver fallback ({@code P10.4-R01}, {@code P20}).
     */
    public enum UnmappedResourcePolicy {
        /**
         * Fails closed with {@code AUTHZ_DECISION_POINT_UNMAPPED} across {@code /capabilities},
         * {@code /actions}, and {@code /surfaces} (canonical enterprise default per {@code P20}).
         */
        FAIL_CLOSED,

        /**
         * Allows unmapped resources at the discovery rule layer so hosts migrating incrementally
         * can govern selected resources first without blocking legacy controllers.
         */
        ALLOW_UNMAPPED_FOR_INCREMENTAL_ADOPTION
    }

    private final MetadataResourceAuthorizationSeam authorizationSeam;
    private final ResourceStateSnapshotProvider snapshotProviderFallback;
    private final Function<ResourceOperationAvailabilityContext, String> decisionPointKeyResolver;
    private final Predicate<ResourceOperationAvailabilityContext> livePermitEvaluator;
    private final Supplier<String> policyRevisionSupplier;
    private final Map<String, ResourceAvailabilityPolicyBinding> bindingsByResourceKey = new ConcurrentHashMap<>();
    private volatile UnmappedResourcePolicy unmappedResourcePolicy = UnmappedResourcePolicy.FAIL_CLOSED;

    /**
     * Creates a new {@link AuthzResourceOperationAvailabilityProvider} without a fallback snapshot provider.
     *
     * @param authorizationSeam canonical metadata authorization seam
     */
    public AuthzResourceOperationAvailabilityProvider(MetadataResourceAuthorizationSeam authorizationSeam) {
        this(authorizationSeam, null);
    }

    /**
     * Creates a new {@link AuthzResourceOperationAvailabilityProvider}.
     *
     * @param authorizationSeam canonical metadata authorization seam
     * @param snapshotProviderFallback optional fallback {@link ResourceStateSnapshotProvider} used when
     *                                 {@code ITEM}-scoped evaluations (such as {@code GovernedResourceCommandExecutor})
     *                                 pass {@code resourceId} without a pre-populated {@link ResourceStateSnapshot}
     */
    public AuthzResourceOperationAvailabilityProvider(
            MetadataResourceAuthorizationSeam authorizationSeam,
            ResourceStateSnapshotProvider snapshotProviderFallback
    ) {
        this.authorizationSeam = Objects.requireNonNull(authorizationSeam, "authorizationSeam is required");
        this.snapshotProviderFallback = snapshotProviderFallback;
        this.decisionPointKeyResolver = null;
        this.livePermitEvaluator = null;
        this.policyRevisionSupplier = null;
    }

    /**
     * Creates a new {@link AuthzResourceOperationAvailabilityProvider} using functional resolvers
     * ({@code Fase P10.1} compatibility constructor).
     *
     * @param authorizationSeam canonical metadata authorization seam
     * @param decisionPointKeyResolver function mapping context to canonical {@code decisionPointKey}
     * @param livePermitEvaluator predicate evaluating whether the operation is currently permitted
     * @param policyRevisionSupplier supplier of current observed policy runtime revision
     */
    public AuthzResourceOperationAvailabilityProvider(
            MetadataResourceAuthorizationSeam authorizationSeam,
            Function<ResourceOperationAvailabilityContext, String> decisionPointKeyResolver,
            Predicate<ResourceOperationAvailabilityContext> livePermitEvaluator,
            Supplier<String> policyRevisionSupplier
    ) {
        this.authorizationSeam = Objects.requireNonNull(authorizationSeam, "authorizationSeam is required");
        this.snapshotProviderFallback = null;
        this.decisionPointKeyResolver = Objects.requireNonNull(decisionPointKeyResolver, "decisionPointKeyResolver is required");
        this.livePermitEvaluator = Objects.requireNonNull(livePermitEvaluator, "livePermitEvaluator is required");
        this.policyRevisionSupplier = Objects.requireNonNull(policyRevisionSupplier, "policyRevisionSupplier is required");
    }

    /**
     * Registers or replaces a {@link ResourceAvailabilityPolicyBinding} for a {@code resourceKey}.
     *
     * @param binding resource availability policy binding
     * @return this provider for fluent chaining
     */
    public AuthzResourceOperationAvailabilityProvider registerResourceBinding(
            ResourceAvailabilityPolicyBinding binding
    ) {
        Objects.requireNonNull(binding, "binding is required");
        bindingsByResourceKey.put(binding.resourceKey(), binding);
        return this;
    }

    /**
     * Registers a {@link ResourceAvailabilityPolicyBinding} only if no binding is currently
     * registered for {@code binding.resourceKey()} ({@code Fase P10.9}).
     *
     * @param binding resource availability policy binding
     * @return this provider for fluent chaining
     */
    public AuthzResourceOperationAvailabilityProvider registerResourceBindingIfAbsent(
            ResourceAvailabilityPolicyBinding binding
    ) {
        Objects.requireNonNull(binding, "binding is required");
        bindingsByResourceKey.putIfAbsent(binding.resourceKey(), binding);
        return this;
    }

    /**
     * Returns {@code true} when a {@link ResourceAvailabilityPolicyBinding} is registered for
     * {@code resourceKey}.
     */
    public boolean hasResourceBinding(String resourceKey) {
        return resourceKey != null && bindingsByResourceKey.containsKey(resourceKey);
    }

    /**
     * Configures the policy applied when evaluating a {@code resourceKey} without a registered
     * {@link ResourceAvailabilityPolicyBinding} ({@code P10.4-R01}). Defaults to
     * {@link UnmappedResourcePolicy#FAIL_CLOSED}.
     *
     * @param policy unmapped resource policy
     * @return this provider for fluent chaining
     */
    public AuthzResourceOperationAvailabilityProvider withUnmappedResourcePolicy(
            UnmappedResourcePolicy policy
    ) {
        this.unmappedResourcePolicy = Objects.requireNonNull(policy, "policy is required");
        return this;
    }

    @Override
    public AvailabilityDecision evaluate(ResourceOperationAvailabilityContext context) {
        if (context == null || context.resourceKey() == null) {
            return AvailabilityDecision.deny("AUTHZ_CONTEXT_MISSING", Map.of());
        }
        ResourceAvailabilityPolicyBinding binding = bindingsByResourceKey.get(context.resourceKey());
        if (binding != null) {
            boolean itemScope = "ITEM".equalsIgnoreCase(context.scope());
            ResourceStateSnapshot snapshot = itemScope
                    ? resolveSnapshotIfNeeded(binding, context.resourceKey(), context.resourceId(), context.resourceState())
                    : null;
            boolean mutating = isMutatingOperation(context, binding);
            return evaluateInternal(
                    binding,
                    binding.resolveDecisionPoint(context.operationId()),
                    context.operationId(),
                    itemScope,
                    mutating,
                    snapshot
            );
        }
        return evaluateFallbackOrUnmapped(context);
    }

    @Override
    public AvailabilityDecision evaluate(ActionDefinition definition, ActionAvailabilityContext context) {
        if (definition == null || context == null || definition.resourceKey() == null) {
            return AvailabilityDecision.deny("AUTHZ_CONTEXT_MISSING", Map.of());
        }
        boolean itemScope = definition.scope() == ActionScope.ITEM;
        ResourceAvailabilityPolicyBinding binding = bindingsByResourceKey.get(definition.resourceKey());
        ResourceStateSnapshot snapshot = itemScope
                ? resolveSnapshotIfNeeded(binding, definition.resourceKey(), context.resourceId(), context.resourceState())
                : null;
        if (binding != null) {
            return evaluateInternal(
                    binding,
                    binding.resolveActionDecisionPoint(definition.id()),
                    definition.id(),
                    itemScope,
                    true,
                    snapshot
            );
        }
        ResourceOperationAvailabilityContext syntheticCtx = itemScope
                ? ResourceOperationAvailabilityContext.item(
                        definition.resourceKey(),
                        definition.resourcePath(),
                        definition.id(),
                        context.resourceId(),
                        snapshot
                )
                : ResourceOperationAvailabilityContext.collection(
                        definition.resourceKey(),
                        definition.resourcePath(),
                        definition.id()
                );
        return evaluateFallbackOrUnmapped(syntheticCtx);
    }

    @Override
    public AvailabilityDecision evaluate(SurfaceDefinition definition, SurfaceAvailabilityContext context) {
        if (definition == null || context == null || definition.resourceKey() == null) {
            return AvailabilityDecision.deny("AUTHZ_CONTEXT_MISSING", Map.of());
        }
        boolean itemScope = definition.scope() == SurfaceScope.ITEM;
        ResourceAvailabilityPolicyBinding binding = bindingsByResourceKey.get(definition.resourceKey());
        ResourceStateSnapshot snapshot = itemScope
                ? resolveSnapshotIfNeeded(binding, definition.resourceKey(), context.resourceId(), context.resourceState())
                : null;
        if (binding != null) {
            boolean mutatingSurface = definition.kind() == SurfaceKind.FORM
                    || definition.kind() == SurfaceKind.PARTIAL_FORM;
            return evaluateInternal(
                    binding,
                    binding.resolveSurfaceDecisionPoint(definition.id()),
                    definition.id(),
                    itemScope,
                    mutatingSurface,
                    snapshot
            );
        }
        ResourceOperationAvailabilityContext syntheticCtx = itemScope
                ? ResourceOperationAvailabilityContext.item(
                        definition.resourceKey(),
                        definition.resourcePath(),
                        definition.id(),
                        context.resourceId(),
                        snapshot
                )
                : ResourceOperationAvailabilityContext.collection(
                        definition.resourceKey(),
                        definition.resourcePath(),
                        definition.id()
                );
        return evaluateFallbackOrUnmapped(syntheticCtx);
    }

    private AvailabilityDecision evaluateFallbackOrUnmapped(ResourceOperationAvailabilityContext context) {
        if (decisionPointKeyResolver != null && livePermitEvaluator != null && policyRevisionSupplier != null) {
            String pointKey = decisionPointKeyResolver.apply(context);
            if (pointKey == null || pointKey.isBlank()) {
                return unmappedDecision();
            }
            String revision = policyRevisionSupplier.get();
            if (revision == null || revision.isBlank()) {
                return AvailabilityDecision.deny("AUTHZ_REVISION_UNAVAILABLE", Map.of());
            }
            boolean permitted = livePermitEvaluator.test(context);
            AdvisoryOperationAvailability advisory = authorizationSeam.evaluateAdvisoryAvailability(
                    pointKey,
                    permitted,
                    revision
            );
            Map<String, Object> metadata = Map.of(
                    "decisionPointKey", advisory.decisionPointKey(),
                    "advisoryOnly", advisory.advisoryOnly(),
                    "requiresRuntimeRevalidation", advisory.requiresRuntimeRevalidation(),
                    "revalidatedOnExecution", advisory.requiresRuntimeRevalidation(),
                    "observedPolicyRevision", advisory.observedPolicyRevision()
            );
            return permitted
                    ? AvailabilityDecision.allow(metadata)
                    : AvailabilityDecision.deny("AUTHZ_POLICY_DENIED", metadata);
        }
        return unmappedDecision();
    }

    private AvailabilityDecision unmappedDecision() {
        if (unmappedResourcePolicy == UnmappedResourcePolicy.ALLOW_UNMAPPED_FOR_INCREMENTAL_ADOPTION) {
            return AvailabilityDecision.allowAll();
        }
        return AvailabilityDecision.deny("AUTHZ_DECISION_POINT_UNMAPPED", Map.of());
    }

    private static boolean isMutatingOperation(
            ResourceOperationAvailabilityContext context,
            ResourceAvailabilityPolicyBinding binding
    ) {
        String rawOp = context.operationId();
        String op = rawOp == null ? "" : rawOp.trim().toLowerCase(java.util.Locale.ROOT);
        if ("create".equals(op)
                || "edit".equals(op)
                || "update".equals(op)
                || "patch".equals(op)
                || "delete".equals(op)
                || "duplicate-draft".equals(op)
                || op.startsWith("bulk")) {
            return true;
        }
        if ("view".equals(op)
                || "detail".equals(op)
                || "byid".equals(op)
                || "all".equals(op)
                || "filter".equals(op)
                || "cursor".equals(op)
                || "filter-cursor".equals(op)
                || "locate".equals(op)
                || "list".equals(op)
                || "export".equals(op)
                || "stats".equals(op)
                || op.startsWith("stats")
                || "options".equals(op)
                || "optionsources".equals(op)
                || "option-sources".equals(op)
                || "by-ids".equals(op)
                || "schemas".equals(op)) {
            return false;
        }
        Object preferredMethod = context.metadata().get("preferredMethod");
        if (preferredMethod != null) {
            String method = String.valueOf(preferredMethod).trim().toUpperCase(java.util.Locale.ROOT);
            if ("GET".equals(method) || "HEAD".equals(method)) {
                return false;
            }
            if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method) || "DELETE".equals(method)) {
                return true;
            }
        }
        if (rawOp != null && binding != null) {
            if (binding.actionDecisionPoints().containsKey(rawOp)) {
                return true;
            }
            DecisionPointDescriptor surfaceDp = binding.surfaceDecisionPoints().get(rawOp);
            if (surfaceDp != null && surfaceDp.httpMethod() != null) {
                String m = surfaceDp.httpMethod().trim().toUpperCase(java.util.Locale.ROOT);
                return !("GET".equals(m) || "HEAD".equals(m));
            }
            Set<String> modified = binding.operationModifiedAttributes().get(rawOp);
            if (modified != null && !modified.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    private ResourceStateSnapshot resolveSnapshotIfNeeded(
            ResourceAvailabilityPolicyBinding binding,
            String resourceKey,
            Object resourceId,
            ResourceStateSnapshot existingSnapshot
    ) {
        if (existingSnapshot != null) {
            if (Boolean.TRUE.equals(existingSnapshot.metadata().get(AuthzResourceGovernanceSpec.SNAPSHOT_ENRICHED_META_KEY))
                    || resourceId == null
                    || binding == null
                    || binding.itemSnapshotResolver() == null) {
                return existingSnapshot;
            }
            Optional<ResourceStateSnapshot> resolved = binding.itemSnapshotResolver().apply(resourceId);
            if (resolved == null || resolved.isEmpty()) {
                return null;
            }
            return mergeEnrichedSnapshot(resolved.get(), existingSnapshot);
        }
        if (resourceId == null) {
            return null;
        }
        if (binding != null && binding.itemSnapshotResolver() != null) {
            Optional<ResourceStateSnapshot> resolvedByBinding = binding.itemSnapshotResolver().apply(resourceId);
            if (resolvedByBinding != null && resolvedByBinding.isPresent()) {
                return resolvedByBinding.get();
            }
        }
        if (snapshotProviderFallback == null) {
            return null;
        }
        Optional<ResourceStateSnapshot> resolved = snapshotProviderFallback.resolve(resourceKey, resourceId);
        return resolved.orElse(null);
    }

    private static ResourceStateSnapshot mergeEnrichedSnapshot(
            ResourceStateSnapshot authzSnapshot,
            ResourceStateSnapshot hostSnapshot
    ) {
        Map<String, Object> mergedMeta = new LinkedHashMap<>(authzSnapshot.metadata());
        mergedMeta.putAll(hostSnapshot.metadata());
        for (String key : List.of(
                AuthzResourceGovernanceSpec.SNAPSHOT_TENANT_META_KEY,
                AuthzResourceGovernanceSpec.SNAPSHOT_ORIGIN_VALUE_META_KEY,
                AuthzResourceGovernanceSpec.SNAPSHOT_DESTINATION_VALUE_META_KEY,
                AuthzResourceGovernanceSpec.SNAPSHOT_ENTITY_REF_META_KEY,
                AuthzResourceGovernanceSpec.SNAPSHOT_ENRICHED_META_KEY,
                AuthzResourceGovernanceSpec.SNAPSHOT_NULL_FACTS_META_KEY
        )) {
            if (authzSnapshot.metadata().containsKey(key)) {
                mergedMeta.put(key, authzSnapshot.metadata().get(key));
            }
        }
        String state = (hostSnapshot.state() != null && !hostSnapshot.state().isBlank())
                ? hostSnapshot.state()
                : authzSnapshot.state();
        return ResourceStateSnapshot.of(state, mergedMeta);
    }

    private AvailabilityDecision evaluateInternal(
            ResourceAvailabilityPolicyBinding binding,
            DecisionPointDescriptor effectiveDecisionPoint,
            String operationId,
            boolean itemScope,
            boolean mutatingOperation,
            ResourceStateSnapshot snapshot
    ) {
        if (itemScope && snapshot == null
                && (binding.itemSnapshotResolver() != null || snapshotProviderFallback != null)) {
            Map<String, Object> notFoundMeta = new LinkedHashMap<>();
            notFoundMeta.put("decisionPointKey", effectiveDecisionPoint.identity().pointKey());
            if (operationId != null && !operationId.isBlank()) {
                notFoundMeta.put("operationId", operationId);
            }
            notFoundMeta.put("evaluationScope", "ITEM");
            notFoundMeta.put("advisoryOnly", true);
            notFoundMeta.put("requiresRuntimeRevalidation", true);
            notFoundMeta.put("revalidatedOnExecution", true);
            notFoundMeta.put(
                    "denialCategory",
                    OperationAvailabilityEvaluation.classifyDenialCategory("resource-state-not-found")
            );
            return AvailabilityDecision.deny(
                    "resource-state-not-found",
                    Map.copyOf(notFoundMeta)
            );
        }
        CallerAvailabilityFactContext callerCtx;
        try {
            callerCtx = binding.callerContextSupplier().get();
        } catch (SecurityException ex) {
            Map<String, Object> missingCallerMeta = new LinkedHashMap<>();
            missingCallerMeta.put("decisionPointKey", effectiveDecisionPoint.identity().pointKey());
            if (operationId != null && !operationId.isBlank()) {
                missingCallerMeta.put("operationId", operationId);
            }
            missingCallerMeta.put("evaluationScope", itemScope ? "ITEM" : "COLLECTION");
            missingCallerMeta.put("advisoryOnly", true);
            missingCallerMeta.put("requiresRuntimeRevalidation", true);
            missingCallerMeta.put("revalidatedOnExecution", true);
            missingCallerMeta.put(
                    "denialCategory",
                    OperationAvailabilityEvaluation.classifyDenialCategory("caller-context-missing")
            );
            return AvailabilityDecision.deny(
                    "caller-context-missing",
                    Map.copyOf(missingCallerMeta)
            );
        }
        if (callerCtx == null) {
            Map<String, Object> missingCallerMeta = new LinkedHashMap<>();
            missingCallerMeta.put("decisionPointKey", effectiveDecisionPoint.identity().pointKey());
            if (operationId != null && !operationId.isBlank()) {
                missingCallerMeta.put("operationId", operationId);
            }
            missingCallerMeta.put("evaluationScope", itemScope ? "ITEM" : "COLLECTION");
            missingCallerMeta.put("advisoryOnly", true);
            missingCallerMeta.put("requiresRuntimeRevalidation", true);
            missingCallerMeta.put("revalidatedOnExecution", true);
            missingCallerMeta.put(
                    "denialCategory",
                    OperationAvailabilityEvaluation.classifyDenialCategory("caller-context-missing")
            );
            return AvailabilityDecision.deny(
                    "caller-context-missing",
                    Map.copyOf(missingCallerMeta)
            );
        }
        if (itemScope && snapshot != null && !callerCtx.sharedUnrestrictedScope()) {
            Object snapshotTenant = snapshot.metadata().get(AuthzResourceGovernanceSpec.SNAPSHOT_TENANT_META_KEY);
            boolean mismatch = false;
            if (callerCtx.allowedHardScopeValues() != null) {
                mismatch = snapshotTenant != null
                        && !callerCtx.allowedHardScopeValues().contains(String.valueOf(snapshotTenant));
            } else if (callerCtx.tenantId() != null) {
                mismatch = snapshotTenant != null
                        && !Objects.equals(callerCtx.tenantId(), String.valueOf(snapshotTenant));
            }
            if (mismatch) {
                Map<String, Object> tenantMismatchMeta = new LinkedHashMap<>();
                tenantMismatchMeta.put("decisionPointKey", effectiveDecisionPoint.identity().pointKey());
                if (operationId != null && !operationId.isBlank()) {
                    tenantMismatchMeta.put("operationId", operationId);
                }
                tenantMismatchMeta.put("evaluationScope", "ITEM");
                tenantMismatchMeta.put("advisoryOnly", true);
                tenantMismatchMeta.put("requiresRuntimeRevalidation", true);
                tenantMismatchMeta.put("revalidatedOnExecution", true);
                tenantMismatchMeta.put(
                        "denialCategory",
                        OperationAvailabilityEvaluation.classifyDenialCategory("hard-scope-tenant-mismatch")
                );
                return AvailabilityDecision.deny(
                        "hard-scope-tenant-mismatch",
                        Map.copyOf(tenantMismatchMeta)
                );
            }
        }

        if (mutatingOperation && callerCtx.readOnlyConsolidation()) {
            Map<String, Object> consolidationMeta = new LinkedHashMap<>();
            consolidationMeta.put("decisionPointKey", effectiveDecisionPoint.identity().pointKey());
            if (operationId != null && !operationId.isBlank()) {
                consolidationMeta.put("operationId", operationId);
            }
            consolidationMeta.put("evaluationScope", itemScope ? "ITEM" : "COLLECTION");
            consolidationMeta.put("advisoryOnly", true);
            consolidationMeta.put("requiresRuntimeRevalidation", true);
            consolidationMeta.put("revalidatedOnExecution", true);
            consolidationMeta.put("readOnlyConsolidation", true);
            consolidationMeta.put(
                    "denialCategory",
                    OperationAvailabilityEvaluation.classifyDenialCategory("consolidation-read-only-scope")
            );
            return AvailabilityDecision.deny(
                    "consolidation-read-only-scope",
                    Map.copyOf(consolidationMeta)
            );
        }

        Set<String> modifiedAttributes = binding.operationModifiedAttributes()
                .getOrDefault(operationId == null ? "" : operationId, Set.of());

        Map<String, Object> itemFacts = Map.of();
        Map<String, FactResolutionStatus> itemStatuses = Map.of();
        if (itemScope && snapshot != null) {
            Map<String, Object> extracted = binding.snapshotTargetFactExtractor().apply(snapshot);
            if (extracted != null && !extracted.isEmpty()) {
                itemFacts = Map.copyOf(extracted);
            }
            if (binding.snapshotTargetFactStatusExtractor() != null) {
                Map<String, FactResolutionStatus> extractedStatuses =
                        binding.snapshotTargetFactStatusExtractor().apply(snapshot);
                if (extractedStatuses != null && !extractedStatuses.isEmpty()) {
                    itemStatuses = Map.copyOf(extractedStatuses);
                }
            }
            if (itemStatuses.isEmpty() && !itemFacts.isEmpty()) {
                Map<String, FactResolutionStatus> statuses = new LinkedHashMap<>();
                for (String key : itemFacts.keySet()) {
                    statuses.put(key, FactResolutionStatus.PRESENT);
                }
                itemStatuses = Map.copyOf(statuses);
            }
        }

        boolean matchesCedente = (itemScope && binding.itemCedenteEvaluator() != null)
                ? Boolean.TRUE.equals(binding.itemCedenteEvaluator().apply(callerCtx, snapshot))
                : callerCtx.callerMatchesCedente();
        boolean matchesCessionario = (itemScope && binding.itemCessionarioEvaluator() != null)
                ? Boolean.TRUE.equals(binding.itemCessionarioEvaluator().apply(callerCtx, snapshot))
                : callerCtx.callerMatchesCessionario();

        String effectiveFactDigest = (effectiveDecisionPoint != null
                        && effectiveDecisionPoint.factContractRef() != null
                        && effectiveDecisionPoint.factContractRef().factContractDigest() != null
                        && !effectiveDecisionPoint.factContractRef().factContractDigest().isBlank())
                ? effectiveDecisionPoint.factContractRef().factContractDigest()
                : binding.factContractDigest();

        boolean itemStateVerified = !itemScope || snapshot != null;
        boolean readOnlyOperation = !mutatingOperation;

        // P10.16-R01: When evaluating an ITEM-scoped custom @WorkflowAction or @UiSurface with its own
        // DecisionPointDescriptor, verify that the item first satisfies the primary resource decision point's
        // access gate (mirroring findEntityById(id) at runtime execution).
        if (itemScope
                && effectiveDecisionPoint != null
                && binding.decisionPoint() != null
                && !Objects.equals(
                        effectiveDecisionPoint.identity().pointKey(),
                        binding.decisionPoint().identity().pointKey()
                )) {
            OperationAvailabilityEvaluation primaryGateEval = authorizationSeam.evaluateOperationAvailability(
                    binding.decisionPoint(),
                    binding.factContractDigest(),
                    "view",
                    true,
                    Set.of(),
                    binding.dualScopeSpec(),
                    matchesCedente,
                    matchesCessionario,
                    callerCtx.trustedSubjectFacts(),
                    callerCtx.trustedSubjectFactStatuses(),
                    itemFacts,
                    itemStatuses,
                    itemStateVerified,
                    true
            );
            if (!primaryGateEval.advisory().allowedInDiscovery()) {
                OperationAvailabilityEvaluation deniedByPrimary = new OperationAvailabilityEvaluation(
                        authorizationSeam.evaluateAdvisoryAvailability(
                                effectiveDecisionPoint.identity().pointKey(),
                                false,
                                primaryGateEval.advisory().observedPolicyRevision()
                        ),
                        primaryGateEval.denialReason() != null ? primaryGateEval.denialReason() : "policy-gate-denied",
                        operationId,
                        "ITEM",
                        primaryGateEval.denialCategory() != null
                                ? primaryGateEval.denialCategory()
                                : OperationAvailabilityEvaluation.classifyDenialCategory("policy-gate-denied"),
                        primaryGateEval.dualScopeCustodyRole(),
                        primaryGateEval.forbiddenWriteAttributeIds(),
                        primaryGateEval.policyReasonCodes()
                );
                return AvailabilityDecision.deny(
                        deniedByPrimary.denialReason(),
                        deniedByPrimary.toSanitizedDecisionMetadata()
                );
            }
        }

        OperationAvailabilityEvaluation eval = authorizationSeam.evaluateOperationAvailability(
                effectiveDecisionPoint,
                effectiveFactDigest,
                operationId,
                itemScope,
                modifiedAttributes,
                binding.dualScopeSpec(),
                matchesCedente,
                matchesCessionario,
                callerCtx.trustedSubjectFacts(),
                callerCtx.trustedSubjectFactStatuses(),
                itemFacts,
                itemStatuses,
                itemStateVerified,
                readOnlyOperation
        );

        Map<String, Object> decisionMetadata = eval.toSanitizedDecisionMetadata();
        if (!eval.advisory().allowedInDiscovery()) {
            return AvailabilityDecision.deny(
                    eval.denialReason() != null ? eval.denialReason() : "policy-denied",
                    decisionMetadata
            );
        }
        return AvailabilityDecision.allow(decisionMetadata);
    }
}
