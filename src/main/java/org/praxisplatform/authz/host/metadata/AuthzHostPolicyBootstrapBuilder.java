package org.praxisplatform.authz.host.metadata;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.catalog.AdmittedInvocationChannel;
import org.praxisplatform.authz.catalog.FieldLineageCatalogEntry;
import org.praxisplatform.authz.catalog.MethodBindingAdmissionRecord;
import org.praxisplatform.authz.compatibility.HostRuntimePolicyCoordinates;
import org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode;
import org.praxisplatform.authz.contracts.binding.HostEnforcementPhase;
import org.praxisplatform.authz.contracts.binding.ReadinessEvidenceOverlay;
import org.praxisplatform.authz.contracts.binding.RuntimeEnforcementBinding;
import org.praxisplatform.authz.contracts.binding.TransactionCardinality;
import org.praxisplatform.authz.contracts.compatibility.DecisionPointCompatibilityEntry;
import org.praxisplatform.authz.contracts.compatibility.HostPolicyCompatibilityManifest;
import org.praxisplatform.authz.contracts.compatibility.ImpactCompletenessStatus;
import org.praxisplatform.authz.contracts.compatibility.ImpactGraphBaseline;
import org.praxisplatform.authz.contracts.compatibility.RolloutActivationStrategy;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.datascope.QueryableFieldDescriptor;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateOperator;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointRef;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.decisionpoint.PointAuthorityMode;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.digest.OpaProviderIoSchemas;
import org.praxisplatform.authz.contracts.envelope.ContributionAuthority;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.policy.AccessContributionSpec;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyRule;
import org.praxisplatform.authz.contracts.policy.AuthorizationRuleContributions;
import org.praxisplatform.authz.contracts.policy.AuthorizationSourceCondition;
import org.praxisplatform.authz.contracts.policy.ConditionProfileKind;
import org.praxisplatform.authz.contracts.policy.DataScopeContributionSpec;
import org.praxisplatform.authz.contracts.policy.FieldUseContributionSpec;
import org.praxisplatform.authz.contracts.policy.FieldWriteContributionSpec;
import org.praxisplatform.authz.contracts.policy.MaskContributionSpec;
import org.praxisplatform.authz.contracts.policy.PolicyFieldSelector;
import org.praxisplatform.authz.contracts.policy.PolicyMaterializationTargetSpec;
import org.praxisplatform.authz.contracts.policy.PolicyTargetSpec;
import org.praxisplatform.authz.opa.bundle.OpaBundleArtifact;
import org.praxisplatform.authz.opa.bundle.OpaBundleAssembler;
import org.praxisplatform.authz.opa.client.DeterministicLocalOpaTransport;
import org.praxisplatform.authz.opa.compiler.CompiledRegoUnit;
import org.praxisplatform.authz.opa.compiler.RegoV1PolicyCompiler;
import org.springframework.aop.support.AopUtils;
import org.springframework.core.ResolvableType;

/**
 * Multi-resource declarative bootstrap builder that assembles {@link HostRuntimePolicyCoordinates},
 * {@link MethodBindingAdmissionRecord}s (with introspected {@link FieldLineageCatalogEntry} lists),
 * compiled {@link OpaBundleArtifact}, and {@link DeterministicLocalOpaTransport} directly from
 * {@link AuthzResourceGovernanceSpec} definitions ({@code Fase P10.14}, {@code CC08}, {@code P20},
 * {@code P22}, {@code P34..P64}).
 */
public final class AuthzHostPolicyBootstrapBuilder {

    /**
     * Immutable runtime bootstrap bundle produced by {@link AuthzHostPolicyBootstrapBuilder#build}.
     *
     * @param serviceKey owning microservice/host key
     * @param coordinates canonical {@link HostRuntimePolicyCoordinates} for startup compatibility verification
     * @param admissionRecords admitted {@link MethodBindingAdmissionRecord}s with introspected field lineage
     * @param bundleArtifact compiled OPA bundle artifact
     * @param localOpaTransport ready-to-use {@link DeterministicLocalOpaTransport} for local/showcase/test execution
     * @param policies compiled {@link AuthorizationPolicyDefinition}s
     */
    public record AuthzHostPolicyBootstrapBundle(
            String serviceKey,
            HostRuntimePolicyCoordinates coordinates,
            List<MethodBindingAdmissionRecord> admissionRecords,
            OpaBundleArtifact bundleArtifact,
            DeterministicLocalOpaTransport localOpaTransport,
            List<AuthorizationPolicyDefinition> policies,
            List<AuthzResourceGovernanceSpec<?>> resourceSpecs
    ) {
        public AuthzHostPolicyBootstrapBundle {
            Objects.requireNonNull(serviceKey, "serviceKey is required");
            Objects.requireNonNull(coordinates, "coordinates is required");
            admissionRecords = List.copyOf(Objects.requireNonNull(admissionRecords, "admissionRecords is required"));
            Objects.requireNonNull(bundleArtifact, "bundleArtifact is required");
            Objects.requireNonNull(localOpaTransport, "localOpaTransport is required");
            policies = List.copyOf(Objects.requireNonNull(policies, "policies is required"));
            resourceSpecs = resourceSpecs == null ? List.of() : List.copyOf(resourceSpecs);
        }

        public AuthzHostPolicyBootstrapBundle(
                String serviceKey,
                HostRuntimePolicyCoordinates coordinates,
                List<MethodBindingAdmissionRecord> admissionRecords,
                OpaBundleArtifact bundleArtifact,
                DeterministicLocalOpaTransport localOpaTransport,
                List<AuthorizationPolicyDefinition> policies
        ) {
            this(
                    serviceKey,
                    coordinates,
                    admissionRecords,
                    bundleArtifact,
                    localOpaTransport,
                    policies,
                    List.of()
            );
        }
    }

    private record RegisteredResourceEntry(
            AuthzResourceGovernanceSpec<?> spec,
            FactContract factContract,
            Class<?> responseDtoClass,
            Class<?> createDtoClass,
            Class<?> updateDtoClass
    ) {}

    private final String serviceKey;
    private String hostVersion = "1.0.0";
    private String runtimeRevision = "rev-2026-11-09-01";
    private final List<RegisteredResourceEntry> resources = new ArrayList<>();
    private final List<AuthorizationPolicyDefinition> policies = new ArrayList<>();

    private AuthzHostPolicyBootstrapBuilder(String serviceKey) {
        this.serviceKey = Objects.requireNonNull(serviceKey, "serviceKey is required").trim();
        if (this.serviceKey.isEmpty()) {
            throw new IllegalArgumentException("serviceKey must not be blank");
        }
    }

    /**
     * Creates a new {@link AuthzHostPolicyBootstrapBuilder} for the given host {@code serviceKey}.
     */
    public static AuthzHostPolicyBootstrapBuilder forService(String serviceKey) {
        return new AuthzHostPolicyBootstrapBuilder(serviceKey);
    }

    /** Configures the host application version recorded in {@link HostPolicyCompatibilityManifest}. */
    public AuthzHostPolicyBootstrapBuilder hostVersion(String hostVersion) {
        this.hostVersion = Objects.requireNonNull(hostVersion, "hostVersion is required").trim();
        return this;
    }

    /** Configures the OPA runtime release revision string. */
    public AuthzHostPolicyBootstrapBuilder runtimeRevision(String runtimeRevision) {
        this.runtimeRevision = Objects.requireNonNull(runtimeRevision, "runtimeRevision is required").trim();
        return this;
    }

    /**
     * Registers a self-contained {@link AuthzResourceGovernanceSpec} (whose {@link AuthzResourceGovernanceSpec#factContract()}
     * is non-null) along with its DTO classes for automatic {@link FieldLineageCatalogEntry} derivation.
     */
    public AuthzHostPolicyBootstrapBuilder addResourceSpec(
            AuthzResourceGovernanceSpec<?> spec,
            Class<?> responseDtoClass,
            Class<?> createDtoClass,
            Class<?> updateDtoClass
    ) {
        Objects.requireNonNull(spec, "spec is required");
        FactContract fc = Objects.requireNonNull(
                spec.factContract(),
                "spec.factContract() is required; configure .serviceKey(...) or .factContract(...) on AuthzResourceGovernanceSpec.builder"
        );
        return addResourceSpec(spec, fc, responseDtoClass, createDtoClass, updateDtoClass);
    }

    /**
     * Registers an {@link AuthzResourceGovernanceSpec} with an explicit {@link FactContract} and DTO classes.
     */
    public AuthzHostPolicyBootstrapBuilder addResourceSpec(
            AuthzResourceGovernanceSpec<?> spec,
            FactContract factContract,
            Class<?> responseDtoClass,
            Class<?> createDtoClass,
            Class<?> updateDtoClass
    ) {
        Objects.requireNonNull(spec, "spec is required");
        Objects.requireNonNull(factContract, "factContract is required");
        this.resources.add(new RegisteredResourceEntry(
                spec,
                factContract,
                responseDtoClass,
                createDtoClass,
                updateDtoClass
        ));
        return this;
    }

    /**
     * Registers a governed mutable {@link AbstractAuthzGovernedResourceService}, automatically
     * extracting its {@link AuthzResourceGovernanceSpec} and generic DTO classes ({@code ResponseDTO},
     * {@code CreateDTO}, {@code UpdateDTO}) via {@link ResolvableType} ({@code Fase P10.15-C}).
     *
     * @param service governed mutable resource service
     * @return this builder
     */
    public AuthzHostPolicyBootstrapBuilder addGovernedService(
            AbstractAuthzGovernedResourceService<?, ?, ?, ?, ?, ?> service
    ) {
        Objects.requireNonNull(service, "service is required");
        AuthzResourceGovernanceSpec<?> spec = Objects.requireNonNull(
                service.getGovernanceSpec(),
                "service.getGovernanceSpec() is required; configure AuthzResourceGovernanceSpec on the service"
        );
        Class<?> targetServiceClass = AopUtils.getTargetClass(service);
        ResolvableType mutableType = ResolvableType.forClass(targetServiceClass)
                .as(AbstractAuthzGovernedResourceService.class);
        Class<?> responseDtoClass = service.getResponseType();
        Class<?> createDtoClass = mutableType.getGeneric(4).resolve(Object.class);
        Class<?> updateDtoClass = mutableType.getGeneric(5).resolve(Object.class);
        return addResourceSpec(spec, responseDtoClass, createDtoClass, updateDtoClass);
    }

    /**
     * Registers a governed read-only {@link AbstractAuthzGovernedReadOnlyResourceService}, automatically
     * extracting its {@link AuthzResourceGovernanceSpec} and {@code ResponseDTO} class ({@code Fase P10.15-C}).
     *
     * @param service governed read-only resource service
     * @return this builder
     */
    public AuthzHostPolicyBootstrapBuilder addGovernedReadOnlyService(
            AbstractAuthzGovernedReadOnlyResourceService<?, ?, ?, ?> service
    ) {
        Objects.requireNonNull(service, "service is required");
        AuthzResourceGovernanceSpec<?> spec = Objects.requireNonNull(
                service.getGovernanceSpec(),
                "service.getGovernanceSpec() is required; configure AuthzResourceGovernanceSpec on the service"
        );
        Class<?> responseDtoClass = service.getResponseType();
        return addResourceSpec(spec, responseDtoClass, null, null);
    }

    /**
     * Registers a custom {@link AuthorizationPolicyDefinition} to be compiled into the OPA bundle.
     */
    public AuthzHostPolicyBootstrapBuilder addPolicy(AuthorizationPolicyDefinition policy) {
        this.policies.add(Objects.requireNonNull(policy, "policy is required"));
        return this;
    }

    /**
     * Synthesizes and registers an {@link AuthorizationPolicyDefinition} targeting a custom workflow
     * action decision point ({@link AuthzResourceGovernanceSpec#actionDecisionPoints()}) ({@code Fase P10.15-C}).
     *
     * @param spec target governed resource specification
     * @param actionKey action key registered via {@code .actionDecisionPoint(actionKey, ...)}
     * @param ruleId unique rule identifier
     * @param targetJsonLogicCondition JSON-Logic condition evaluated in {@code TARGET} mode
     * @return this builder
     */
    public AuthzHostPolicyBootstrapBuilder addActionPolicy(
            AuthzResourceGovernanceSpec<?> spec,
            String actionKey,
            String ruleId,
            Map<String, Object> targetJsonLogicCondition
    ) {
        return addActionPolicy(spec, actionKey, ruleId, targetJsonLogicCondition, Set.of());
    }

    /**
     * Synthesizes and registers an {@link AuthorizationPolicyDefinition} targeting a custom workflow
     * action decision point ({@link AuthzResourceGovernanceSpec#actionDecisionPoints()}) with optional
     * {@code FIELD_WRITE} attribute grants ({@code Fase P10.15-C}).
     *
     * @param spec target governed resource specification
     * @param actionKey action key registered via {@code .actionDecisionPoint(actionKey, ...)}
     * @param ruleId unique rule identifier
     * @param targetJsonLogicCondition JSON-Logic condition evaluated in {@code TARGET} mode
     * @param allowedAttributeWrites optional set of canonical {@code attributeId}s granted write access
     * @return this builder
     */
    public AuthzHostPolicyBootstrapBuilder addActionPolicy(
            AuthzResourceGovernanceSpec<?> spec,
            String actionKey,
            String ruleId,
            Map<String, Object> targetJsonLogicCondition,
            Set<String> allowedAttributeWrites
    ) {
        Objects.requireNonNull(spec, "spec is required");
        Objects.requireNonNull(actionKey, "actionKey is required");
        Objects.requireNonNull(ruleId, "ruleId is required");
        Objects.requireNonNull(targetJsonLogicCondition, "targetJsonLogicCondition is required");

        DecisionPointDescriptor actionDp = spec.actionDecisionPoints().get(actionKey);
        if (actionDp == null) {
            throw new IllegalArgumentException(
                    "Unknown actionKey '" + actionKey + "' on spec for resource '" + spec.resourceKey()
                            + "'; register it via .actionDecisionPoint(\"" + actionKey + "\", ...)"
            );
        }

        List<FieldWriteContributionSpec> fieldWrites = new ArrayList<>();
        if (allowedAttributeWrites != null && !allowedAttributeWrites.isEmpty()) {
            fieldWrites.add(new FieldWriteContributionSpec(
                    PolicyFieldSelector.exact(Set.copyOf(allowedAttributeWrites)),
                    RuleEffect.ALLOW
            ));
        }

        AuthorizationPolicyRule rule = new AuthorizationPolicyRule(
                ruleId,
                "Grants workflow action '" + actionKey + "' for " + spec.resourceKey(),
                Set.of(EvaluationMode.TARGET),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        targetJsonLogicCondition
                ),
                new AuthorizationRuleContributions(
                        new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                        null,
                        List.of(),
                        List.copyOf(fieldWrites),
                        List.of(),
                        "ALLOW_ACTION_" + actionKey.toUpperCase().replace('-', '_').replace('.', '_')
                ),
                List.of(new ObligationDirective(
                        "DURABLE_AUDIT_EVIDENCE",
                        "ON_PERMIT",
                        "BEFORE_COMMIT_OUTBOX",
                        Map.of(
                                "auditCategory", "GOVERNED_WORKFLOW_ACTION",
                                "actionKey", actionKey
                        )
                ))
        );

        String sanitizedResource = spec.resourceKey().replace('.', '-');
        String sanitizedAction = actionKey.replace('.', '-');
        String policyId = "pol-" + serviceKey + "-" + sanitizedResource + "-act-" + sanitizedAction;
        String unitKey = "unit:" + policyId + ":v1";

        AuthorizationPolicyDefinition policy = new AuthorizationPolicyDefinition(
                AuthorizationPolicyDefinition.SCHEMA_VERSION_V1,
                policyId,
                "1.0.0",
                "Action Policy (" + actionKey + ") for " + spec.resourceKey(),
                "Declarative workflow action authorization policy",
                Set.of("WORKFLOW_ACTION"),
                actionDp.legalPurpose() != null ? actionDp.legalPurpose() : "STATUTORY_LEGAL_OBLIGATION",
                actionDp.legalBasisRef() != null ? actionDp.legalBasisRef() : "LGPD:ART_7_III",
                OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                List.of(PolicyTargetSpec.exact(
                        "tgt-" + sanitizedResource + "-act-" + sanitizedAction,
                        actionDp.identity().pointKey(),
                        actionDp.descriptorDigest(),
                        Set.of(EvaluationMode.TARGET)
                )),
                spec.dualScopeDelegationSpec(),
                List.of(),
                List.of(rule),
                List.of(new PolicyMaterializationTargetSpec(
                        "policy_engine",
                        "opa-policy",
                        unitKey,
                        OpaProviderIoSchemas.COMPILER_PROFILE_V1
                ))
        );
        return addPolicy(policy);
    }

    /**
     * Synthesizes and registers a collection-and-target {@link AuthorizationPolicyDefinition} for a
     * governed bulk workflow action ({@code @WorkflowAction(scope = ActionScope.COLLECTION)} /
     * {@code BulkMode.DOMAIN_COMMAND}) registered via {@link AuthzResourceGovernanceSpec.Builder#bulkWorkflowAction}
     * ({@code Fase P10.16-A}).
     *
     * @param spec target governed resource specification
     * @param actionKey bulk action key registered via {@code .bulkWorkflowAction(actionKey, ...)}
     * @param ruleId unique rule identifier
     * @param resourceScopeFactPath resource fact path (e.g. {@code "resource.lotacaoSetorId"})
     * @param subjectScopeSetFactPath subject collection fact path (e.g. {@code "subject.organizationUnitIds"})
     * @param allowedAttributeWrites set of canonical {@code attributeId}s granted write access
     * @return this builder
     */
    public AuthzHostPolicyBootstrapBuilder addBulkActionPolicy(
            AuthzResourceGovernanceSpec<?> spec,
            String actionKey,
            String ruleId,
            String resourceScopeFactPath,
            String subjectScopeSetFactPath,
            Set<String> allowedAttributeWrites
    ) {
        Objects.requireNonNull(resourceScopeFactPath, "resourceScopeFactPath is required");
        Objects.requireNonNull(subjectScopeSetFactPath, "subjectScopeSetFactPath is required");
        Map<String, Object> baseScope = Map.of("in", List.of(
                Map.of("var", resourceScopeFactPath),
                Map.of("var", subjectScopeSetFactPath)
        ));
        Map<String, Object> dataScopeSearchCondition = spec.allowGlobalNullScope()
                ? Map.of("or", List.of(baseScope, Map.of("is_null", List.of(Map.of("var", resourceScopeFactPath)))))
                : baseScope;
        return addBulkActionPolicy(
                spec,
                actionKey,
                ruleId,
                Map.of("!=", List.of(Map.of("var", "subject.principalId"), "")),
                dataScopeSearchCondition,
                allowedAttributeWrites
        );
    }

    /**
     * Synthesizes and registers a collection-and-target {@link AuthorizationPolicyDefinition} for a
     * governed bulk workflow action ({@code @WorkflowAction(scope = ActionScope.COLLECTION)} /
     * {@code BulkMode.DOMAIN_COMMAND}) with explicit JSON-Logic admission and data-scope conditions
     * ({@code Fase P10.16-A}).
     *
     * @param spec target governed resource specification
     * @param actionKey bulk action key registered via {@code .bulkWorkflowAction(actionKey, ...)}
     * @param ruleId unique rule identifier
     * @param admissionCondition JSON-Logic condition evaluated in {@code SEARCH} and {@code TARGET} modes
     * @param dataScopeSearchCondition JSON-Logic data-scope condition evaluated in {@code SEARCH} and {@code TARGET} modes
     * @param allowedAttributeWrites optional set of canonical {@code attributeId}s granted write access
     * @return this builder
     */
    public AuthzHostPolicyBootstrapBuilder addBulkActionPolicy(
            AuthzResourceGovernanceSpec<?> spec,
            String actionKey,
            String ruleId,
            Map<String, Object> admissionCondition,
            Map<String, Object> dataScopeSearchCondition,
            Set<String> allowedAttributeWrites
    ) {
        Objects.requireNonNull(spec, "spec is required");
        Objects.requireNonNull(actionKey, "actionKey is required");
        Objects.requireNonNull(ruleId, "ruleId is required");
        Objects.requireNonNull(admissionCondition, "admissionCondition is required");
        Objects.requireNonNull(dataScopeSearchCondition, "dataScopeSearchCondition is required");

        DecisionPointDescriptor actionDp = spec.actionDecisionPoints().get(actionKey);
        if (actionDp == null) {
            throw new IllegalArgumentException(
                    "Unknown bulk actionKey '" + actionKey + "' on spec for resource '" + spec.resourceKey()
                            + "'; register it via .bulkWorkflowAction(\"" + actionKey + "\", ...)"
            );
        }
        if (!actionDp.evaluationModes().contains(EvaluationMode.SEARCH)
                || !actionDp.supportedCapabilities().contains(org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability.DATA_SCOPE)
                || actionDp.queryProjectionRef() == null) {
            throw new IllegalArgumentException(
                    "Action '" + actionKey + "' on spec for resource '" + spec.resourceKey()
                            + "' does not support collection-scoped bulk execution (missing EvaluationMode.SEARCH, DATA_SCOPE, or QueryableProjectionRef); "
                            + "register it via .bulkWorkflowAction(\"" + actionKey + "\", ...) instead of .workflowAction(...)"
            );
        }

        List<FieldWriteContributionSpec> fieldWrites = new ArrayList<>();
        if (allowedAttributeWrites != null && !allowedAttributeWrites.isEmpty()) {
            fieldWrites.add(new FieldWriteContributionSpec(
                    PolicyFieldSelector.exact(Set.copyOf(allowedAttributeWrites)),
                    RuleEffect.ALLOW
            ));
        }

        Set<EvaluationMode> evalModes = actionDp.evaluationModes().isEmpty()
                ? Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET)
                : actionDp.evaluationModes();

        String actionReasonSuffix = actionKey.toUpperCase().replace('-', '_').replace('.', '_');
        List<ObligationDirective> auditObligations = List.of(new ObligationDirective(
                "DURABLE_AUDIT_EVIDENCE",
                "ON_PERMIT",
                "BEFORE_COMMIT_OUTBOX",
                Map.of(
                        "auditCategory", "GOVERNED_BULK_WORKFLOW_ACTION",
                        "actionKey", actionKey
                )
        ));

        List<AuthorizationPolicyRule> rules = new ArrayList<>(2);
        if (evalModes.contains(EvaluationMode.SEARCH)) {
            rules.add(new AuthorizationPolicyRule(
                    ruleId + "-search",
                    "Grants collection-level SEARCH admission and data scope for bulk workflow action '"
                            + actionKey + "' on " + spec.resourceKey(),
                    Set.of(EvaluationMode.SEARCH),
                    new AuthorizationSourceCondition(
                            AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                            ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                            admissionCondition
                    ),
                    new AuthorizationRuleContributions(
                            new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                            new DataScopeContributionSpec(
                                    ContributionAuthority.GRANT,
                                    new AuthorizationSourceCondition(
                                            AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                            ConditionProfileKind.AUTHORIZATION_SEARCH_SOURCE_V1,
                                            dataScopeSearchCondition
                                    )
                            ),
                            List.of(),
                            List.copyOf(fieldWrites),
                            List.of(),
                            "ALLOW_BULK_ACTION_SEARCH_" + actionReasonSuffix
                    ),
                    auditObligations
            ));
        }
        if (evalModes.contains(EvaluationMode.TARGET)) {
            Map<String, Object> targetCombinedCondition = combineAndConditions(
                    List.of(admissionCondition, dataScopeSearchCondition)
            );
            rules.add(new AuthorizationPolicyRule(
                    ruleId + "-target",
                    "Grants per-item TARGET execution for bulk workflow action '"
                            + actionKey + "' on " + spec.resourceKey(),
                    Set.of(EvaluationMode.TARGET),
                    new AuthorizationSourceCondition(
                            AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                            ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                            targetCombinedCondition
                    ),
                    new AuthorizationRuleContributions(
                            new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                            null,
                            List.of(),
                            List.copyOf(fieldWrites),
                            List.of(),
                            "ALLOW_BULK_ACTION_TARGET_" + actionReasonSuffix
                    ),
                    auditObligations
            ));
        }

        String sanitizedResource = spec.resourceKey().replace('.', '-');
        String sanitizedAction = actionKey.replace('.', '-');
        String policyId = "pol-" + serviceKey + "-" + sanitizedResource + "-bulk-act-" + sanitizedAction;
        String unitKey = "unit:" + policyId + ":v1";

        AuthorizationPolicyDefinition policy = new AuthorizationPolicyDefinition(
                AuthorizationPolicyDefinition.SCHEMA_VERSION_V1,
                policyId,
                "1.0.0",
                "Bulk Action Policy (" + actionKey + ") for " + spec.resourceKey(),
                "Declarative collection-scoped bulk workflow action authorization policy",
                Set.of("BULK_WORKFLOW_ACTION"),
                actionDp.legalPurpose() != null ? actionDp.legalPurpose() : "STATUTORY_LEGAL_OBLIGATION",
                actionDp.legalBasisRef() != null ? actionDp.legalBasisRef() : "LGPD:ART_7_III",
                OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                List.of(PolicyTargetSpec.exact(
                        "tgt-" + sanitizedResource + "-bulk-act-" + sanitizedAction,
                        actionDp.identity().pointKey(),
                        actionDp.descriptorDigest(),
                        evalModes
                )),
                spec.dualScopeDelegationSpec(),
                List.of(),
                List.copyOf(rules),
                List.of(new PolicyMaterializationTargetSpec(
                        "policy_engine",
                        "opa-policy",
                        unitKey,
                        OpaProviderIoSchemas.COMPILER_PROFILE_V1
                ))
        );
        return addPolicy(policy);
    }

    /**
     * Synthesizes and registers a collection-and-target {@link AuthorizationPolicyDefinition} for an
     * {@code AUTHENTICATED_SHARED} bulk workflow action ({@code BulkMode.DOMAIN_COMMAND}), using a
     * non-null predicate on the resource's primary queryable field for its shared {@code SEARCH} scope.
     */
    public AuthzHostPolicyBootstrapBuilder addSharedBulkActionPolicy(
            AuthzResourceGovernanceSpec<?> spec,
            String actionKey,
            String ruleId,
            Map<String, Object> admissionCondition,
            Set<String> allowedAttributeWrites
    ) {
        Objects.requireNonNull(spec, "spec is required");
        String primaryFieldPath = resolvePrimaryQueryableFieldPath(spec);
        Map<String, Object> nonNullScopeCondition = Map.of(
                "is_not_null",
                List.of(Map.of("var", primaryFieldPath))
        );
        return addBulkActionPolicy(
                spec,
                actionKey,
                ruleId,
                admissionCondition,
                nonNullScopeCondition,
                allowedAttributeWrites
        );
    }

    /**
     * Synthesizes and registers an {@link AuthorizationPolicyDefinition} targeting a custom surface
     * decision point ({@link AuthzResourceGovernanceSpec#surfaceDecisionPoints()}) with optional
     * field-masking directives ({@code Fase P10.15-C}).
     *
     * @param spec target governed resource specification
     * @param surfaceKey surface key registered via {@code .surfaceDecisionPoint(surfaceKey, ...)}
     * @param ruleId unique rule identifier
     * @param targetJsonLogicCondition JSON-Logic condition evaluated for the surface
     * @param redactConstantMasksByAttributeId optional map of {@code attributeId} to constant mask replacement
     * @return this builder
     */
    private static List<MaskContributionSpec> toRedactConstantMasks(
            Map<String, String> redactConstantMasksByAttributeId
    ) {
        if (redactConstantMasksByAttributeId == null || redactConstantMasksByAttributeId.isEmpty()) {
            return List.of();
        }
        List<MaskContributionSpec> masks = new ArrayList<>(redactConstantMasksByAttributeId.size());
        for (Map.Entry<String, String> entry : redactConstantMasksByAttributeId.entrySet()) {
            masks.add(new MaskContributionSpec(
                    PolicyFieldSelector.exact(Set.of(entry.getKey())),
                    "REDACT_CONSTANT",
                    Map.of("replacement", entry.getValue())
            ));
        }
        return List.copyOf(masks);
    }

    public AuthzHostPolicyBootstrapBuilder addSurfacePolicy(
            AuthzResourceGovernanceSpec<?> spec,
            String surfaceKey,
            String ruleId,
            Map<String, Object> targetJsonLogicCondition,
            Map<String, String> redactConstantMasksByAttributeId
    ) {
        return addSurfacePolicy(
                spec,
                surfaceKey,
                ruleId,
                targetJsonLogicCondition,
                toRedactConstantMasks(redactConstantMasksByAttributeId)
        );
    }

    /**
     * Synthesizes and registers an {@link AuthorizationPolicyDefinition} targeting a declarative
     * UI surface decision point using explicit {@link MaskContributionSpec} directives.
     */
    public AuthzHostPolicyBootstrapBuilder addSurfacePolicy(
            AuthzResourceGovernanceSpec<?> spec,
            String surfaceKey,
            String ruleId,
            Map<String, Object> targetJsonLogicCondition,
            List<MaskContributionSpec> maskDirectives
    ) {
        Objects.requireNonNull(spec, "spec is required");
        Objects.requireNonNull(surfaceKey, "surfaceKey is required");
        Objects.requireNonNull(ruleId, "ruleId is required");
        Objects.requireNonNull(targetJsonLogicCondition, "targetJsonLogicCondition is required");

        DecisionPointDescriptor surfaceDp = spec.surfaceDecisionPoints().get(surfaceKey);
        if (surfaceDp == null) {
            throw new IllegalArgumentException(
                    "Unknown surfaceKey '" + surfaceKey + "' on spec for resource '" + spec.resourceKey()
                            + "'; register it via .surfaceDecisionPoint(\"" + surfaceKey + "\", ...)"
            );
        }

        List<MaskContributionSpec> masks = maskDirectives == null ? List.of() : List.copyOf(maskDirectives);

        Set<EvaluationMode> evalModes = surfaceDp.evaluationModes().isEmpty()
                ? Set.of(EvaluationMode.TARGET)
                : surfaceDp.evaluationModes();

        AuthorizationPolicyRule rule = new AuthorizationPolicyRule(
                ruleId,
                "Grants surface '" + surfaceKey + "' access for " + spec.resourceKey(),
                evalModes,
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        targetJsonLogicCondition
                ),
                new AuthorizationRuleContributions(
                        new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                        null,
                        List.of(),
                        List.of(),
                        List.copyOf(masks),
                        "ALLOW_SURFACE_" + surfaceKey.toUpperCase().replace('-', '_').replace('.', '_')
                ),
                List.of(new ObligationDirective(
                        "DURABLE_AUDIT_EVIDENCE",
                        "ON_PERMIT",
                        "BEFORE_COMMIT_OUTBOX",
                        Map.of(
                                "auditCategory", "GOVERNED_SURFACE_ACCESS",
                                "surfaceKey", surfaceKey
                        )
                ))
        );

        String sanitizedResource = spec.resourceKey().replace('.', '-');
        String sanitizedSurface = surfaceKey.replace('.', '-');
        String policyId = "pol-" + serviceKey + "-" + sanitizedResource + "-srf-" + sanitizedSurface;
        String unitKey = "unit:" + policyId + ":v1";

        AuthorizationPolicyDefinition policy = new AuthorizationPolicyDefinition(
                AuthorizationPolicyDefinition.SCHEMA_VERSION_V1,
                policyId,
                "1.0.0",
                "Surface Policy (" + surfaceKey + ") for " + spec.resourceKey(),
                "Declarative UI surface authorization and masking policy",
                Set.of("UI_SURFACE"),
                surfaceDp.legalPurpose() != null ? surfaceDp.legalPurpose() : "STATUTORY_LEGAL_OBLIGATION",
                surfaceDp.legalBasisRef() != null ? surfaceDp.legalBasisRef() : "LGPD:ART_7_III",
                OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                List.of(PolicyTargetSpec.exact(
                        "tgt-" + sanitizedResource + "-srf-" + sanitizedSurface,
                        surfaceDp.identity().pointKey(),
                        surfaceDp.descriptorDigest(),
                        evalModes
                )),
                spec.dualScopeDelegationSpec(),
                List.of(),
                List.of(rule),
                List.of(new PolicyMaterializationTargetSpec(
                        "policy_engine",
                        "opa-policy",
                        unitKey,
                        OpaProviderIoSchemas.COMPILER_PROFILE_V1
                ))
        );
        return addPolicy(policy);
    }

    /**
     * Synthesizes and registers zero-config baseline authorization, data-scope, field-masking,
     * workflow-action, and UI-surface policies directly from an annotation-introspected
     * {@link AuthzResourceGovernanceSpec} ({@code Wave 1.4B}).
     *
     * <p>Masks are drawn from {@link AuthzResourceGovernanceSpec#maskSpecs()} (combining explicit
     * {@link org.praxisplatform.authz.contracts.annotation.AuthzMask} declarations and auto-derived
     * {@link org.praxisplatform.uischema.annotation.DomainGovernance} redactions). Disjunctive role
     * and rule conditions keep {@code "or"} at the JSON-Logic root so {@code RegoV1PolicyCompiler}
     * always materializes real Rego rules.</p>
     *
     * @param spec target governed resource specification
     * @return this builder
     */
    public AuthzHostPolicyBootstrapBuilder addAnnotatedResource(AuthzResourceGovernanceSpec<?> spec) {
        return addAnnotatedResource(spec, null, null, null);
    }

    /**
     * Synthesizes and registers zero-config policies from {@code spec}, optionally augmenting
     * masking directives by introspecting additional response/create/update DTO classes.
     *
     * @param spec target governed resource specification
     * @param responseDtoClass optional response DTO class for additional {@code @AuthzMask}/{@code @DomainGovernance} masks
     * @param createDtoClass optional create DTO class
     * @param updateDtoClass optional update DTO class
     * @return this builder
     */
    public AuthzHostPolicyBootstrapBuilder addAnnotatedResource(
            AuthzResourceGovernanceSpec<?> spec,
            Class<?> responseDtoClass,
            Class<?> createDtoClass,
            Class<?> updateDtoClass
    ) {
        Objects.requireNonNull(spec, "spec is required");
        addResourceSpec(spec, responseDtoClass, createDtoClass, updateDtoClass);
        List<MetadataDtoGovernanceIntrospector.DeclaredMaskSpec> effectiveMasks =
                collectEffectiveMasks(spec, responseDtoClass, createDtoClass, updateDtoClass);
        synthesizeAnnotatedPrimaryScopePolicy(spec, effectiveMasks);
        synthesizeAnnotatedActionPolicies(spec);
        synthesizeAnnotatedSurfacePolicies(spec, effectiveMasks);
        return this;
    }

    /**
     * Registers zero-config baseline policies for all supplied {@link AuthzResourceGovernanceSpec}s.
     *
     * @param specs governed resource specifications
     * @return this builder
     */
    public AuthzHostPolicyBootstrapBuilder addAnnotatedResources(
            java.util.Collection<? extends AuthzResourceGovernanceSpec<?>> specs
    ) {
        Objects.requireNonNull(specs, "specs is required");
        for (AuthzResourceGovernanceSpec<?> spec : specs) {
            if (spec != null) {
                addAnnotatedResource(spec);
            }
        }
        return this;
    }

    private List<MetadataDtoGovernanceIntrospector.DeclaredMaskSpec> collectEffectiveMasks(
            AuthzResourceGovernanceSpec<?> spec,
            Class<?> responseDtoClass,
            Class<?> createDtoClass,
            Class<?> updateDtoClass
    ) {
        List<MetadataDtoGovernanceIntrospector.DeclaredMaskSpec> merged = new ArrayList<>(spec.maskSpecs());
        Set<String> coveredAttributes = new java.util.LinkedHashSet<>();
        for (MetadataDtoGovernanceIntrospector.DeclaredMaskSpec mask : merged) {
            if (mask.contribution().fieldSelector() != null
                    && mask.contribution().fieldSelector().attributeIds() != null) {
                coveredAttributes.addAll(mask.contribution().fieldSelector().attributeIds());
            }
        }
        MetadataDtoGovernanceIntrospector introspector = new MetadataDtoGovernanceIntrospector();
        Class<?> fallbackResponse = responseDtoClass;
        for (Class<?> dto : new Class<?>[] {responseDtoClass, createDtoClass, updateDtoClass}) {
            if (dto == null) {
                continue;
            }
            var contract = dto == responseDtoClass
                    ? introspector.introspect(dto, spec.resourceKey())
                    : introspector.introspectWriteDto(dto, fallbackResponse, spec.resourceKey());
            for (MetadataDtoGovernanceIntrospector.DeclaredMaskSpec declared : contract.declaredMasks()) {
                Set<String> attrs = declared.contribution().fieldSelector() != null
                        ? declared.contribution().fieldSelector().attributeIds()
                        : Set.of();
                if (attrs.isEmpty() || !coveredAttributes.containsAll(attrs)) {
                    merged.add(declared);
                    coveredAttributes.addAll(attrs);
                }
            }
            for (MaskContributionSpec derived : contract.derivedMasks()) {
                Set<String> attrs = derived.fieldSelector() != null
                        ? derived.fieldSelector().attributeIds()
                        : Set.of();
                if (!attrs.isEmpty() && !coveredAttributes.containsAll(attrs)) {
                    merged.add(new MetadataDtoGovernanceIntrospector.DeclaredMaskSpec(
                            derived,
                            Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET),
                            Set.of(),
                            "Auto-derived from @DomainGovernance"
                    ));
                    coveredAttributes.addAll(attrs);
                }
            }
        }
        return List.copyOf(merged);
    }

    private void synthesizeAnnotatedPrimaryScopePolicy(
            AuthzResourceGovernanceSpec<?> spec,
            List<MetadataDtoGovernanceIntrospector.DeclaredMaskSpec> allMasks
    ) {
        DecisionPointDescriptor dp = spec.decisionPoint();
        if (dp == null) {
            return;
        }
        List<MaskContributionSpec> searchMasks = allMasks.stream()
                .filter(m -> m.surfaces().isEmpty() && m.modes().contains(EvaluationMode.SEARCH))
                .map(MetadataDtoGovernanceIntrospector.DeclaredMaskSpec::contribution)
                .toList();
        List<MaskContributionSpec> targetMasks = allMasks.stream()
                .filter(m -> m.surfaces().isEmpty() && m.modes().contains(EvaluationMode.TARGET))
                .map(MetadataDtoGovernanceIntrospector.DeclaredMaskSpec::contribution)
                .toList();

        String sanitizedResource = spec.resourceKey().replace('.', '-');
        AuthzResourceGovernanceSpec.TenantScopeSpec tenantSpec = spec.tenantScopeSpec();
        String policyId = (tenantSpec != null && !tenantSpec.policyId().isBlank())
                ? tenantSpec.policyId()
                : "pol-" + serviceKey + "-" + sanitizedResource + "-scope";
        String baseRuleId = (tenantSpec != null && !tenantSpec.ruleId().isBlank())
                ? tenantSpec.ruleId()
                : "rule-" + sanitizedResource + "-scope";
        String unitKey = "unit:" + policyId + ":v1";

        List<ObligationDirective> auditObligations = List.of(new ObligationDirective(
                "DURABLE_AUDIT_EVIDENCE",
                "ON_PERMIT",
                "BEFORE_COMMIT_OUTBOX",
                Map.of(
                        "auditCategory", "GOVERNED_RESOURCE_ACCESS",
                        "resourceKey", spec.resourceKey()
                )
        ));

        List<AuthorizationPolicyRule> rules = new ArrayList<>();
        Map<String, Object> principalPresent = Map.of("is_not_null", Map.of("var", "subject.principalId"));

        if (spec.dualScopeDelegationSpec() != null) {
            var dual = spec.dualScopeDelegationSpec();
            String originResourceFact = dual.originFactPath();
            String originSubjectFact = spec.originSubjectFactKey() != null
                    ? spec.originSubjectFactKey()
                    : "subject.organizationUnitIds";
            Map<String, Object> originPred = Map.of(
                    "in",
                    List.of(Map.of("var", originResourceFact), Map.of("var", originSubjectFact))
            );
            Map<String, Object> originAdmission = Map.of(
                    "and",
                    List.of(principalPresent, Map.of("is_not_null", Map.of("var", originSubjectFact)))
            );
            rules.add(new AuthorizationPolicyRule(
                    baseRuleId + "-origin-search",
                    "Origin custody SEARCH scope for " + spec.resourceKey(),
                    Set.of(EvaluationMode.SEARCH),
                    new AuthorizationSourceCondition(
                            AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                            ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                            originAdmission
                    ),
                    new AuthorizationRuleContributions(
                            new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                            new DataScopeContributionSpec(
                                    ContributionAuthority.GRANT,
                                    new AuthorizationSourceCondition(
                                            AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                            ConditionProfileKind.AUTHORIZATION_SEARCH_SOURCE_V1,
                                            originPred
                                    )
                            ),
                            List.of(),
                            List.of(),
                            searchMasks,
                            "ALLOW_ORIGIN_CUSTODY_SEARCH"
                    ),
                    auditObligations
            ));
            rules.add(new AuthorizationPolicyRule(
                    baseRuleId + "-origin-target",
                    "Origin custody TARGET access for " + spec.resourceKey(),
                    Set.of(EvaluationMode.TARGET),
                    new AuthorizationSourceCondition(
                            AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                            ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                            combineAndConditions(List.of(originAdmission, originPred))
                    ),
                    new AuthorizationRuleContributions(
                            new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                            null,
                            List.of(),
                            List.of(),
                            targetMasks,
                            "ALLOW_ORIGIN_CUSTODY_TARGET"
                    ),
                    auditObligations
            ));

            String destResourceFact = dual.destinationFactPath();
            if (destResourceFact != null && !destResourceFact.isBlank()) {
                String destSubjectFact = spec.destinationSubjectFactKey() != null
                        ? spec.destinationSubjectFactKey()
                        : "subject.organizationUnitIds";
                Map<String, Object> destPred = Map.of(
                        "in",
                        List.of(Map.of("var", destResourceFact), Map.of("var", destSubjectFact))
                );
                Map<String, Object> destAdmission = Map.of(
                        "and",
                        List.of(principalPresent, Map.of("is_not_null", Map.of("var", destSubjectFact)))
                );
                List<FieldWriteContributionSpec> destFieldWrites =
                        ((org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec.ORIGIN_DESTINATION_SPLIT.equals(dual.mode())
                                || "CEDENTE_CESSIONARIO_SPLIT".equals(dual.mode()))
                                && dual.destinationAllowedWriteAttributes() != null
                                && !dual.destinationAllowedWriteAttributes().isEmpty())
                                ? List.of(new FieldWriteContributionSpec(
                                        PolicyFieldSelector.exact(Set.copyOf(dual.destinationAllowedWriteAttributes())),
                                        RuleEffect.ALLOW
                                ))
                                : List.of();
                rules.add(new AuthorizationPolicyRule(
                        baseRuleId + "-dest-search",
                        "Destination custody SEARCH scope for " + spec.resourceKey(),
                        Set.of(EvaluationMode.SEARCH),
                        new AuthorizationSourceCondition(
                                AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                                destAdmission
                        ),
                        new AuthorizationRuleContributions(
                                new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                                new DataScopeContributionSpec(
                                        ContributionAuthority.GRANT,
                                        new AuthorizationSourceCondition(
                                                AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                                ConditionProfileKind.AUTHORIZATION_SEARCH_SOURCE_V1,
                                                destPred
                                        )
                                ),
                                List.of(),
                                destFieldWrites,
                                searchMasks,
                                "ALLOW_DESTINATION_CUSTODY_SEARCH"
                        ),
                        auditObligations
                ));
                rules.add(new AuthorizationPolicyRule(
                        baseRuleId + "-dest-target",
                        "Destination custody TARGET access for " + spec.resourceKey(),
                        Set.of(EvaluationMode.TARGET),
                        new AuthorizationSourceCondition(
                                AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                                combineAndConditions(List.of(destAdmission, destPred))
                        ),
                        new AuthorizationRuleContributions(
                                new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                                null,
                                List.of(),
                                destFieldWrites,
                                targetMasks,
                                "ALLOW_DESTINATION_CUSTODY_TARGET"
                        ),
                        auditObligations
                ));
            }
        } else if (spec.tenantScopeMode()
                == org.praxisplatform.authz.contracts.annotation.AuthzTenantScopeMode.AUTHENTICATED_SHARED) {
            List<FieldUseContributionSpec> searchFieldUse =
                    searchMasks.isEmpty() ? defaultSearchFieldUse(spec) : List.of();
            rules.add(new AuthorizationPolicyRule(
                    baseRuleId + "-shared-search",
                    "Authenticated shared SEARCH access for " + spec.resourceKey(),
                    Set.of(EvaluationMode.SEARCH),
                    new AuthorizationSourceCondition(
                            AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                            ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                            principalPresent
                    ),
                    new AuthorizationRuleContributions(
                            new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                            null,
                            searchFieldUse,
                            List.of(),
                            searchMasks,
                            "ALLOW_AUTHENTICATED_SHARED_SEARCH"
                    ),
                    auditObligations
            ));
            rules.add(new AuthorizationPolicyRule(
                    baseRuleId + "-shared-target",
                    "Authenticated shared TARGET access for " + spec.resourceKey(),
                    Set.of(EvaluationMode.TARGET),
                    new AuthorizationSourceCondition(
                            AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                            ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                            principalPresent
                    ),
                    new AuthorizationRuleContributions(
                            new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                            null,
                            List.of(),
                            List.of(),
                            targetMasks,
                            "ALLOW_AUTHENTICATED_SHARED_TARGET"
                    ),
                    auditObligations
            ));
        } else {
            Map<String, Object> scopePred = buildResourceScopePredicate(spec);
            Map<String, Object> searchAdmission = buildSubjectScopeAdmissionCondition(spec);
            Map<String, Object> targetCond = combineAndConditions(List.of(searchAdmission, scopePred));
            rules.add(new AuthorizationPolicyRule(
                    baseRuleId + "-search",
                    "Scoped SEARCH access and data filter for " + spec.resourceKey(),
                    Set.of(EvaluationMode.SEARCH),
                    new AuthorizationSourceCondition(
                            AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                            ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                            searchAdmission
                    ),
                    new AuthorizationRuleContributions(
                            new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                            new DataScopeContributionSpec(
                                    ContributionAuthority.GRANT,
                                    new AuthorizationSourceCondition(
                                            AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                            ConditionProfileKind.AUTHORIZATION_SEARCH_SOURCE_V1,
                                            scopePred
                                    )
                            ),
                            List.of(),
                            List.of(),
                            searchMasks,
                            "ALLOW_SCOPED_RESOURCE_SEARCH"
                    ),
                    auditObligations
            ));
            rules.add(new AuthorizationPolicyRule(
                    baseRuleId + "-target",
                    "Scoped TARGET access and masking for " + spec.resourceKey(),
                    Set.of(EvaluationMode.TARGET),
                    new AuthorizationSourceCondition(
                            AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                            ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                            targetCond
                    ),
                    new AuthorizationRuleContributions(
                            new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                            null,
                            List.of(),
                            List.of(),
                            targetMasks,
                            "ALLOW_SCOPED_RESOURCE_TARGET"
                    ),
                    auditObligations
            ));
        }

        Set<EvaluationMode> dpModes = dp.evaluationModes().isEmpty()
                ? Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET)
                : dp.evaluationModes();
        AuthorizationPolicyDefinition policy = new AuthorizationPolicyDefinition(
                AuthorizationPolicyDefinition.SCHEMA_VERSION_V1,
                policyId,
                "1.0.0",
                "Zero-Config Scope Policy for " + spec.resourceKey(),
                "Annotation-derived scope, field-masking, and durable audit authorization policy",
                Set.of("TENANT_SCOPE"),
                dp.legalPurpose() != null ? dp.legalPurpose() : "STATUTORY_LEGAL_OBLIGATION",
                dp.legalBasisRef() != null ? dp.legalBasisRef() : "LGPD:ART_7_III",
                OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                List.of(PolicyTargetSpec.exact(
                        "tgt-" + sanitizedResource + "-scope",
                        dp.identity().pointKey(),
                        dp.descriptorDigest(),
                        dpModes
                )),
                spec.dualScopeDelegationSpec(),
                List.of(),
                List.copyOf(rules),
                List.of(new PolicyMaterializationTargetSpec(
                        "policy_engine",
                        "opa-policy",
                        unitKey,
                        OpaProviderIoSchemas.COMPILER_PROFILE_V1
                ))
        );
        addPolicy(policy);
    }

    private void synthesizeAnnotatedActionPolicies(AuthzResourceGovernanceSpec<?> spec) {
        if (spec.actionDecisionPoints().isEmpty()) {
            return;
        }
        String sanitizedResource = spec.resourceKey().replace('.', '-');
        for (Map.Entry<String, DecisionPointDescriptor> entry : spec.actionDecisionPoints().entrySet()) {
            String actionKey = entry.getKey();
            DecisionPointDescriptor actionDp = entry.getValue();
            AuthzResourceGovernanceSpec.ActionRuleSpec ruleSpec = spec.actionRuleSpecs().get(actionKey);
            String sanitizedAction = actionKey.replace('.', '-');
            boolean isBulk = actionDp.evaluationModes().contains(EvaluationMode.SEARCH)
                    && actionDp.supportedCapabilities().contains(EnforcementCapability.DATA_SCOPE)
                    && actionDp.queryProjectionRef() != null;

            String policyId = (ruleSpec != null && !ruleSpec.policyId().isBlank())
                    ? ruleSpec.policyId()
                    : "pol-" + serviceKey + "-" + sanitizedResource
                            + (isBulk ? "-bulk-act-" : "-act-") + sanitizedAction;
            String ruleId = (ruleSpec != null && !ruleSpec.ruleId().isBlank())
                    ? ruleSpec.ruleId()
                    : "rule-" + sanitizedResource + "-act-" + sanitizedAction;
            String unitKey = "unit:" + policyId + ":v1";

            Set<String> allowedWrites = new java.util.LinkedHashSet<>();
            if (ruleSpec != null && !ruleSpec.allowedWriteAttributes().isEmpty()) {
                allowedWrites.addAll(ruleSpec.allowedWriteAttributes());
            } else {
                Set<String> inferred = spec.operationModifiedAttributes().get(actionKey);
                if (inferred != null) {
                    allowedWrites.addAll(inferred);
                }
            }
            List<FieldWriteContributionSpec> fieldWrites = allowedWrites.isEmpty()
                    ? List.of()
                    : List.of(new FieldWriteContributionSpec(
                            PolicyFieldSelector.exact(Set.copyOf(allowedWrites)),
                            RuleEffect.ALLOW
                    ));

            String reasonCode = (ruleSpec != null && !ruleSpec.reasonCode().isBlank())
                    ? ruleSpec.reasonCode()
                    : ("ALLOW_" + (isBulk ? "BULK_ACTION_" : "ACTION_")
                            + actionKey.toUpperCase().replace('-', '_').replace('.', '_'));
            boolean auditRequired = ruleSpec == null || ruleSpec.auditRequired();
            String auditCategory = (ruleSpec != null && !ruleSpec.auditCategory().isBlank())
                    ? ruleSpec.auditCategory()
                    : (isBulk ? "GOVERNED_BULK_WORKFLOW_ACTION" : "GOVERNED_WORKFLOW_ACTION");
            List<ObligationDirective> obligations = auditRequired
                    ? List.of(new ObligationDirective(
                            "DURABLE_AUDIT_EVIDENCE",
                            "ON_PERMIT",
                            "BEFORE_COMMIT_OUTBOX",
                            Map.of("auditCategory", auditCategory, "actionKey", actionKey)
                    ))
                    : List.of();

            Set<EvaluationMode> evalModes = actionDp.evaluationModes().isEmpty()
                    ? Set.of(EvaluationMode.TARGET)
                    : actionDp.evaluationModes();

            List<AuthorizationPolicyRule> rules = new ArrayList<>();
            if (evalModes.contains(EvaluationMode.SEARCH)) {
                Map<String, Object> searchCond = buildAnnotatedRuleCondition(spec, ruleSpec, false);
                Map<String, Object> searchScopeExpr = spec.tenantScopeMode()
                        == org.praxisplatform.authz.contracts.annotation.AuthzTenantScopeMode.AUTHENTICATED_SHARED
                        ? Map.of("is_not_null", List.of(Map.of("var", resolvePrimaryQueryableFieldPath(spec))))
                        : buildResourceScopePredicate(spec);
                DataScopeContributionSpec searchScope = new DataScopeContributionSpec(
                        ContributionAuthority.GRANT,
                        new AuthorizationSourceCondition(
                                AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                ConditionProfileKind.AUTHORIZATION_SEARCH_SOURCE_V1,
                                searchScopeExpr
                        )
                );
                rules.add(new AuthorizationPolicyRule(
                        ruleId + "-search",
                        "Grants SEARCH admission and scope for workflow action '" + actionKey
                                + "' on " + spec.resourceKey(),
                        Set.of(EvaluationMode.SEARCH),
                        new AuthorizationSourceCondition(
                                AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                                searchCond
                        ),
                        new AuthorizationRuleContributions(
                                new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                                searchScope,
                                List.of(),
                                fieldWrites,
                                List.of(),
                                reasonCode
                        ),
                        obligations
                ));
            }
            if (evalModes.contains(EvaluationMode.TARGET)) {
                Map<String, Object> targetCond = buildAnnotatedRuleCondition(spec, ruleSpec, true);
                rules.add(new AuthorizationPolicyRule(
                        isBulk ? ruleId + "-target" : ruleId,
                        "Grants TARGET execution for workflow action '" + actionKey
                                + "' on " + spec.resourceKey(),
                        Set.of(EvaluationMode.TARGET),
                        new AuthorizationSourceCondition(
                                AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                                targetCond
                        ),
                        new AuthorizationRuleContributions(
                                new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                                null,
                                List.of(),
                                fieldWrites,
                                List.of(),
                                reasonCode
                        ),
                        obligations
                ));
            }

            String legalPurpose = (ruleSpec != null && !ruleSpec.legalPurpose().isBlank())
                    ? ruleSpec.legalPurpose()
                    : (actionDp.legalPurpose() != null ? actionDp.legalPurpose() : "STATUTORY_LEGAL_OBLIGATION");
            String legalBasisRef = (ruleSpec != null && !ruleSpec.legalBasisRef().isBlank())
                    ? ruleSpec.legalBasisRef()
                    : (actionDp.legalBasisRef() != null ? actionDp.legalBasisRef() : "LGPD:ART_7_III");
            String description = (ruleSpec != null && !ruleSpec.description().isBlank())
                    ? ruleSpec.description()
                    : "Declarative workflow action authorization policy for '" + actionKey + "'";

            addPolicy(new AuthorizationPolicyDefinition(
                    AuthorizationPolicyDefinition.SCHEMA_VERSION_V1,
                    policyId,
                    "1.0.0",
                    "Action Policy (" + actionKey + ") for " + spec.resourceKey(),
                    description,
                    Set.of(isBulk ? "BULK_WORKFLOW_ACTION" : "WORKFLOW_ACTION"),
                    legalPurpose,
                    legalBasisRef,
                    OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                    List.of(PolicyTargetSpec.exact(
                            "tgt-" + sanitizedResource + "-act-" + sanitizedAction,
                            actionDp.identity().pointKey(),
                            actionDp.descriptorDigest(),
                            evalModes
                    )),
                    spec.dualScopeDelegationSpec(),
                    List.of(),
                    List.copyOf(rules),
                    List.of(new PolicyMaterializationTargetSpec(
                            "policy_engine",
                            "opa-policy",
                            unitKey,
                            OpaProviderIoSchemas.COMPILER_PROFILE_V1
                    ))
            ));
        }
    }

    private void synthesizeAnnotatedSurfacePolicies(
            AuthzResourceGovernanceSpec<?> spec,
            List<MetadataDtoGovernanceIntrospector.DeclaredMaskSpec> allMasks
    ) {
        if (spec.surfaceDecisionPoints().isEmpty()) {
            return;
        }
        String sanitizedResource = spec.resourceKey().replace('.', '-');
        for (Map.Entry<String, DecisionPointDescriptor> entry : spec.surfaceDecisionPoints().entrySet()) {
            String surfaceKey = entry.getKey();
            DecisionPointDescriptor surfaceDp = entry.getValue();
            AuthzResourceGovernanceSpec.ActionRuleSpec ruleSpec = spec.surfaceRuleSpecs().get(surfaceKey);
            String sanitizedSurface = surfaceKey.replace('.', '-');

            String policyId = (ruleSpec != null && !ruleSpec.policyId().isBlank())
                    ? ruleSpec.policyId()
                    : "pol-" + serviceKey + "-" + sanitizedResource + "-srf-" + sanitizedSurface;
            String ruleId = (ruleSpec != null && !ruleSpec.ruleId().isBlank())
                    ? ruleSpec.ruleId()
                    : "rule-" + sanitizedResource + "-srf-" + sanitizedSurface;
            String unitKey = "unit:" + policyId + ":v1";

            List<MaskContributionSpec> surfaceMasks = allMasks.stream()
                    .filter(m -> m.modes().contains(EvaluationMode.TARGET)
                            && (m.surfaces().isEmpty() || m.surfaces().contains(surfaceKey)))
                    .map(MetadataDtoGovernanceIntrospector.DeclaredMaskSpec::contribution)
                    .toList();

            Set<EvaluationMode> evalModes = surfaceDp.evaluationModes().isEmpty()
                    ? Set.of(EvaluationMode.TARGET)
                    : surfaceDp.evaluationModes();
            Map<String, Object> targetCond = buildAnnotatedRuleCondition(spec, ruleSpec, true);
            String reasonCode = (ruleSpec != null && !ruleSpec.reasonCode().isBlank())
                    ? ruleSpec.reasonCode()
                    : ("ALLOW_SURFACE_" + surfaceKey.toUpperCase().replace('-', '_').replace('.', '_'));
            boolean auditRequired = ruleSpec == null || ruleSpec.auditRequired();
            String auditCategory = (ruleSpec != null && !ruleSpec.auditCategory().isBlank())
                    ? ruleSpec.auditCategory()
                    : "GOVERNED_SURFACE_ACCESS";
            List<ObligationDirective> obligations = auditRequired
                    ? List.of(new ObligationDirective(
                            "DURABLE_AUDIT_EVIDENCE",
                            "ON_PERMIT",
                            "BEFORE_COMMIT_OUTBOX",
                            Map.of("auditCategory", auditCategory, "surfaceKey", surfaceKey)
                    ))
                    : List.of();

            AuthorizationPolicyRule rule = new AuthorizationPolicyRule(
                    ruleId,
                    "Grants surface '" + surfaceKey + "' access and masking for " + spec.resourceKey(),
                    evalModes,
                    new AuthorizationSourceCondition(
                            AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                            ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                            targetCond
                    ),
                    new AuthorizationRuleContributions(
                            new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                            null,
                            List.of(),
                            List.of(),
                            surfaceMasks,
                            reasonCode
                    ),
                    obligations
            );

            String legalPurpose = (ruleSpec != null && !ruleSpec.legalPurpose().isBlank())
                    ? ruleSpec.legalPurpose()
                    : (surfaceDp.legalPurpose() != null ? surfaceDp.legalPurpose() : "STATUTORY_LEGAL_OBLIGATION");
            String legalBasisRef = (ruleSpec != null && !ruleSpec.legalBasisRef().isBlank())
                    ? ruleSpec.legalBasisRef()
                    : (surfaceDp.legalBasisRef() != null ? surfaceDp.legalBasisRef() : "LGPD:ART_7_III");
            String description = (ruleSpec != null && !ruleSpec.description().isBlank())
                    ? ruleSpec.description()
                    : "Declarative UI surface authorization and masking policy for '" + surfaceKey + "'";

            addPolicy(new AuthorizationPolicyDefinition(
                    AuthorizationPolicyDefinition.SCHEMA_VERSION_V1,
                    policyId,
                    "1.0.0",
                    "Surface Policy (" + surfaceKey + ") for " + spec.resourceKey(),
                    description,
                    Set.of("UI_SURFACE"),
                    legalPurpose,
                    legalBasisRef,
                    OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                    List.of(PolicyTargetSpec.exact(
                            "tgt-" + sanitizedResource + "-srf-" + sanitizedSurface,
                            surfaceDp.identity().pointKey(),
                            surfaceDp.descriptorDigest(),
                            evalModes
                    )),
                    spec.dualScopeDelegationSpec(),
                    List.of(),
                    List.of(rule),
                    List.of(new PolicyMaterializationTargetSpec(
                            "policy_engine",
                            "opa-policy",
                            unitKey,
                            OpaProviderIoSchemas.COMPILER_PROFILE_V1
                    ))
            ));
        }
    }

    private static Map<String, Object> buildSubjectScopeAdmissionCondition(AuthzResourceGovernanceSpec<?> spec) {
        Map<String, Object> principalPresent = Map.of("is_not_null", Map.of("var", "subject.principalId"));
        if (spec.dualScopeDelegationSpec() != null
                || spec.tenantScopeMode()
                        == org.praxisplatform.authz.contracts.annotation.AuthzTenantScopeMode.AUTHENTICATED_SHARED) {
            return principalPresent;
        }
        String subjectFactPath = resolveEffectiveSubjectScopeFactPath(spec);
        return Map.of(
                "and",
                List.of(principalPresent, Map.of("is_not_null", Map.of("var", subjectFactPath)))
        );
    }

    private static Map<String, Object> buildResourceScopePredicate(AuthzResourceGovernanceSpec<?> spec) {
        if (spec.dualScopeDelegationSpec() != null) {
            var dual = spec.dualScopeDelegationSpec();
            String originResourceFact = dual.originFactPath();
            String originSubjectFact = spec.originSubjectFactKey() != null
                    ? spec.originSubjectFactKey()
                    : "subject.organizationUnitIds";
            Map<String, Object> originPred = Map.of(
                    "in",
                    List.of(Map.of("var", originResourceFact), Map.of("var", originSubjectFact))
            );
            String destResourceFact = dual.destinationFactPath();
            if (destResourceFact != null && !destResourceFact.isBlank()) {
                String destSubjectFact = spec.destinationSubjectFactKey() != null
                        ? spec.destinationSubjectFactKey()
                        : "subject.organizationUnitIds";
                Map<String, Object> destPred = Map.of(
                        "in",
                        List.of(Map.of("var", destResourceFact), Map.of("var", destSubjectFact))
                );
                return Map.of("or", List.of(originPred, destPred));
            }
            return originPred;
        }
        AuthzResourceGovernanceSpec.TenantScopeSpec tenantSpec = spec.tenantScopeSpec();
        String resourceFactPath = (tenantSpec != null && !tenantSpec.resourceFactPath().isBlank())
                ? tenantSpec.resourceFactPath()
                : "resource." + spec.tenantFieldName();
        String subjectFactPath = resolveEffectiveSubjectScopeFactPath(spec);
        boolean collectionSubjectFact = isCollectionScopeFact(subjectFactPath, spec.tenantScopeMode());
        Map<String, Object> comparison = collectionSubjectFact
                ? Map.of("in", List.of(Map.of("var", resourceFactPath), Map.of("var", subjectFactPath)))
                : Map.of("==", List.of(Map.of("var", resourceFactPath), Map.of("var", subjectFactPath)));
        if (spec.allowGlobalNullScope()) {
            return Map.of("or", List.of(comparison, Map.of("is_null", Map.of("var", resourceFactPath))));
        }
        return comparison;
    }

    private static String resolveEffectiveSubjectScopeFactPath(AuthzResourceGovernanceSpec<?> spec) {
        if (spec.tenantScopeSpec() != null && !spec.tenantScopeSpec().subjectFactPath().isBlank()) {
            return spec.tenantScopeSpec().subjectFactPath();
        }
        if (spec.hardScopeSubjectFactKey() != null && !spec.hardScopeSubjectFactKey().isBlank()) {
            return spec.hardScopeSubjectFactKey();
        }
        return spec.tenantScopeMode()
                == org.praxisplatform.authz.contracts.annotation.AuthzTenantScopeMode.TENANT_ONLY
                ? "subject.tenantId"
                : "subject.organizationUnitIds";
    }

    private static boolean isCollectionScopeFact(
            String subjectFactPath,
            org.praxisplatform.authz.contracts.annotation.AuthzTenantScopeMode mode
    ) {
        if (AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS.equals(subjectFactPath)
                || AuthzCallerContext.FACT_ORGANIZATION_UNIT_IDS.equals(subjectFactPath)
                || subjectFactPath.endsWith("Ids")
                || subjectFactPath.endsWith("ids")) {
            return true;
        }
        return mode == org.praxisplatform.authz.contracts.annotation.AuthzTenantScopeMode.ORGANIZATIONAL_UNIT
                && !"subject.tenantId".equals(subjectFactPath);
    }

    private static Map<String, Object> buildAnnotatedRuleCondition(
            AuthzResourceGovernanceSpec<?> spec,
            AuthzResourceGovernanceSpec.ActionRuleSpec ruleSpec,
            boolean includeResourceScope
    ) {
        List<Map<String, Object>> baseTerms = new ArrayList<>();
        if (ruleSpec == null || ruleSpec.requireAuthenticatedPrincipal()) {
            baseTerms.add(Map.of("is_not_null", Map.of("var", "subject.principalId")));
        }
        Map<String, Object> scopeCondition = includeResourceScope && spec.tenantScopeMode()
                != org.praxisplatform.authz.contracts.annotation.AuthzTenantScopeMode.AUTHENTICATED_SHARED
                ? combineAndConditions(List.of(buildSubjectScopeAdmissionCondition(spec), buildResourceScopePredicate(spec)))
                : buildSubjectScopeAdmissionCondition(spec);
        baseTerms.add(scopeCondition);

        if (ruleSpec != null && !ruleSpec.conditionFactPath().isBlank()) {
            if (!ruleSpec.conditionAllowedValues().isEmpty()) {
                baseTerms.add(Map.of(
                        "in",
                        List.of(Map.of("var", ruleSpec.conditionFactPath()), ruleSpec.conditionAllowedValues())
                ));
            } else {
                baseTerms.add(Map.of("is_not_null", Map.of("var", ruleSpec.conditionFactPath())));
            }
        }
        if (ruleSpec != null && !ruleSpec.conditionJsonLogic().isBlank()) {
            baseTerms.add(parseJsonLogicObject(ruleSpec.conditionJsonLogic()));
        }
        if (ruleSpec != null && !ruleSpec.requiredRoles().isEmpty()) {
            List<Map<String, Object>> roleBranches = new ArrayList<>(ruleSpec.requiredRoles().size());
            for (String role : ruleSpec.requiredRoles()) {
                roleBranches.add(Map.of("in", List.of(role, Map.of("var", "subject.roles"))));
            }
            if (roleBranches.size() == 1) {
                baseTerms.add(roleBranches.get(0));
            } else {
                baseTerms.add(Map.of("or", roleBranches));
            }
        }
        return combineAndConditions(baseTerms);
    }

    /**
     * Combines multiple JSON-Logic conditions under logical AND while distributing any top-level
     * {@code "or"} to the outermost node so {@code RegoV1PolicyCompiler} emits complete Rego rules.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> combineAndConditions(List<Map<String, Object>> terms) {
        List<List<Map<String, Object>>> dnfBranches = new ArrayList<>();
        dnfBranches.add(new ArrayList<>());
        for (Map<String, Object> term : terms) {
            if (term == null || term.isEmpty()) {
                continue;
            }
            List<Map<String, Object>> termDisjuncts = extractTopLevelDisjuncts(term);
            List<List<Map<String, Object>>> nextBranches = new ArrayList<>();
            for (List<Map<String, Object>> existing : dnfBranches) {
                for (Map<String, Object> disjunct : termDisjuncts) {
                    List<Map<String, Object>> combined = new ArrayList<>(existing);
                    flattenAndTerms(disjunct, combined);
                    nextBranches.add(combined);
                }
            }
            dnfBranches = nextBranches;
        }
        if (dnfBranches.size() == 1) {
            return andOfTerms(dnfBranches.get(0));
        }
        List<Map<String, Object>> orBranches = new ArrayList<>(dnfBranches.size());
        for (List<Map<String, Object>> branchTerms : dnfBranches) {
            orBranches.add(andOfTerms(branchTerms));
        }
        return Map.of("or", List.copyOf(orBranches));
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> extractTopLevelDisjuncts(Map<String, Object> expr) {
        if (expr.size() == 1 && expr.containsKey("or") && expr.get("or") instanceof List<?> rawList) {
            List<Map<String, Object>> disjuncts = new ArrayList<>();
            for (Object item : rawList) {
                if (item instanceof Map<?, ?> map) {
                    disjuncts.addAll(extractTopLevelDisjuncts((Map<String, Object>) map));
                }
            }
            if (!disjuncts.isEmpty()) {
                return disjuncts;
            }
        }
        if (expr.size() == 1 && expr.containsKey("and") && expr.get("and") instanceof List<?> rawAnd) {
            List<Map<String, Object>> nestedTerms = new ArrayList<>();
            boolean hasNestedOr = false;
            for (Object item : rawAnd) {
                if (item instanceof Map<?, ?> map) {
                    Map<String, Object> sub = (Map<String, Object>) map;
                    if (sub.containsKey("or")) {
                        hasNestedOr = true;
                    }
                    nestedTerms.add(sub);
                }
            }
            if (hasNestedOr) {
                Map<String, Object> distributed = combineAndConditions(nestedTerms);
                if (distributed.containsKey("or") && distributed.get("or") instanceof List<?> distList) {
                    List<Map<String, Object>> out = new ArrayList<>();
                    for (Object item : distList) {
                        if (item instanceof Map<?, ?> map) {
                            out.add((Map<String, Object>) map);
                        }
                    }
                    if (!out.isEmpty()) {
                        return out;
                    }
                }
            }
        }
        return List.of(expr);
    }

    @SuppressWarnings("unchecked")
    private static void flattenAndTerms(Map<String, Object> term, List<Map<String, Object>> sink) {
        if (term.size() == 1 && term.containsKey("and") && term.get("and") instanceof List<?> rawList) {
            for (Object item : rawList) {
                if (item instanceof Map<?, ?> map) {
                    flattenAndTerms((Map<String, Object>) map, sink);
                }
            }
            return;
        }
        if (!sink.contains(term)) {
            sink.add(term);
        }
    }

    private static Map<String, Object> andOfTerms(List<Map<String, Object>> terms) {
        if (terms.isEmpty()) {
            return Map.of("is_not_null", Map.of("var", "subject.principalId"));
        }
        if (terms.size() == 1) {
            return terms.get(0);
        }
        return Map.of("and", List.copyOf(terms));
    }

    private static Map<String, Object> parseJsonLogicObject(String json) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().readValue(
                    json,
                    new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {}
            );
        } catch (Exception ex) {
            throw new IllegalArgumentException(
                    "Invalid conditionJsonLogic in @AuthzActionRule: " + ex.getMessage(),
                    ex
            );
        }
    }

    /**
     * Synthesizes and registers a standard organizational-scope + field-masking + durable-audit
     * {@link AuthorizationPolicyDefinition} targeting the given {@code spec}'s primary decision point.
     *
     * @param spec target governed resource specification
     * @param ruleId unique rule identifier
     * @param resourceScopeFactPath resource fact path (e.g. {@code "resource.lotacaoSetorId"})
     * @param subjectScopeSetFactPath subject collection fact path (e.g. {@code "subject.organizationUnitIds"})
     * @param redactConstantMasksByAttributeId map of restricted {@code attributeId} to constant mask replacement
     * @return this builder
     */
    public AuthzHostPolicyBootstrapBuilder addOrganizationalScopePolicy(
            AuthzResourceGovernanceSpec<?> spec,
            String ruleId,
            String resourceScopeFactPath,
            String subjectScopeSetFactPath,
            Map<String, String> redactConstantMasksByAttributeId
    ) {
        return addOrganizationalScopePolicy(
                spec,
                ruleId,
                resourceScopeFactPath,
                subjectScopeSetFactPath,
                toRedactConstantMasks(redactConstantMasksByAttributeId),
                List.of()
        );
    }

    /**
     * Synthesizes and registers a standard organizational-scope + field-masking + durable-audit
     * {@link AuthorizationPolicyDefinition} using explicit {@link MaskContributionSpec} directives.
     */
    public AuthzHostPolicyBootstrapBuilder addOrganizationalScopePolicy(
            AuthzResourceGovernanceSpec<?> spec,
            String ruleId,
            String resourceScopeFactPath,
            String subjectScopeSetFactPath,
            List<MaskContributionSpec> maskDirectives
    ) {
        return addOrganizationalScopePolicy(
                spec,
                ruleId,
                resourceScopeFactPath,
                subjectScopeSetFactPath,
                maskDirectives,
                List.of()
        );
    }

    /**
     * Synthesizes and registers a standard organizational-scope + field-masking + durable-audit
     * {@link AuthorizationPolicyDefinition} with optional additional {@link AuthorizationPolicyRule}s.
     */
    public AuthzHostPolicyBootstrapBuilder addOrganizationalScopePolicy(
            AuthzResourceGovernanceSpec<?> spec,
            String ruleId,
            String resourceScopeFactPath,
            String subjectScopeSetFactPath,
            List<MaskContributionSpec> maskDirectives,
            List<AuthorizationPolicyRule> additionalRules
    ) {
        Objects.requireNonNull(spec, "spec is required");
        Objects.requireNonNull(ruleId, "ruleId is required");
        Objects.requireNonNull(resourceScopeFactPath, "resourceScopeFactPath is required");
        Objects.requireNonNull(subjectScopeSetFactPath, "subjectScopeSetFactPath is required");

        List<MaskContributionSpec> masks = maskDirectives == null ? List.of() : List.copyOf(maskDirectives);
        Map<String, Object> principalCondition = Map.of("!=", List.of(Map.of("var", "subject.principalId"), ""));
        Map<String, Object> baseComparison = Map.of(
                "in",
                List.of(
                        Map.of("var", resourceScopeFactPath),
                        Map.of("var", subjectScopeSetFactPath)
                )
        );
        Map<String, Object> scopeInCondition = spec.allowGlobalNullScope()
                ? Map.of("or", List.of(baseComparison, Map.of("is_null", Map.of("var", resourceScopeFactPath))))
                : baseComparison;
        List<ObligationDirective> auditObligations = durableResourceAccessAuditObligations();

        AuthorizationPolicyRule searchRule = new AuthorizationPolicyRule(
                ruleId,
                "Grants collection SEARCH organizational scope and masks restricted attributes for " + spec.resourceKey(),
                Set.of(EvaluationMode.SEARCH),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        principalCondition
                ),
                new AuthorizationRuleContributions(
                        new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                        new DataScopeContributionSpec(
                                ContributionAuthority.GRANT,
                                new AuthorizationSourceCondition(
                                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                        ConditionProfileKind.AUTHORIZATION_SEARCH_SOURCE_V1,
                                        scopeInCondition
                                )
                        ),
                        List.of(),
                        List.of(),
                        masks,
                        "ALLOW_ORGANIZATIONAL_SCOPE"
                ),
                auditObligations
        );

        AuthorizationPolicyRule targetRule = new AuthorizationPolicyRule(
                ruleId + "-target",
                "Grants item TARGET organizational scope and masks restricted attributes for " + spec.resourceKey(),
                Set.of(EvaluationMode.TARGET),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        combineAndConditions(List.of(principalCondition, scopeInCondition))
                ),
                new AuthorizationRuleContributions(
                        new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                        null,
                        List.of(),
                        List.of(),
                        masks,
                        "ALLOW_ORGANIZATIONAL_SCOPE"
                ),
                auditObligations
        );

        return addPolicy(buildPrimaryScopePolicyDefinition(
                spec,
                "Organizational Scope Policy for " + spec.resourceKey(),
                "Declarative organizational scope and field masking policy",
                Set.of("ORGANIZATIONAL_SCOPE"),
                combinePolicyRules(List.of(searchRule, targetRule), additionalRules)
        ));
    }

    /**
     * Synthesizes and registers an {@code AUTHENTICATED_SHARED} primary policy for shared catalog
     * resources accessible across tenants to any authenticated principal.
     */
    public AuthzHostPolicyBootstrapBuilder addAuthenticatedSharedPolicy(
            AuthzResourceGovernanceSpec<?> spec,
            String ruleId,
            Map<String, String> redactConstantMasksByAttributeId
    ) {
        return addAuthenticatedSharedPolicy(
                spec,
                ruleId,
                toRedactConstantMasks(redactConstantMasksByAttributeId),
                List.of()
        );
    }

    /**
     * Synthesizes and registers an {@code AUTHENTICATED_SHARED} primary policy with explicit
     * {@link MaskContributionSpec} directives.
     */
    public AuthzHostPolicyBootstrapBuilder addAuthenticatedSharedPolicy(
            AuthzResourceGovernanceSpec<?> spec,
            String ruleId,
            List<MaskContributionSpec> maskDirectives
    ) {
        return addAuthenticatedSharedPolicy(spec, ruleId, maskDirectives, List.of());
    }

    /**
     * Synthesizes and registers an {@code AUTHENTICATED_SHARED} primary policy with explicit
     * {@link MaskContributionSpec} directives and optional additional {@link AuthorizationPolicyRule}s.
     */
    public AuthzHostPolicyBootstrapBuilder addAuthenticatedSharedPolicy(
            AuthzResourceGovernanceSpec<?> spec,
            String ruleId,
            List<MaskContributionSpec> maskDirectives,
            List<AuthorizationPolicyRule> additionalRules
    ) {
        Objects.requireNonNull(spec, "spec is required");
        Objects.requireNonNull(ruleId, "ruleId is required");
        List<MaskContributionSpec> masks = maskDirectives == null ? List.of() : List.copyOf(maskDirectives);
        List<FieldUseContributionSpec> searchFieldUse =
                masks.isEmpty() ? defaultSearchFieldUse(spec) : List.of();
        Map<String, Object> principalCondition = Map.of("!=", List.of(Map.of("var", "subject.principalId"), ""));
        List<ObligationDirective> auditObligations = durableResourceAccessAuditObligations();

        AuthorizationPolicyRule searchRule = new AuthorizationPolicyRule(
                ruleId + "-shared-search",
                "Authenticated shared SEARCH access for " + spec.resourceKey(),
                Set.of(EvaluationMode.SEARCH),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        principalCondition
                ),
                new AuthorizationRuleContributions(
                        new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                        null,
                        searchFieldUse,
                        List.of(),
                        masks,
                        "ALLOW_AUTHENTICATED_SHARED_SEARCH"
                ),
                auditObligations
        );

        AuthorizationPolicyRule targetRule = new AuthorizationPolicyRule(
                ruleId + "-shared-target",
                "Authenticated shared TARGET access for " + spec.resourceKey(),
                Set.of(EvaluationMode.TARGET),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        principalCondition
                ),
                new AuthorizationRuleContributions(
                        new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                        null,
                        List.of(),
                        List.of(),
                        masks,
                        "ALLOW_AUTHENTICATED_SHARED_TARGET"
                ),
                auditObligations
        );

        return addPolicy(buildPrimaryScopePolicyDefinition(
                spec,
                "Authenticated Shared Policy for " + spec.resourceKey(),
                "Declarative authenticated-shared admission and field masking policy",
                Set.of("AUTHENTICATED_SHARED"),
                combinePolicyRules(List.of(searchRule, targetRule), additionalRules)
        ));
    }

    private static List<FieldUseContributionSpec> defaultSearchFieldUse(
            AuthzResourceGovernanceSpec<?> spec
    ) {
        if (spec.factContract() != null && spec.factContract().descriptorsByPath() != null) {
            for (FactDescriptor descriptor : spec.factContract().descriptorsByPath().values()) {
                if (descriptor != null
                        && descriptor.factPath().startsWith("resource.")
                        && descriptor.attributeId() != null
                        && !descriptor.attributeId().isBlank()
                        && !"RESTRICTED".equalsIgnoreCase(descriptor.classification())
                        && !"SECRET".equalsIgnoreCase(descriptor.dataCategory())
                        && !"CREDENTIAL".equalsIgnoreCase(descriptor.dataCategory())) {
                    return List.of(new FieldUseContributionSpec(
                            PolicyFieldSelector.exact(Set.of(descriptor.attributeId())),
                            Set.of(FieldUseCategory.VALUE),
                            RuleEffect.ALLOW
                    ));
                }
            }
            for (FactDescriptor descriptor : spec.factContract().descriptorsByPath().values()) {
                if (descriptor != null
                        && descriptor.factPath().startsWith("resource.")
                        && descriptor.attributeId() != null
                        && !descriptor.attributeId().isBlank()) {
                    return List.of(new FieldUseContributionSpec(
                            PolicyFieldSelector.exact(Set.of(descriptor.attributeId())),
                            Set.of(FieldUseCategory.VALUE),
                            RuleEffect.ALLOW
                    ));
                }
            }
        }
        if (spec.queryProjection() != null && spec.queryProjection().fieldsByPath() != null) {
            for (QueryableFieldDescriptor descriptor : spec.queryProjection().fieldsByPath().values()) {
                if (descriptor != null
                        && descriptor.attributeId() != null
                        && !descriptor.attributeId().isBlank()) {
                    return List.of(new FieldUseContributionSpec(
                            PolicyFieldSelector.exact(Set.of(descriptor.attributeId())),
                            Set.of(FieldUseCategory.VALUE),
                            RuleEffect.ALLOW
                    ));
                }
            }
        }
        throw new IllegalStateException(
                "Unable to locate canonical resource attributeId for SEARCH fieldUse contribution on "
                        + spec.resourceKey()
        );
    }

    private static String resolvePrimaryQueryableFieldPath(AuthzResourceGovernanceSpec<?> spec) {
        AuthzResourceGovernanceSpec.TenantScopeSpec tenantSpec = spec.tenantScopeSpec();
        if (tenantSpec != null
                && tenantSpec.sharedBulkNonNullFactPath() != null
                && !tenantSpec.sharedBulkNonNullFactPath().isBlank()) {
            return tenantSpec.sharedBulkNonNullFactPath().trim();
        }
        if (spec.queryProjection() != null && spec.queryProjection().fieldsByPath() != null
                && !spec.queryProjection().fieldsByPath().isEmpty()) {
            Map<String, QueryableFieldDescriptor> fieldsByPath = spec.queryProjection().fieldsByPath();
            for (QueryableFieldDescriptor qfd : fieldsByPath.values()) {
                if (qfd != null && qfd.supportedOperators() != null
                        && qfd.supportedOperators().contains(SearchPredicateOperator.IS_NOT_NULL)) {
                    return qfd.fieldPath();
                }
            }
            return fieldsByPath.keySet().iterator().next();
        }
        throw new IllegalStateException(
                "Unable to locate primary queryable field path for AUTHENTICATED_SHARED dataScope on "
                        + spec.resourceKey()
        );
    }

    private static List<ObligationDirective> durableResourceAccessAuditObligations() {
        return List.of(new ObligationDirective(
                "DURABLE_AUDIT_EVIDENCE",
                "ON_PERMIT",
                "BEFORE_COMMIT_OUTBOX",
                Map.of("auditCategory", "GOVERNED_RESOURCE_ACCESS")
        ));
    }

    private static List<AuthorizationPolicyRule> combinePolicyRules(
            List<AuthorizationPolicyRule> baseRules,
            List<AuthorizationPolicyRule> additionalRules
    ) {
        if (additionalRules == null || additionalRules.isEmpty()) {
            return List.copyOf(baseRules);
        }
        List<AuthorizationPolicyRule> merged = new ArrayList<>(baseRules.size() + additionalRules.size());
        merged.addAll(baseRules);
        additionalRules.stream().filter(Objects::nonNull).forEach(merged::add);
        return List.copyOf(merged);
    }

    private AuthorizationPolicyDefinition buildPrimaryScopePolicyDefinition(
            AuthzResourceGovernanceSpec<?> spec,
            String title,
            String description,
            Set<String> categories,
            List<AuthorizationPolicyRule> rules
    ) {
        DecisionPointDescriptor dp = spec.decisionPoint();
        String policyId = "pol-" + serviceKey + "-" + spec.resourceKey().replace('.', '-');
        String unitKey = "unit:" + policyId + ":v1";
        Set<EvaluationMode> dpModes = dp.evaluationModes().isEmpty()
                ? Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET)
                : dp.evaluationModes();
        return new AuthorizationPolicyDefinition(
                AuthorizationPolicyDefinition.SCHEMA_VERSION_V1,
                policyId,
                "1.0.0",
                title,
                description,
                categories,
                dp.legalPurpose() != null ? dp.legalPurpose() : "STATUTORY_LEGAL_OBLIGATION",
                dp.legalBasisRef() != null ? dp.legalBasisRef() : "LGPD:ART_7_III",
                OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                List.of(PolicyTargetSpec.exact(
                        "tgt-" + spec.resourceKey().replace('.', '-'),
                        dp.identity().pointKey(),
                        dp.descriptorDigest(),
                        dpModes
                )),
                spec.dualScopeDelegationSpec(),
                List.of(),
                rules,
                List.of(new PolicyMaterializationTargetSpec(
                        "policy_engine",
                        "opa-policy",
                        unitKey,
                        OpaProviderIoSchemas.COMPILER_PROFILE_V1
                ))
        );
    }

    /**
     * Compiles all registered policies and resource specifications into a ready-to-wire
     * {@link AuthzHostPolicyBootstrapBundle} using a default {@link MetadataDtoGovernanceIntrospector}.
     */
    public AuthzHostPolicyBootstrapBundle build() {
        return build(new MetadataDtoGovernanceIntrospector());
    }

    /**
     * Compiles all registered policies and resource specifications into a ready-to-wire
     * {@link AuthzHostPolicyBootstrapBundle}.
     */
    public AuthzHostPolicyBootstrapBundle build(MetadataDtoGovernanceIntrospector dtoIntrospector) {
        Objects.requireNonNull(dtoIntrospector, "dtoIntrospector is required");
        if (resources.isEmpty()) {
            throw new IllegalStateException("At least one AuthzResourceGovernanceSpec must be registered via addResourceSpec(...)");
        }
        if (policies.isEmpty()) {
            throw new IllegalStateException("At least one AuthorizationPolicyDefinition must be registered via addPolicy(...) or addOrganizationalScopePolicy(...)");
        }

        Map<String, DecisionPointDescriptor> pointsByKey = new LinkedHashMap<>();
        Map<String, FactContract> factContractsById = new LinkedHashMap<>();
        Map<String, QueryableResourceProjection> queryProjectionsById = new LinkedHashMap<>();

        for (RegisteredResourceEntry entry : resources) {
            AuthzResourceGovernanceSpec<?> spec = entry.spec();
            DecisionPointDescriptor dp = spec.decisionPoint();
            pointsByKey.put(dp.identity().pointKey(), dp);
            for (DecisionPointDescriptor actionDp : spec.actionDecisionPoints().values()) {
                pointsByKey.put(actionDp.identity().pointKey(), actionDp);
            }
            for (DecisionPointDescriptor surfaceDp : spec.surfaceDecisionPoints().values()) {
                pointsByKey.put(surfaceDp.identity().pointKey(), surfaceDp);
            }
            factContractsById.put(entry.factContract().factContractId(), entry.factContract());
            QueryableResourceProjection qp = spec.queryProjection();
            if (qp != null) {
                queryProjectionsById.put(qp.projectionId(), qp);
            }
        }

        RegoV1PolicyCompiler compiler = new RegoV1PolicyCompiler();
        List<CompiledRegoUnit> compiledUnits = new ArrayList<>();
        Set<String> unitKeys = new LinkedHashSet<>();
        Set<String> requiredMaskStrategyIds = new LinkedHashSet<>();
        Set<String> requiredObligationTypes = new LinkedHashSet<>();
        for (AuthorizationPolicyDefinition policy : policies) {
            CompiledRegoUnit unit = compiler.compileUnit(
                    policy,
                    pointsByKey,
                    factContractsById,
                    queryProjectionsById
            );
            compiledUnits.add(unit);
            for (PolicyMaterializationTargetSpec target : policy.materializationTargets()) {
                unitKeys.add(target.targetArtifactKey());
            }
            for (AuthorizationPolicyRule rule : policy.rules()) {
                if (rule.contributions() != null && rule.contributions().mask() != null) {
                    for (MaskContributionSpec mask : rule.contributions().mask()) {
                        if (mask != null && mask.strategyId() != null) {
                            requiredMaskStrategyIds.add(mask.strategyId());
                        }
                    }
                }
                if (rule.obligations() != null) {
                    for (ObligationDirective obligation : rule.obligations()) {
                        if (obligation != null && obligation.obligationType() != null) {
                            requiredObligationTypes.add(obligation.obligationType());
                        }
                    }
                }
            }
        }

        String capDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST,
                "opa-cap-v1"
        );
        OpaBundleAssembler assembler = new OpaBundleAssembler(compiler);
        OpaBundleArtifact bundleArtifact = assembler.assembleBundle(
                "rel-" + serviceKey + "-1",
                runtimeRevision,
                1L,
                "prod-cluster",
                "opa-node-1",
                capDigest,
                compiledUnits
        );

        DeterministicLocalOpaTransport localTransport = new DeterministicLocalOpaTransport(
                bundleArtifact,
                List.copyOf(queryProjectionsById.values())
        );

        Map<String, RuntimeEnforcementBinding> bindingsByPointKey = new LinkedHashMap<>();
        List<DecisionPointCompatibilityEntry> compatEntries = new ArrayList<>();
        List<MethodBindingAdmissionRecord> admissionRecords = new ArrayList<>();

        for (RegisteredResourceEntry entry : resources) {
            AuthzResourceGovernanceSpec<?> spec = entry.spec();
            FactContract fc = entry.factContract();
            QueryableResourceProjection qp = spec.queryProjection();
            List<FieldLineageCatalogEntry> lineageEntries = dtoIntrospector.deriveFieldLineageCatalogEntries(
                    spec.resourceKey(),
                    entry.responseDtoClass(),
                    entry.createDtoClass(),
                    entry.updateDtoClass()
            );

            List<DecisionPointDescriptor> resourceDecisionPoints = new ArrayList<>();
            resourceDecisionPoints.add(spec.decisionPoint());
            resourceDecisionPoints.addAll(spec.actionDecisionPoints().values());
            resourceDecisionPoints.addAll(spec.surfaceDecisionPoints().values());

            for (DecisionPointDescriptor dp : resourceDecisionPoints) {
                String pointKey = dp.identity().pointKey();
                if (bindingsByPointKey.containsKey(pointKey)) {
                    continue;
                }
                String bindingDigest = CanonicalDigestCalculator.computeDigest(
                        DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST,
                        serviceKey + "|" + pointKey + "|binding|v1"
                );
                EvaluationMode primaryMode = dp.evaluationModes().contains(EvaluationMode.SEARCH)
                        ? EvaluationMode.SEARCH
                        : EvaluationMode.TARGET;
                EnforcementCapability primaryCap = dp.supportedCapabilities().contains(EnforcementCapability.DATA_SCOPE)
                        ? EnforcementCapability.DATA_SCOPE
                        : EnforcementCapability.ACCESS;
                Set<FieldUseCategory> bindingFieldUseCategories = dp.supportedCapabilities().contains(EnforcementCapability.FIELD_USE)
                        ? Set.of(FieldUseCategory.VALUE, FieldUseCategory.FILTER)
                        : Set.of();

                RuntimeEnforcementBinding binding = new RuntimeEnforcementBinding(
                        RuntimeEnforcementBinding.SCHEMA_VERSION_V1,
                        "bnd-" + spec.resourceKey().replace('.', '-') + "-" + dp.identity().operationOrActionKey(),
                        new DecisionPointRef(
                                pointKey,
                                dp.identity().pointKind(),
                                dp.identity().serviceKey(),
                                dp.identity().resourceKey(),
                                dp.identity().operationOrActionKey(),
                                dp.descriptorDigest()
                        ),
                        primaryMode,
                        primaryCap,
                        bindingFieldUseCategories,
                        primaryMode == EvaluationMode.SEARCH
                                ? HostEnforcementPhase.REQUEST_QUERY
                                : HostEnforcementPhase.PRE_MUTATION,
                        "OPA_REGO_V1",
                        PointAuthorityMode.AUTHORITATIVE,
                        "praxis.enforcement-profile.spring-jpa/v1",
                        primaryMode == EvaluationMode.SEARCH ? "DefaultSearchHandler/v1" : "DefaultTargetHandler/v1",
                        "praxis.authz-host-contract/v1",
                        BatchAuthorizationMode.REJECT_ALL,
                        TransactionCardinality.STATEMENT_ATOMIC,
                        bindingDigest,
                        new ReadinessEvidenceOverlay(
                                ReadinessEvidenceOverlay.ALL_STAGES,
                                bundleArtifact.runtimeRelease().runtimeRevision(),
                                bundleArtifact.runtimeRelease().policySetDigest(),
                                Instant.now()
                        )
                );
                bindingsByPointKey.put(pointKey, binding);

                boolean hasQueryProjection = dp.queryProjectionRef() != null && qp != null;
                compatEntries.add(new DecisionPointCompatibilityEntry(
                        pointKey,
                        dp.descriptorDigest(),
                        fc.factContractId(),
                        fc.factContractDigest(),
                        hasQueryProjection ? qp.projectionId() : null,
                        hasQueryProjection ? qp.projectionDigest() : null,
                        bindingDigest,
                        RolloutActivationStrategy.POLICY_FIRST,
                        true
                ));

                admissionRecords.add(new MethodBindingAdmissionRecord(
                        serviceKey,
                        dp,
                        binding,
                        Set.of(
                                AdmittedInvocationChannel.REST_ENDPOINT,
                                AdmittedInvocationChannel.PROXIED_INTERNAL_SERVICE
                        ),
                        true,
                        lineageEntries
                ));
            }
        }

        Set<String> hostRegisteredMaskStrategies = new LinkedHashSet<>(
                List.of("REDACT_CONSTANT", "PARTIAL_MASK", "HASH_TOKEN_KEYED")
        );
        hostRegisteredMaskStrategies.addAll(requiredMaskStrategyIds);

        Set<String> hostRegisteredObligationTypes = new LinkedHashSet<>(
                List.of("DURABLE_AUDIT_EVIDENCE")
        );
        hostRegisteredObligationTypes.addAll(requiredObligationTypes);

        HostPolicyCompatibilityManifest hostManifest = new HostPolicyCompatibilityManifest(
                HostPolicyCompatibilityManifest.SCHEMA_VERSION_V1,
                serviceKey + "-app",
                serviceKey,
                hostVersion,
                Instant.now(),
                OpaProviderIoSchemas.REQUIRED_PROVIDER_IO_SCHEMAS_V1,
                Set.copyOf(hostRegisteredMaskStrategies),
                Set.copyOf(hostRegisteredObligationTypes),
                compatEntries
        );

        ImpactGraphBaseline impactBaseline = new ImpactGraphBaseline(
                "imp-" + serviceKey + "-1",
                ImpactCompletenessStatus.COMPLETE,
                unitKeys,
                pointsByKey.keySet(),
                Set.copyOf(requiredMaskStrategyIds),
                Set.copyOf(requiredObligationTypes),
                Set.of()
        );

        HostRuntimePolicyCoordinates coordinates = new HostRuntimePolicyCoordinates(
                hostManifest,
                bundleArtifact.runtimeRelease(),
                impactBaseline,
                factContractsById,
                queryProjectionsById,
                bindingsByPointKey
        );

        return new AuthzHostPolicyBootstrapBundle(
                serviceKey,
                coordinates,
                admissionRecords,
                bundleArtifact,
                localTransport,
                policies,
                resources.stream().map(RegisteredResourceEntry::spec).toList()
        );
    }
}
