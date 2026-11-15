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
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
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
            List<AuthorizationPolicyDefinition> policies
    ) {
        public AuthzHostPolicyBootstrapBundle {
            Objects.requireNonNull(serviceKey, "serviceKey is required");
            Objects.requireNonNull(coordinates, "coordinates is required");
            admissionRecords = List.copyOf(Objects.requireNonNull(admissionRecords, "admissionRecords is required"));
            Objects.requireNonNull(bundleArtifact, "bundleArtifact is required");
            Objects.requireNonNull(localOpaTransport, "localOpaTransport is required");
            policies = List.copyOf(Objects.requireNonNull(policies, "policies is required"));
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
        return addBulkActionPolicy(
                spec,
                actionKey,
                ruleId,
                Map.of("!=", List.of(Map.of("var", "subject.principalId"), "")),
                Map.of("in", List.of(
                        Map.of("var", resourceScopeFactPath),
                        Map.of("var", subjectScopeSetFactPath)
                )),
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
            Map<String, Object> targetCombinedCondition = Map.of(
                    "and",
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
    public AuthzHostPolicyBootstrapBuilder addSurfacePolicy(
            AuthzResourceGovernanceSpec<?> spec,
            String surfaceKey,
            String ruleId,
            Map<String, Object> targetJsonLogicCondition,
            Map<String, String> redactConstantMasksByAttributeId
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

        List<MaskContributionSpec> masks = new ArrayList<>();
        if (redactConstantMasksByAttributeId != null) {
            for (Map.Entry<String, String> entry : redactConstantMasksByAttributeId.entrySet()) {
                masks.add(new MaskContributionSpec(
                        PolicyFieldSelector.exact(Set.of(entry.getKey())),
                        "REDACT_CONSTANT",
                        Map.of("replacement", entry.getValue())
                ));
            }
        }

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
        Objects.requireNonNull(spec, "spec is required");
        Objects.requireNonNull(ruleId, "ruleId is required");
        Objects.requireNonNull(resourceScopeFactPath, "resourceScopeFactPath is required");
        Objects.requireNonNull(subjectScopeSetFactPath, "subjectScopeSetFactPath is required");

        List<MaskContributionSpec> masks = new ArrayList<>();
        if (redactConstantMasksByAttributeId != null) {
            for (Map.Entry<String, String> entry : redactConstantMasksByAttributeId.entrySet()) {
                masks.add(new MaskContributionSpec(
                        PolicyFieldSelector.exact(Set.of(entry.getKey())),
                        "REDACT_CONSTANT",
                        Map.of("replacement", entry.getValue())
                ));
            }
        }

        Map<String, Object> principalCondition = Map.of("!=", List.of(Map.of("var", "subject.principalId"), ""));
        Map<String, Object> scopeInCondition = Map.of(
                "in",
                List.of(
                        Map.of("var", resourceScopeFactPath),
                        Map.of("var", subjectScopeSetFactPath)
                )
        );
        List<ObligationDirective> auditObligations = List.of(new ObligationDirective(
                "DURABLE_AUDIT_EVIDENCE",
                "ON_PERMIT",
                "BEFORE_COMMIT_OUTBOX",
                Map.of("auditCategory", "GOVERNED_RESOURCE_ACCESS")
        ));

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
                        List.copyOf(masks),
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
                        Map.of("and", List.of(principalCondition, scopeInCondition))
                ),
                new AuthorizationRuleContributions(
                        new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                        null,
                        List.of(),
                        List.of(),
                        List.copyOf(masks),
                        "ALLOW_ORGANIZATIONAL_SCOPE"
                ),
                auditObligations
        );

        DecisionPointDescriptor dp = spec.decisionPoint();
        String policyId = "pol-" + serviceKey + "-" + spec.resourceKey().replace('.', '-');
        String unitKey = "unit:" + policyId + ":v1";

        AuthorizationPolicyDefinition policy = new AuthorizationPolicyDefinition(
                AuthorizationPolicyDefinition.SCHEMA_VERSION_V1,
                policyId,
                "1.0.0",
                "Organizational Scope Policy for " + spec.resourceKey(),
                "Declarative organizational scope and field masking policy",
                Set.of("ORGANIZATIONAL_SCOPE"),
                dp.legalPurpose() != null ? dp.legalPurpose() : "STATUTORY_LEGAL_OBLIGATION",
                dp.legalBasisRef() != null ? dp.legalBasisRef() : "LGPD:ART_7_III",
                OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                List.of(PolicyTargetSpec.exact(
                        "tgt-" + spec.resourceKey().replace('.', '-'),
                        dp.identity().pointKey(),
                        dp.descriptorDigest(),
                        Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET)
                )),
                spec.dualScopeDelegationSpec(),
                List.of(),
                List.of(searchRule, targetRule),
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
                policies
        );
    }
}
