package org.praxisplatform.authz.pilot;

import java.time.Instant;
import java.util.List;
import java.util.Map;
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
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.FactCardinality;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactPresenceModel;
import org.praxisplatform.authz.contracts.context.FactResolutionStage;
import org.praxisplatform.authz.contracts.context.FactSlotNamespace;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.datascope.QueryableFieldDescriptor;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateOperator;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionKind;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointIdentity;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointRef;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionResultContractKind;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FactContractRef;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.decisionpoint.PointAuthorityMode;
import org.praxisplatform.authz.contracts.decisionpoint.QueryableProjectionRef;
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
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;
import org.praxisplatform.authz.contracts.policy.MaskContributionSpec;
import org.praxisplatform.authz.contracts.policy.PolicyFieldSelector;
import org.praxisplatform.authz.contracts.policy.PolicyMaterializationTargetSpec;
import org.praxisplatform.authz.contracts.policy.PolicyTargetSpec;
import org.praxisplatform.authz.opa.bundle.OpaBundleArtifact;
import org.praxisplatform.authz.opa.bundle.OpaBundleAssembler;
import org.praxisplatform.authz.opa.client.DeterministicLocalOpaTransport;
import org.praxisplatform.authz.opa.compiler.CompiledRegoUnit;
import org.praxisplatform.authz.opa.compiler.RegoV1PolicyCompiler;

/**
 * Provides canonical, ready-to-verify authorization blueprints for both the Ergon
 * {@code Afastamento} showcase pilot (dual-scope cedente/cessionário, sensitive health CID masking,
 * selective write protection) and generic non-Ergon hosts ({@code P22}).
 */
public record AfastamentoAuthzPilotBlueprint(
        String serviceKey,
        String resourceKey,
        DecisionPointDescriptor decisionPoint,
        FactContract factContract,
        QueryableResourceProjection queryProjection,
        RuntimeEnforcementBinding enforcementBinding,
        DualScopeDelegationSpec dualScopeSpec,
        AuthorizationPolicyDefinition policyDefinition,
        OpaBundleArtifact bundleArtifact,
        DeterministicLocalOpaTransport localOpaTransport,
        HostRuntimePolicyCoordinates coordinates,
        List<MethodBindingAdmissionRecord> admissionRecords
) {

    /**
     * Builds the canonical Ergon {@code Afastamento} pilot blueprint ({@code serviceKey = "praxis-ergon-showcase"},
     * {@code resourceKey = "human-resources.afastamentos"}).
     */
    public static AfastamentoAuthzPilotBlueprint createErgonAfastamentoBlueprint() {
        return createHostBlueprint(
                "praxis-ergon-showcase",
                "human-resources.afastamentos",
                "ergon.afastamentos"
        );
    }

    /**
     * Builds a host-neutral authorization blueprint without any Ergon classes or naming conventions,
     * proving cross-host contract reuse ({@code P22}).
     */
    public static AfastamentoAuthzPilotBlueprint createHostBlueprint(
            String serviceKey,
            String resourceKey,
            String attributePrefix
    ) {
        String fcId = "fc-" + resourceKey.replace('.', '-');
        String qpId = "qp-" + resourceKey.replace('.', '-');
        String fcDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, fcId + "|v1");
        String qpDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, qpId + "|v1");
        String dpDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, serviceKey + "|" + resourceKey + "|filter|v1");
        String bindingDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, serviceKey + "|" + resourceKey + "|binding|v1");
        String capDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, "opa-cap-v1");

        String scopeAttrId = attributePrefix + ".lotacao_setor_id";
        String sensitiveAttrId = attributePrefix + ".cid_codigo";
        String substitutoAttrId = attributePrefix + ".substituto_servidor_id";
        String statusAttrId = attributePrefix + ".status_afastamento";

        FactDescriptor subPrincipal = new FactDescriptor(
                "subject.principalId", FactSlotNamespace.SUBJECT, FactValueType.STRING, FactCardinality.SCALAR,
                FactPresenceModel.ALWAYS_PRESENT, null, null, FactResolutionStage.EXTRACT,
                Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET), false,
                "INTERNAL", "OPERATIONAL", Set.of(), "STATUTORY_LEGAL_OBLIGATION", null);
        FactDescriptor subOrgs = new FactDescriptor(
                "subject.organizationUnitIds", FactSlotNamespace.SUBJECT, FactValueType.INT64, FactCardinality.SET,
                FactPresenceModel.ALWAYS_PRESENT, null, null, FactResolutionStage.ENRICH,
                Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET), false,
                "INTERNAL", "OPERATIONAL", Set.of(), "STATUTORY_LEGAL_OBLIGATION", null);
        FactDescriptor resScope = new FactDescriptor(
                "resource.lotacaoSetorId", FactSlotNamespace.RESOURCE, FactValueType.INT64, FactCardinality.SCALAR,
                FactPresenceModel.ALWAYS_PRESENT, scopeAttrId, null, FactResolutionStage.EXTRACT,
                Set.of(ContextEvaluationPhase.TARGET), true,
                "INTERNAL", "OPERATIONAL", Set.of(), "STATUTORY_LEGAL_OBLIGATION", null);
        FactDescriptor resSensitive = new FactDescriptor(
                "resource.cidCodigo", FactSlotNamespace.RESOURCE, FactValueType.STRING, FactCardinality.SCALAR,
                FactPresenceModel.MAY_BE_ABSENT, sensitiveAttrId, null, FactResolutionStage.EXTRACT,
                Set.of(ContextEvaluationPhase.TARGET), true,
                "RESTRICTED", "SENSITIVE_PERSONAL", Set.of("HEALTH_DATA"), "OFFICIAL_HEALTH_EXPERTISE", null);

        FactContract fc = new FactContract(
                FactContract.SCHEMA_VERSION_V1,
                fcId,
                "1.0.0",
                fcDigest,
                resourceKey,
                Map.of(
                        subPrincipal.factPath(), subPrincipal,
                        subOrgs.factPath(), subOrgs,
                        resScope.factPath(), resScope,
                        resSensitive.factPath(), resSensitive
                )
        );

        QueryableResourceProjection qp = new QueryableResourceProjection(
                QueryableResourceProjection.SCHEMA_VERSION_V1,
                qpId,
                resourceKey,
                qpDigest,
                Map.of(
                        "resource.lotacaoSetorId",
                        new QueryableFieldDescriptor(
                                "resource.lotacaoSetorId",
                                scopeAttrId,
                                FactValueType.INT64,
                                Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.IN),
                                true)
                )
        );

        DecisionPointIdentity dpId = DecisionPointIdentity.resourceOperation(serviceKey, resourceKey, "filter");
        DecisionPointDescriptor dp = new DecisionPointDescriptor(
                DecisionPointDescriptor.SCHEMA_VERSION_V1,
                dpId,
                DecisionKind.AUTHORIZATION,
                DecisionResultContractKind.GATE,
                null,
                "SEARCH",
                "POST",
                "/api/" + resourceKey.replace('.', '/') + "/filter",
                Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET),
                Set.of(
                        EnforcementCapability.ACCESS,
                        EnforcementCapability.DATA_SCOPE,
                        EnforcementCapability.FIELD_USE,
                        EnforcementCapability.FIELD_WRITE,
                        EnforcementCapability.MASK
                ),
                Set.of(
                        FieldUseCategory.VALUE,
                        FieldUseCategory.FILTER,
                        FieldUseCategory.SORT,
                        FieldUseCategory.GROUP,
                        FieldUseCategory.AGGREGATE,
                        FieldUseCategory.JOIN
                ),
                null,
                new FactContractRef(fcId, fcDigest),
                new QueryableProjectionRef(qpId, qpDigest),
                null,
                null,
                "STATUTORY_LEGAL_OBLIGATION",
                "LGPD:ART_7_III",
                null,
                dpDigest
        );

        DualScopeDelegationSpec dualScopeSpec = new DualScopeDelegationSpec(
                "CEDENTE_CESSIONARIO_SPLIT",
                "resource.orgCedenteId",
                "resource.orgCessionariaId",
                Set.of(statusAttrId, sensitiveAttrId),
                Set.of(substitutoAttrId)
        );

        AuthorizationPolicyRule rule = new AuthorizationPolicyRule(
                "rule-scope-and-mask",
                "Grants organizational scope access and masks sensitive health attribute",
                Set.of(EvaluationMode.TARGET, EvaluationMode.SEARCH),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        Map.of("==", List.of(Map.of("var", "subject.principalId"), "usr-gestor-101"))
                ),
                new AuthorizationRuleContributions(
                        new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                        new DataScopeContributionSpec(
                                ContributionAuthority.GRANT,
                                new AuthorizationSourceCondition(
                                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                                        ConditionProfileKind.AUTHORIZATION_SEARCH_SOURCE_V1,
                                        Map.of("in", List.of(
                                                Map.of("var", "resource.lotacaoSetorId"),
                                                Map.of("var", "subject.organizationUnitIds")))
                                )
                        ),
                        List.of(),
                        List.of(),
                        List.of(new MaskContributionSpec(
                                PolicyFieldSelector.exact(Set.of(sensitiveAttrId)),
                                "REDACT_CONSTANT",
                                Map.of("replacement", "***CID-RESTRITO***")
                        )),
                        "ALLOW_LOTACAO_GESTOR"
                ),
                List.of(new ObligationDirective(
                        "DURABLE_AUDIT_EVIDENCE",
                        "ON_PERMIT",
                        "BEFORE_COMMIT_OUTBOX",
                        Map.of("auditCategory", "PILOT_RESOURCE_ACCESS")))
        );

        String policyId = "pol-" + serviceKey + "-" + resourceKey.replace('.', '-');
        String unitKey = "unit:" + policyId + ":v1";

        AuthorizationPolicyDefinition policy = new AuthorizationPolicyDefinition(
                AuthorizationPolicyDefinition.SCHEMA_VERSION_V1,
                policyId,
                "1.0.0",
                "Pilot Policy for " + resourceKey,
                "Organizational scope and sensitive field masking",
                Set.of("ORGANIZATIONAL_SCOPE"),
                "STATUTORY_LEGAL_OBLIGATION",
                "LGPD:ART_7_III",
                OpaProviderIoSchemas.COMBINING_PROFILE_V1,
                List.of(PolicyTargetSpec.exact(
                        "tgt-1",
                        dp.identity().pointKey(),
                        dpDigest,
                        Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET))),
                dualScopeSpec,
                List.of(),
                List.of(rule),
                List.of(new PolicyMaterializationTargetSpec(
                        "policy_engine", "opa-policy", unitKey, OpaProviderIoSchemas.COMPILER_PROFILE_V1))
        );

        RegoV1PolicyCompiler compiler = new RegoV1PolicyCompiler();
        CompiledRegoUnit compiledUnit = compiler.compileUnit(
                policy,
                Map.of(dp.identity().pointKey(), dp),
                Map.of(fc.factContractId(), fc),
                Map.of(qp.projectionId(), qp)
        );

        OpaBundleAssembler assembler = new OpaBundleAssembler(compiler);
        OpaBundleArtifact bundleArtifact = assembler.assembleBundle(
                "rel-" + serviceKey + "-1",
                "rev-2026-11-08-01",
                1L,
                "prod-cluster",
                "opa-node-1",
                capDigest,
                List.of(compiledUnit)
        );

        DeterministicLocalOpaTransport localTransport = new DeterministicLocalOpaTransport(
                bundleArtifact,
                List.of(qp)
        );

        RuntimeEnforcementBinding binding = new RuntimeEnforcementBinding(
                RuntimeEnforcementBinding.SCHEMA_VERSION_V1,
                "bnd-" + resourceKey.replace('.', '-') + "-search",
                new DecisionPointRef(
                        dp.identity().pointKey(),
                        dp.identity().pointKind(),
                        dp.identity().serviceKey(),
                        dp.identity().resourceKey(),
                        dp.identity().operationOrActionKey(),
                        dpDigest
                ),
                EvaluationMode.SEARCH,
                EnforcementCapability.DATA_SCOPE,
                Set.of(FieldUseCategory.VALUE, FieldUseCategory.FILTER),
                HostEnforcementPhase.REQUEST_QUERY,
                "OPA_REGO_V1",
                PointAuthorityMode.AUTHORITATIVE,
                "praxis.enforcement-profile.spring-jpa/v1",
                "DefaultSearchHandler/v1",
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

        DecisionPointCompatibilityEntry compatEntry = new DecisionPointCompatibilityEntry(
                dp.identity().pointKey(),
                dpDigest,
                fc.factContractId(),
                fcDigest,
                qp.projectionId(),
                qpDigest,
                bindingDigest,
                RolloutActivationStrategy.POLICY_FIRST,
                true
        );

        HostPolicyCompatibilityManifest hostManifest = new HostPolicyCompatibilityManifest(
                HostPolicyCompatibilityManifest.SCHEMA_VERSION_V1,
                serviceKey + "-app",
                serviceKey,
                "1.0.0",
                Instant.now(),
                OpaProviderIoSchemas.REQUIRED_PROVIDER_IO_SCHEMAS_V1,
                Set.of("REDACT_CONSTANT", "PARTIAL_MASK", "HASH_TOKEN_KEYED"),
                Set.of("DURABLE_AUDIT_EVIDENCE"),
                List.of(compatEntry)
        );

        ImpactGraphBaseline impactBaseline = new ImpactGraphBaseline(
                "imp-" + serviceKey + "-1",
                ImpactCompletenessStatus.COMPLETE,
                Set.of(unitKey),
                Set.of(dp.identity().pointKey()),
                Set.of("REDACT_CONSTANT"),
                Set.of("DURABLE_AUDIT_EVIDENCE"),
                Set.of()
        );

        HostRuntimePolicyCoordinates coordinates = new HostRuntimePolicyCoordinates(
                hostManifest,
                bundleArtifact.runtimeRelease(),
                impactBaseline,
                Map.of(fc.factContractId(), fc),
                Map.of(qp.projectionId(), qp),
                Map.of(dp.identity().pointKey(), binding)
        );

        // P44, P58, P62: Field lineage entries across ResponseDTO, CreateDTO, UpdateDTO with distinct wire names mapping to canonical attributeId
        List<FieldLineageCatalogEntry> lineageEntries = List.of(
                new FieldLineageCatalogEntry(
                        sensitiveAttrId,
                        "concept:health:icd10",
                        "schema://" + resourceKey + "/ResponseDTO",
                        "cidCodigo",
                        "READ_PROJECTION",
                        "HEALTH_SENSITIVE",
                        "DENIED",
                        false,
                        Set.of(FieldUseCategory.VALUE),
                        List.of(),
                        true
                ),
                new FieldLineageCatalogEntry(
                        sensitiveAttrId,
                        "concept:health:icd10",
                        "schema://" + resourceKey + "/CreateDTO",
                        "codigoCid10",
                        "CREATE_INPUT",
                        "HEALTH_SENSITIVE",
                        "DENIED",
                        false,
                        Set.of(FieldUseCategory.VALUE),
                        List.of(),
                        true
                ),
                new FieldLineageCatalogEntry(
                        substitutoAttrId,
                        "concept:hr:substitute-employee",
                        "schema://" + resourceKey + "/UpdateDTO",
                        "substitutoServidorId",
                        "UPDATE_INPUT",
                        "OPERATIONAL_INTERNAL",
                        "SCHEMA_METADATA_ONLY",
                        true,
                        Set.of(FieldUseCategory.VALUE, FieldUseCategory.FILTER),
                        List.of(),
                        true
                )
        );

        MethodBindingAdmissionRecord admissionRecord = new MethodBindingAdmissionRecord(
                serviceKey,
                dp,
                binding,
                Set.of(
                        AdmittedInvocationChannel.REST_ENDPOINT,
                        AdmittedInvocationChannel.PROXIED_INTERNAL_SERVICE
                ),
                true,
                lineageEntries
        );

        return new AfastamentoAuthzPilotBlueprint(
                serviceKey,
                resourceKey,
                dp,
                fc,
                qp,
                binding,
                dualScopeSpec,
                policy,
                bundleArtifact,
                localTransport,
                coordinates,
                List.of(admissionRecord)
        );
    }
}
