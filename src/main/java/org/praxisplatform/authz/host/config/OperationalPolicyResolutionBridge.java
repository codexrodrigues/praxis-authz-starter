package org.praxisplatform.authz.host.config;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler;
import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler.ConfigRuleMaterializationSnapshot;
import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler.MaterializationResolutionState;
import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler.ReconciliationOutcome;
import org.praxisplatform.authz.opa.governance.PolicyCandidateVerificationCorpusCase;
import org.praxisplatform.config.service.OperationalPolicyResolution;

/**
 * Canonical control-plane bridge connecting {@code praxis-config-starter}'s
 * {@link OperationalPolicyResolution} directly to {@link ConfigMaterializationToOpaReconciler}
 * ({@code CC10}, {@code CC11}, {@code P18}, {@code P28}, {@code P53}, {@code P55}, {@code P63}).
 *
 * <p>Maps the 4 states of {@link OperationalPolicyResolution.State} ({@code ELIGIBLE_APPLIED_HEAD},
 * {@code PREVIOUSLY_APPLIED_WITHOUT_ELIGIBLE_HEAD}, {@code NEVER_APPLIED},
 * {@code INCONSISTENT_OR_UNAVAILABLE}) and the immutable {@link OperationalPolicyResolution.Policy}
 * evidence into a {@link ConfigRuleMaterializationSnapshot} and reconciles or withdraws the
 * corresponding OPA bundle head fail-closed.</p>
 */
public final class OperationalPolicyResolutionBridge {

    private final ConfigMaterializationToOpaReconciler reconciler;

    /**
     * Creates a bridge backed by {@link ConfigMaterializationToOpaReconciler}.
     *
     * @param reconciler canonical OPA materialization reconciler
     */
    public OperationalPolicyResolutionBridge(ConfigMaterializationToOpaReconciler reconciler) {
        this.reconciler = Objects.requireNonNull(reconciler, "reconciler is required");
    }

    /**
     * Translates an {@link OperationalPolicyResolution} from {@code praxis-config-starter} into a
     * {@link ConfigRuleMaterializationSnapshot} and executes governed OPA bundle activation or
     * withdrawal ({@code P18}, {@code P28}, {@code P53}, {@code P55}, {@code P63}).
     *
     * @param tenantId canonical tenant identifier
     * @param environment canonical environment identifier
     * @param resolution {@link OperationalPolicyResolution} returned by {@code OperationalPolicyService}
     * @param authoredBy principal who authored the policy version
     * @param approvedBy principal who approved the policy version (must satisfy 4-eyes {@code authoredBy != approvedBy})
     * @param operatorPrincipalId operator triggering reconciliation
     * @param operatorGrantedAuthorities granted authorities of the operator
     * @param opaInstanceId target OPA instance identifier
     * @param opaCapabilitiesDigest SHA-256 digest of OPA capabilities
     * @param policyDefinition canonical {@link AuthorizationPolicyDefinition} (required when {@code ELIGIBLE_APPLIED_HEAD})
     * @param verificationCorpus mandatory positive/negative verification corpus cases
     * @param decisionPointsByKey decision points by key
     * @param factContractsById fact contracts by ID
     * @param queryProjectionsById query projections by ID
     * @return {@link ReconciliationOutcome} describing bundle activation or head withdrawal
     */
    public ReconciliationOutcome reconcileFromOperationalResolution(
            String tenantId,
            String environment,
            OperationalPolicyResolution resolution,
            String opaUnitTargetKey,
            String authoredBy,
            String approvedBy,
            String operatorPrincipalId,
            Set<String> operatorGrantedAuthorities,
            String opaInstanceId,
            String opaCapabilitiesDigest,
            AuthorizationPolicyDefinition policyDefinition,
            List<PolicyCandidateVerificationCorpusCase> verificationCorpus,
            Map<String, DecisionPointDescriptor> decisionPointsByKey,
            Map<String, FactContract> factContractsById,
            Map<String, QueryableResourceProjection> queryProjectionsById
    ) {
        Objects.requireNonNull(resolution, "resolution is required");
        Objects.requireNonNull(opaUnitTargetKey, "opaUnitTargetKey is required");
        MaterializationResolutionState mappedState = switch (resolution.resolutionState()) {
            case ELIGIBLE_APPLIED_HEAD -> MaterializationResolutionState.ELIGIBLE_APPLIED_HEAD;
            case PREVIOUSLY_APPLIED_WITHOUT_ELIGIBLE_HEAD -> MaterializationResolutionState.PREVIOUSLY_APPLIED_WITHOUT_ELIGIBLE_HEAD;
            case NEVER_APPLIED -> MaterializationResolutionState.NEVER_APPLIED;
            case INCONSISTENT_OR_UNAVAILABLE -> MaterializationResolutionState.INCONSISTENT_OR_UNAVAILABLE;
        };

        OperationalPolicyResolution.Policy policy = resolution.policy();
        if (mappedState == MaterializationResolutionState.ELIGIBLE_APPLIED_HEAD && policy == null) {
            throw new IllegalArgumentException(
                    "ELIGIBLE_APPLIED_HEAD resolution requires a non-null OperationalPolicyResolution.Policy");
        }
        String materializationId = policy != null ? policy.materializationId().toString() : "mat-none";
        String definitionId = policy != null ? policy.definitionId().toString() : "def-none";
        int definitionVersion = policy != null ? policy.definitionVersion() : 1;
        String sourceHash = policy != null ? policy.sourceHash() : resolution.resolutionFingerprint();
        String status = mappedState == MaterializationResolutionState.ELIGIBLE_APPLIED_HEAD ? "applied" : "withdrawn";
        boolean everApplied = mappedState != MaterializationResolutionState.NEVER_APPLIED;

        ConfigRuleMaterializationSnapshot snapshot = new ConfigRuleMaterializationSnapshot(
                materializationId,
                definitionId,
                definitionVersion,
                tenantId,
                environment,
                "policy_engine",
                "opa-policy",
                opaUnitTargetKey,
                "rel-" + materializationId,
                status,
                everApplied,
                sourceHash,
                authoredBy,
                approvedBy,
                operatorPrincipalId,
                mappedState,
                mappedState == MaterializationResolutionState.ELIGIBLE_APPLIED_HEAD ? policyDefinition : null,
                mappedState == MaterializationResolutionState.ELIGIBLE_APPLIED_HEAD ? verificationCorpus : List.of(),
                resolution.observedAt()
        );

        return reconciler.reconcileOrWithdraw(
                snapshot,
                opaInstanceId,
                opaCapabilitiesDigest,
                operatorPrincipalId,
                operatorGrantedAuthorities,
                decisionPointsByKey,
                factContractsById,
                queryProjectionsById
        );
    }

    /** Returns the underlying {@link ConfigMaterializationToOpaReconciler}. */
    public ConfigMaterializationToOpaReconciler reconciler() {
        return reconciler;
    }
}
