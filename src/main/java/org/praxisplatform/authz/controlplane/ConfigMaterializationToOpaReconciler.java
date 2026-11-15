package org.praxisplatform.authz.controlplane;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.praxisplatform.authz.opa.compiler.RegoV1PolicyCompiler;
import org.praxisplatform.authz.opa.governance.GovernedOpaReleaseCoordinator;
import org.praxisplatform.authz.opa.governance.GovernedOpaReleaseCoordinator.GovernedReleaseActivationResult;
import org.praxisplatform.authz.opa.governance.PolicyCandidateVerificationCorpusCase;

/**
 * Reconciles the governed {@code DomainRuleMaterialization} / {@code OperationalPolicyService}
 * lifecycle in {@code praxis-config-starter} with OPA bundle compilation, verification, activation,
 * and withdrawal ({@code P18}, {@code P21}, {@code P28}, {@code P31}, {@code P32}, {@code P53},
 * {@code P55}, {@code P63}).
 *
 * <p>Guarantees that:</p>
 * <ul>
 *   <li>Reading or inspecting a materialization snapshot never grants domain access by itself;</li>
 *   <li>Only an {@code ELIGIBLE_APPLIED_HEAD} with {@code status = "applied"}, {@code everApplied = true},
 *       {@code targetLayer = "policy_engine"}, {@code targetArtifactType = "opa-policy"}, 4-eyes approval
 *       ({@code authoredBy != approvedBy}), and matching {@code sourceHash == definitionFingerprint}
 *       can be activated;</li>
 *   <li>When a materialization is withdrawn or superseded ({@code PREVIOUSLY_APPLIED_WITHOUT_ELIGIBLE_HEAD}
 *       or {@code INCONSISTENT_OR_UNAVAILABLE}), the active OPA head for that target key is immediately
 *       revoked fail-closed.</li>
 * </ul>
 */
public final class ConfigMaterializationToOpaReconciler {

    /** Mirrors {@code OperationalPolicyResolution.State} from {@code praxis-config-starter}. */
    public enum MaterializationResolutionState {
        NEVER_APPLIED,
        ELIGIBLE_APPLIED_HEAD,
        PREVIOUSLY_APPLIED_WITHOUT_ELIGIBLE_HEAD,
        INCONSISTENT_OR_UNAVAILABLE
    }

    /** Canonical snapshot of a {@code DomainRuleMaterialization} for {@code decisionKind = AUTHORIZATION}. */
    public record ConfigRuleMaterializationSnapshot(
            String materializationId,
            String ruleDefinitionId,
            int definitionVersion,
            String tenantId,
            String environment,
            String targetLayer,
            String targetArtifactType,
            String targetArtifactKey,
            String targetReleaseKey,
            String status,
            boolean everApplied,
            String sourceHash,
            String authoredBy,
            String approvedBy,
            String appliedBy,
            MaterializationResolutionState resolutionState,
            AuthorizationPolicyDefinition candidatePolicy,
            List<PolicyCandidateVerificationCorpusCase> verificationCorpus,
            Instant observedAt
    ) {
        public ConfigRuleMaterializationSnapshot {
            Objects.requireNonNull(materializationId, "materializationId is required");
            Objects.requireNonNull(ruleDefinitionId, "ruleDefinitionId is required");
            Objects.requireNonNull(tenantId, "tenantId is required");
            Objects.requireNonNull(environment, "environment is required");
            Objects.requireNonNull(targetLayer, "targetLayer is required");
            Objects.requireNonNull(targetArtifactType, "targetArtifactType is required");
            Objects.requireNonNull(targetArtifactKey, "targetArtifactKey is required");
            Objects.requireNonNull(status, "status is required");
            Objects.requireNonNull(sourceHash, "sourceHash is required");
            Objects.requireNonNull(authoredBy, "authoredBy is required");
            Objects.requireNonNull(approvedBy, "approvedBy is required");
            Objects.requireNonNull(appliedBy, "appliedBy is required");
            Objects.requireNonNull(resolutionState, "resolutionState is required");
            Objects.requireNonNull(observedAt, "observedAt is required");
        }
    }

    /** Result of reconciling a {@link ConfigRuleMaterializationSnapshot} with the OPA release coordinator. */
    public record ReconciliationOutcome(
            String targetArtifactKey,
            MaterializationResolutionState resolutionState,
            boolean bundleActivated,
            boolean previousHeadWithdrawn,
            GovernedReleaseActivationResult activationResult,
            String diagnosticCode
    ) {}

    private final RegoV1PolicyCompiler compiler;
    private final GovernedOpaReleaseCoordinator releaseCoordinator;
    private final Map<String, OpaRuntimeHead> activeHeadsByCompositeKey = new ConcurrentHashMap<>();
    private final Map<String, OpaRuntimeHead> activeHeadsByTargetKey = new ConcurrentHashMap<>();
    private final Map<String, Integer> activeVersionByCompositeKey = new ConcurrentHashMap<>();

    public ConfigMaterializationToOpaReconciler(
            RegoV1PolicyCompiler compiler,
            GovernedOpaReleaseCoordinator releaseCoordinator
    ) {
        this.compiler = Objects.requireNonNull(compiler, "compiler is required");
        this.releaseCoordinator = Objects.requireNonNull(releaseCoordinator, "releaseCoordinator is required");
    }

    /**
     * Reconciles a {@link ConfigRuleMaterializationSnapshot} from {@code praxis-config-starter}
     * into an active OPA release or revokes any previously active release if withdrawn/inconsistent.
     */
    public ReconciliationOutcome reconcileOrWithdraw(
            ConfigRuleMaterializationSnapshot snapshot,
            String instanceId,
            String opaCapabilitiesDigest,
            String operatorPrincipalId,
            Set<String> operatorAuthorities,
            Map<String, DecisionPointDescriptor> decisionPointsByKey,
            Map<String, FactContract> factContractsById,
            Map<String, QueryableResourceProjection> queryProjectionsById
    ) {
        Objects.requireNonNull(snapshot, "snapshot is required");
        String compositeKey = toCompositeKey(snapshot.tenantId(), snapshot.environment(), snapshot.targetArtifactKey());

        // 1. Handle withdrawal / superseding / inconsistency by revoking any active head fail-closed (P18, P28, P55)
        if (snapshot.resolutionState() == MaterializationResolutionState.PREVIOUSLY_APPLIED_WITHOUT_ELIGIBLE_HEAD
                || snapshot.resolutionState() == MaterializationResolutionState.INCONSISTENT_OR_UNAVAILABLE
                || snapshot.resolutionState() == MaterializationResolutionState.NEVER_APPLIED) {
            OpaRuntimeHead removed = activeHeadsByCompositeKey.remove(compositeKey);
            activeHeadsByTargetKey.remove(snapshot.targetArtifactKey());
            return new ReconciliationOutcome(
                    snapshot.targetArtifactKey(),
                    snapshot.resolutionState(),
                    false,
                    removed != null,
                    null,
                    "HEAD_NOT_ELIGIBLE_OR_WITHDRAWN:" + snapshot.resolutionState()
            );
        }

        // 2. Validate layer, artifact type, applied status, and everApplied invariant (P28, P31, P55)
        if (!"policy_engine".equals(snapshot.targetLayer())
                || !"opa-policy".equals(snapshot.targetArtifactType())
                || !"applied".equals(snapshot.status())
                || !snapshot.everApplied()) {
            activeHeadsByCompositeKey.remove(compositeKey);
            activeHeadsByTargetKey.remove(snapshot.targetArtifactKey());
            throw new SecurityException("AUTHZ_MATERIALIZATION_NOT_APPLIED_OPA_HEAD: Materialization '"
                    + snapshot.materializationId() + "' is not an applied policy_engine/opa-policy head (P28/P55)");
        }

        // 3. Enforce monotonic version progression against stale snapshot replay (P17, P28, P55)
        Integer currentVersion = activeVersionByCompositeKey.get(compositeKey);
        if (currentVersion != null && snapshot.definitionVersion() < currentVersion) {
            throw new SecurityException("AUTHZ_MATERIALIZATION_VERSION_ROLLBACK_REJECTED: Cannot activate stale definitionVersion "
                    + snapshot.definitionVersion() + " over already-applied definitionVersion "
                    + currentVersion + " for target '" + compositeKey + "' (P17/P28/P55)");
        }

        // 4. Enforce 4-eyes separation of duties between author and approver (P28, P55)
        if (snapshot.authoredBy().trim().equalsIgnoreCase(snapshot.approvedBy().trim())) {
            throw new SecurityException("AUTHZ_FOUR_EYES_APPROVAL_REQUIRED: authoredBy ('"
                    + snapshot.authoredBy() + "') must not equal approvedBy ('"
                    + snapshot.approvedBy() + "') for governed OPA policy activation (P28/P55)");
        }

        if (snapshot.candidatePolicy() == null) {
            throw new IllegalArgumentException("ELIGIBLE_APPLIED_HEAD snapshot must carry candidatePolicy");
        }

        // 5. Verify candidatePolicy explicitly declares a matching materializationTarget targetArtifactKey (P28, P38, P55)
        boolean targetMatchesPolicyDeclaration = snapshot.candidatePolicy().materializationTargets().stream()
                .anyMatch(t -> "policy_engine".equals(t.targetLayer())
                        && "opa-policy".equals(t.targetArtifactType())
                        && snapshot.targetArtifactKey().equals(t.targetArtifactKey()));
        if (!targetMatchesPolicyDeclaration) {
            throw new SecurityException("AUTHZ_MATERIALIZATION_TARGET_KEY_MISMATCH: Snapshot targetArtifactKey '"
                    + snapshot.targetArtifactKey() + "' is not declared in candidatePolicy.materializationTargets() (P28/P38/P55)");
        }

        // 6. Verify exact sourceHash == compiled definitionFingerprint (P55, P63)
        String compiledFingerprint = compiler.compileUnit(
                snapshot.candidatePolicy(),
                decisionPointsByKey,
                factContractsById,
                queryProjectionsById
        ).unitManifest().digestChain().definitionFingerprint();

        if (!snapshot.sourceHash().equals(compiledFingerprint)) {
            throw new SecurityException("AUTHZ_MATERIALIZATION_SOURCE_HASH_MISMATCH: Config sourceHash '"
                    + snapshot.sourceHash() + "' does not match compiled definitionFingerprint '"
                    + compiledFingerprint + "' (P55/P63)");
        }

        // 7. Execute governed release verification (including mandatory positive + negative corpus) and activate
        String releaseId = snapshot.targetReleaseKey() != null && !snapshot.targetReleaseKey().isBlank()
                ? snapshot.targetReleaseKey()
                : "rel-" + snapshot.materializationId();
        String runtimeRevision = "rev-" + snapshot.materializationId() + "-v" + snapshot.definitionVersion();

        GovernedReleaseActivationResult activationResult = releaseCoordinator.verifyAndActivateRelease(
                releaseId,
                runtimeRevision,
                snapshot.environment(),
                instanceId,
                opaCapabilitiesDigest,
                operatorPrincipalId,
                operatorAuthorities,
                List.of(snapshot.candidatePolicy()),
                Map.of(snapshot.candidatePolicy().policyId(), snapshot.sourceHash()),
                decisionPointsByKey,
                factContractsById,
                queryProjectionsById,
                snapshot.verificationCorpus()
        );

        activeHeadsByCompositeKey.put(compositeKey, activationResult.bundleArtifact().runtimeHead());
        activeHeadsByTargetKey.put(snapshot.targetArtifactKey(), activationResult.bundleArtifact().runtimeHead());
        activeVersionByCompositeKey.put(compositeKey, snapshot.definitionVersion());

        return new ReconciliationOutcome(
                snapshot.targetArtifactKey(),
                snapshot.resolutionState(),
                true,
                false,
                activationResult,
                "ACTIVATED_ELIGIBLE_HEAD"
        );
    }

    /** Returns the currently active {@link OpaRuntimeHead} for a tenant, environment, and target artifact key. */
    public Optional<OpaRuntimeHead> findActiveHead(String tenantId, String environment, String targetArtifactKey) {
        return Optional.ofNullable(activeHeadsByCompositeKey.get(toCompositeKey(tenantId, environment, targetArtifactKey)));
    }

    /** Returns the currently active {@link OpaRuntimeHead} for a target artifact key, or empty if withdrawn/never applied. */
    public Optional<OpaRuntimeHead> findActiveHead(String targetArtifactKey) {
        return Optional.ofNullable(activeHeadsByTargetKey.get(targetArtifactKey));
    }

    private static String toCompositeKey(String tenantId, String environment, String targetArtifactKey) {
        return tenantId + "|" + environment + "|" + targetArtifactKey;
    }
}
