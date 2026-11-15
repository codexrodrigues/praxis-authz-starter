package org.praxisplatform.authz.pilot;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactSlotNamespace;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyRule;
import org.praxisplatform.authz.contracts.policy.PolicyFactRequirement;
import org.praxisplatform.authz.contracts.policy.PolicyTargetSpec;
import org.praxisplatform.authz.opa.governance.GovernedOpaReleaseCoordinator;
import org.praxisplatform.authz.opa.governance.GovernedOpaReleaseCoordinator.GovernedReleaseActivationResult;
import org.praxisplatform.authz.opa.governance.PolicyCandidateVerificationCorpusCase;

/**
 * Mediates conversational/LLM policy authoring and candidate admission, enforcing:
 * <ul>
 *   <li>Exact catalog resolution without inventing roles, facts, or legal bases ({@code P51}, {@code P52});</li>
 *   <li>Prompt-injection and untrusted catalog text isolation ({@code P54});</li>
 *   <li>Typed fact provider/phase support validation ({@code P61});</li>
 *   <li>Mandatory positive + negative corpus execution and approved-digest verification via
 *       {@link GovernedOpaReleaseCoordinator} ({@code P53}, {@code P55}, {@code P63}).</li>
 * </ul>
 */
public final class GovernedPolicyAuthoringGateway {

    private static final List<String> PROMPT_INJECTION_PATTERNS = List.of(
            "ignore previous instructions",
            "bypass hard scope",
            "allow all",
            "grant admin",
            "skip corpus"
    );

    private final GovernedOpaReleaseCoordinator releaseCoordinator;

    public GovernedPolicyAuthoringGateway(GovernedOpaReleaseCoordinator releaseCoordinator) {
        this.releaseCoordinator = Objects.requireNonNull(releaseCoordinator, "releaseCoordinator is required");
    }

    /**
     * Validates an LLM-proposed or PAP-submitted policy candidate against exact catalog contracts,
     * prompt-injection guards, and fact-phase support before delegating to
     * {@link GovernedOpaReleaseCoordinator} ({@code P51..P55}, {@code P61}, {@code P63}).
     */
    public GovernedReleaseActivationResult admitVerifyAndActivateCandidate(
            String releaseId,
            String runtimeRevision,
            String deploymentNamespace,
            String instanceId,
            String opaCapabilitiesDigest,
            String callerPrincipalId,
            Set<String> callerAuthorities,
            Set<String> callerAllowedServiceKeys,
            String untrustedPromptOrDocNotes,
            AuthorizationPolicyDefinition candidatePolicy,
            Map<String, String> expectedApprovedFingerprintsByPolicyId,
            Map<String, DecisionPointDescriptor> decisionPointsByKey,
            Map<String, FactContract> factContractsById,
            Map<String, QueryableResourceProjection> queryProjectionsById,
            Set<String> supportedProviderFactPaths,
            List<PolicyCandidateVerificationCorpusCase> verificationCorpus
    ) {
        Objects.requireNonNull(candidatePolicy, "candidatePolicy is required");

        // 1. P54: Treat prompt/document text as untrusted data; normalize NFKC + whitespace and block prompt-injection attempts
        if (untrustedPromptOrDocNotes != null) {
            String normalizedNotes = Normalizer.normalize(untrustedPromptOrDocNotes, Normalizer.Form.NFKC)
                    .toLowerCase(Locale.ROOT)
                    .replaceAll("\\s+", " ")
                    .trim();
            for (String pattern : PROMPT_INJECTION_PATTERNS) {
                if (normalizedNotes.contains(pattern)) {
                    throw new SecurityException("AUTHZ_PROMPT_INJECTION_OR_BYPASS_DETECTED: Untrusted text attempted '"
                            + pattern + "' (P54)");
                }
            }
        }

        // 2. P52 & P54: Verify every target decision point exists in the catalog AND belongs to caller's delegated service scope
        List<String> unresolvedTerms = new ArrayList<>();
        for (PolicyTargetSpec target : candidatePolicy.targets()) {
            DecisionPointDescriptor dp = decisionPointsByKey.get(target.pointKey());
            if (dp == null) {
                unresolvedTerms.add("UNKNOWN_DECISION_POINT:" + target.pointKey());
                continue;
            }
            if (callerAllowedServiceKeys == null || !callerAllowedServiceKeys.contains(dp.identity().serviceKey())) {
                throw new SecurityException("AUTHZ_AUTHORING_HARD_SCOPE_VIOLATION: Caller '"
                        + callerPrincipalId + "' cannot author policies for service '"
                        + dp.identity().serviceKey() + "' (P54)");
            }

            // 3. P52 & P61: Verify all required facts AND all AST-referenced facts exist in the governing FactContract,
            // are supported by trusted providers, and support required phases (ADMISSION vs TARGET)
            FactContract fc = factContractsById.get(dp.factContractRef().factContractId());
            if (fc == null) {
                unresolvedTerms.add("UNKNOWN_FACT_CONTRACT:" + dp.factContractRef().factContractId());
                continue;
            }
            QueryableResourceProjection qp = dp.queryProjectionRef() != null && queryProjectionsById != null
                    ? queryProjectionsById.get(dp.queryProjectionRef().projectionId())
                    : null;

            for (PolicyFactRequirement req : candidatePolicy.factRequirements()) {
                validateFactReference(
                        req.factPath(),
                        req.requiredInModes(),
                        false,
                        fc,
                        qp,
                        supportedProviderFactPaths,
                        unresolvedTerms
                );
            }

            for (AuthorizationPolicyRule rule : candidatePolicy.rules()) {
                Set<String> conditionVars = new LinkedHashSet<>();
                extractVarPathsFromAst(rule.when().expression(), conditionVars);
                for (String varPath : conditionVars) {
                    validateFactReference(
                            varPath,
                            rule.evaluationModes(),
                            false,
                            fc,
                            qp,
                            supportedProviderFactPaths,
                            unresolvedTerms
                    );
                }
                if (rule.contributions().dataScope() != null && rule.contributions().dataScope().resourceCondition() != null) {
                    Set<String> dataScopeVars = new LinkedHashSet<>();
                    extractVarPathsFromAst(rule.contributions().dataScope().resourceCondition().expression(), dataScopeVars);
                    for (String varPath : dataScopeVars) {
                        validateFactReference(
                                varPath,
                                Set.of(EvaluationMode.SEARCH),
                                true,
                                fc,
                                qp,
                                supportedProviderFactPaths,
                                unresolvedTerms
                        );
                    }
                }
            }
        }

        if (!unresolvedTerms.isEmpty()) {
            throw new IllegalArgumentException("AUTHZ_CANDIDATE_UNRESOLVED_CATALOG_TERMS: " + unresolvedTerms + " (P52/P61)");
        }

        // 4. P53, P55, P63: Compile Rego v1, verify approved digest, execute independent positive+negative corpus, and activate
        return releaseCoordinator.verifyAndActivateRelease(
                releaseId,
                runtimeRevision,
                deploymentNamespace,
                instanceId,
                opaCapabilitiesDigest,
                callerPrincipalId,
                callerAuthorities,
                List.of(candidatePolicy),
                expectedApprovedFingerprintsByPolicyId,
                decisionPointsByKey,
                factContractsById,
                queryProjectionsById,
                verificationCorpus
        );
    }

    private void validateFactReference(
            String factPath,
            Set<EvaluationMode> modes,
            boolean isDataScopeCondition,
            FactContract fc,
            QueryableResourceProjection qp,
            Set<String> supportedProviderFactPaths,
            List<String> unresolvedTerms
    ) {
        FactDescriptor fd = fc.descriptorsByPath().get(factPath);
        if (fd == null) {
            unresolvedTerms.add("AMBIGUOUS_OR_UNKNOWN_FACT:" + factPath);
            return;
        }
        // In DataScope conditions, resource.* facts are pushed down as queryable projection fields
        if (isDataScopeCondition && fd.namespace() == FactSlotNamespace.RESOURCE) {
            if (qp == null || !qp.fieldsByPath().containsKey(factPath)) {
                unresolvedTerms.add("UNSUPPORTED_QUERYABLE_PROJECTION_FACT:" + factPath);
            }
            return;
        }
        if (supportedProviderFactPaths == null || !supportedProviderFactPaths.contains(factPath)) {
            unresolvedTerms.add("UNSUPPORTED_PROVIDER_FACT_BINDING:" + factPath);
        } else if (modes.contains(EvaluationMode.SEARCH)
                && !fd.availableInPhases().contains(ContextEvaluationPhase.ADMISSION)) {
            unresolvedTerms.add("UNSUPPORTED_FACT_PHASE_FOR_SEARCH:" + factPath);
        }
    }

    private void extractVarPathsFromAst(Object astNode, Set<String> collector) {
        if (astNode instanceof Map<?, ?> mapNode) {
            if (mapNode.size() == 1 && mapNode.containsKey("var")) {
                Object varVal = mapNode.get("var");
                if (varVal instanceof String s && !s.isBlank()) {
                    collector.add(s);
                }
                return;
            }
            for (Object child : mapNode.values()) {
                extractVarPathsFromAst(child, collector);
            }
        } else if (astNode instanceof Collection<?> colNode) {
            for (Object item : colNode) {
                extractVarPathsFromAst(item, collector);
            }
        }
    }
}
