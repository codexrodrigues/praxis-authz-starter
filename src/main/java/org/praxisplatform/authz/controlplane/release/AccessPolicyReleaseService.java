package org.praxisplatform.authz.controlplane.release;

import static org.praxisplatform.authz.opa.governance.GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY;
import static org.praxisplatform.config.domain.DomainRuleDefinition.AUTHORIZATION_POLICY_RULE_TYPE;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.praxisplatform.authz.catalog.PapCatalogQueryRequest;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.praxisplatform.authz.contracts.policy.PolicyTargetSpecKind;
import org.praxisplatform.authz.controlplane.GovernedPapAdminOperationsService;
import org.praxisplatform.authz.controlplane.release.AccessPolicyReleaseLedger.Bundle;
import org.praxisplatform.authz.controlplane.release.AccessPolicyReleaseLedger.Deployment;
import org.praxisplatform.authz.controlplane.release.AccessPolicyReleaseLedger.Release;
import org.praxisplatform.authz.controlplane.release.AccessPolicyReleaseLedger.Revision;
import org.praxisplatform.authz.controlplane.release.AccessPolicyReleaseLedger.Scope;
import org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle;
import org.praxisplatform.authz.opa.client.HttpClientOpaTransport;
import org.praxisplatform.authz.opa.compiler.RegoV1PolicyCompiler;
import org.praxisplatform.authz.opa.governance.GovernedOpaReleaseCoordinator;
import org.praxisplatform.authz.opa.governance.PolicyCandidateVerificationCorpusCase;
import org.praxisplatform.authz.opa.revision.OpaEvaluationFailureException;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.config.repository.DomainRuleDefinitionApprovalRepository;
import org.praxisplatform.config.repository.DomainRuleDefinitionRepository;
import org.praxisplatform.config.service.DomainRuleDefinitionFingerprint;
import org.praxisplatform.config.service.DomainRuleGovernancePrincipal;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

public final class AccessPolicyReleaseService {
    public record View(UUID releaseId, UUID definitionId, UUID approvalId, String definitionHash,
                       String state, boolean current, OpaRuntimeHead expectedHead, OpaRuntimeHead observedHead) {
        boolean pending() {
            return "activating".equals(state) || "reverting".equals(state);
        }
    }

    private record Approved(UUID approvalId, String hash, AuthorizationPolicyDefinition policy) {}

    private static final Set<EvaluationMode> TARGET = Set.of(EvaluationMode.TARGET);
    private static final String TENANT_FACT = "subject.tenantId";

    private final AccessPolicyReleaseLedger ledger;
    private final Scope scope;
    private final String opaEnvironmentKey;
    private final TransactionTemplate transactions;
    private final DomainRuleDefinitionRepository definitions;
    private final DomainRuleDefinitionApprovalRepository approvals;
    private final DomainRuleDefinitionFingerprint fingerprint;
    private final ObjectMapper json;
    private final GovernedOpaReleaseCoordinator coordinator;
    private final RegoV1PolicyCompiler compiler;
    private final HttpClientOpaTransport opa;
    private final RuntimeDecisionPointRegistry registry;
    private final GovernedPapAdminOperationsService pap;
    private final AccessPolicyVerificationCorpus corpus;
    private final AuthzHostPolicyBootstrapBundle bootstrap;
    private final Map<String, DecisionPointDescriptor> points;
    private final Revision baseline;

    public AccessPolicyReleaseService(AccessPolicyReleaseSettings settings, String instanceId, JdbcOperations jdbc,
                                     TransactionTemplate transactions, DomainRuleDefinitionRepository definitions,
                                     DomainRuleDefinitionApprovalRepository approvals,
                                     DomainRuleDefinitionFingerprint fingerprint, ObjectMapper json,
                                     GovernedOpaReleaseCoordinator coordinator, RegoV1PolicyCompiler compiler,
                                     HttpClientOpaTransport opa, RuntimeDecisionPointRegistry registry,
                                     GovernedPapAdminOperationsService pap, AccessPolicyVerificationCorpus corpus, AuthzHostPolicyBootstrapBundle bootstrap) {
        this.scope = new Scope(instanceId, settings.tenantId(), settings.environment());
        this.ledger = new AccessPolicyReleaseLedger(jdbc, json, scope);
        this.opaEnvironmentKey = settings.opaEnvironmentKey();
        this.transactions = transactions;
        this.definitions = definitions;
        this.approvals = approvals;
        this.fingerprint = fingerprint;
        this.json = json;
        this.coordinator = coordinator;
        this.compiler = compiler;
        this.opa = opa;
        this.registry = registry;
        this.pap = pap;
        this.corpus = corpus;
        this.bootstrap = bootstrap;
        if (!scope.instanceId().equals(bootstrap.bundleArtifact().runtimeHead().instanceId())) {
            throw new IllegalArgumentException("Access release OPA instance must match the host bootstrap instance");
        }
        Map<String, DecisionPointDescriptor> indexed = new LinkedHashMap<>();
        bootstrap.admissionRecords().forEach(record ->
                indexed.put(record.decisionPoint().identity().pointKey(), record.decisionPoint()));
        this.points = Map.copyOf(indexed);
        Map<String, String> pins = new LinkedHashMap<>();
        for (var unit : bootstrap.bundleArtifact().compiledUnits()) {
            var manifest = unit.unitManifest();
            pins.put(manifest.policyId(), manifest.digestChain().definitionFingerprint());
        }
        var artifact = bootstrap.bundleArtifact();
        String expectedPolicySet = CanonicalDigestCalculator.computeDigest(DigestDomainKind.POLICY_SET_DIGEST,
                opaEnvironmentKey + "|" + artifact.runtimeRelease().compositionManifest().compositionDigest());
        if (!expectedPolicySet.equals(artifact.runtimeHead().policySetDigest())) {
            throw new IllegalArgumentException("OPA environment must match the bootstrap policy set");
        }
        this.baseline = new Revision(artifact.runtimeHead(), artifact.bundleArchiveBytes(),
                bootstrap.policies(), Map.copyOf(pins), json.nullNode());
    }

    public View publish(UUID definitionId, DomainRuleGovernancePrincipal principal,
                        Set<String> services, Set<String> authorities) {
        requireScope(principal);
        return locked(principal, () -> {
            var approved = approved(definitionId, principal, services);
            var deployment = ledger.deployment().orElse(null);
            if (deployment != null && deployment.pending()) {
                throw conflict("Confirm the pending OPA deployment before publishing another release.");
            }
            var candidate = approved.policy();
            validateAccess(candidate, principal, services, authorities);
            Revision current = deployment == null ? baseline : deployment.revision();
            requireServing(current.head());
            var previous = ledger.findPublished(definitionId, approved.hash(), current.head());
            if (previous.isPresent()) {
                return view(previous.get(), deployment);
            }

            var currentPolicies = new LinkedHashMap<String, AuthorizationPolicyDefinition>();
            current.policies().forEach(policy -> currentPolicies.put(policy.policyId(), policy));
            if (currentPolicies.containsKey(candidate.policyId())) {
                throw conflict("This policy identifier is already present in the serving composition.");
            }

            var pins = new LinkedHashMap<>(current.pins());
            var contracts = bootstrap.coordinates();
            UUID id = UUID.randomUUID();
            try {
                var compiled = compiler.compileUnit(candidate, points,
                        contracts.factContractsById(), contracts.queryProjectionsByRef());
                pins.put(candidate.policyId(), compiled.unitManifest().digestChain().definitionFingerprint());
                currentPolicies.put(candidate.policyId(), candidate);
                var cases = corpus.forApprovedChange(candidate, approved.hash());
                validateCorpus(candidate, cases);
                long next = Math.addExact(current.head().activationRevision(), 1);
                Revision forward = prepare(id + "-forward", next, principal, List.copyOf(currentPolicies.values()),
                        pins, cases.activation());
                Revision rollback = prepare(id + "-rollback", Math.addExact(next, 1), principal,
                        current.policies(), current.pins(), cases.restoration());
                var release = new Release(id, definitionId, approved.approvalId(), approved.hash(),
                        bootstrap.serviceKey(), "published", current.head(), forward, rollback, null, null);
                ledger.insert(release, principal.actorRef());
                return view(release, deployment);
            } catch (IllegalArgumentException | IllegalStateException e) {
                throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                        "The approved policy and independent corpus did not produce a verified release.", e);
            }
        });
    }

    public View read(UUID id, DomainRuleGovernancePrincipal principal, Set<String> services) {
        requireScope(principal);
        return locked(principal, () -> view(visible(id, services), ledger.deployment().orElse(null)));
    }

    public View request(UUID id, boolean restoring, DomainRuleGovernancePrincipal principal,
                        Set<String> services, Set<String> authorities) {
        requireScope(principal);
        View requested = locked(principal, () -> {
            var release = visible(id, services);
            var deployment = ledger.deployment().orElse(null);
            boolean selected = isSelected(release, deployment);
            String pending = restoring ? "reverting" : "activating";
            String done = restoring ? "reverted" : "active";
            if (selected && (pending.equals(release.state()) || done.equals(release.state()))) {
                return view(release, deployment);
            }
            boolean cancelForward = restoring && selected && "activating".equals(release.state());
            if (deployment != null && deployment.pending() && !cancelForward) {
                throw conflict("An OPA deployment is already pending.");
            }
            if (restoring) {
                if (!selected || (!cancelForward && !"active".equals(release.state()))) {
                    throw conflict("Only the current activation or active release can be reverted.");
                }
                // An unconfirmed forward may have failed to load. Its verified restoration remains deployable.
                if (!cancelForward) {
                    requireServing(release.forward().head());
                }
            } else {
                if (!"published".equals(release.state())) {
                    throw conflict("Only a published release can be activated.");
                }
                var current = deployment == null ? baseline.head() : deployment.revision().head();
                if (!release.basedOn().equals(current)) {
                    throw conflict("The runtime changed after publication. Prepare the approved definition again.");
                }
                var approved = approved(release.definitionId(), principal, services);
                if (!release.definitionHash().equals(approved.hash())
                        || !release.approvalId().equals(approved.approvalId())) {
                    throw conflict("The approval changed after publication.");
                }
                validateAccess(approved.policy(), principal, services, authorities);
                requireServing(current);
            }
            ledger.request(release, restoring, principal.actorRef());
            return view(visible(id, services), ledger.deployment().orElseThrow());
        });
        if (!requested.pending()) {
            return requested;
        }
        OpaRuntimeHead observed;
        try {
            observed = opa.confirmRuntimeHead(requested.expectedHead());
        } catch (OpaEvaluationFailureException e) {
            // The durable deployment remains pending; only an exact OPA observation advances it.
            return read(id, principal, services);
        }
        return locked(principal, () -> {
            var release = visible(id, services);
            var deployment = ledger.deployment().orElseThrow();
            if (isSelected(release, deployment) && deployment.pending()
                    && requested.state().equals(release.state())
                    && observed.equals(deployment.revision().head())) {
                ledger.observe(release, restoring, observed);
                release = visible(id, services);
            }
            return view(release, ledger.deployment().orElse(null));
        });
    }

    Bundle bundle() {
        return ledger.bundle().orElseGet(() -> new Bundle(baseline.archive(), baseline.head().headEtag()));
    }

    private Revision prepare(String revision, long activation, DomainRuleGovernancePrincipal principal,
                             List<AuthorizationPolicyDefinition> policies, Map<String, String> pins,
                             List<PolicyCandidateVerificationCorpusCase> cases) {
        var contracts = bootstrap.coordinates();
        var prepared = coordinator.prepareVerifiedRelease(revision, revision, activation,
                opaEnvironmentKey, scope.instanceId(),
                baseline.head().opaCapabilitiesDigest(), principal.actorRef(), Set.of(REQUIRED_ADMIN_AUTHORITY),
                policies, pins, points, contracts.factContractsById(), contracts.queryProjectionsByRef(), cases);
        var artifact = prepared.bundleArtifact();
        return new Revision(artifact.runtimeHead(), artifact.bundleArchiveBytes(), policies, pins,
                json.valueToTree(prepared.activationReceipt()));
    }

    private Approved approved(UUID definitionId, DomainRuleGovernancePrincipal principal, Set<String> services) {
        var definition = definitions.findById(definitionId).filter(item ->
                principal.tenantId().equals(item.getTenantId()) && principal.environment().equals(item.getEnvironment())
                        && AUTHORIZATION_POLICY_RULE_TYPE.equals(item.getRuleType())
                        && bootstrap.serviceKey().equals(item.getServiceKey()) && services.contains(item.getServiceKey()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Authorization definition unavailable."));
        if (!"approved".equals(definition.getStatus()) || !"authenticated".equals(definition.getCreatedByType())
                || definition.getCreatedBy() == null || definition.getCreatedBy().isBlank()) {
            throw conflict("The authorization definition requires an independent approval before release.");
        }
        String hash = fingerprint.sha256(definition);
        var approval = approvals.findByTenantIdAndEnvironmentAndDefinitionIdAndDefinitionHashOrderByApprovedAtAsc(
                        principal.tenantId(), principal.environment(), definitionId, hash)
                .stream().filter(item -> "RULE_DEFINITION_APPROVER".equals(item.getRole())
                        && item.getActorRef() != null && !item.getActorRef().isBlank()
                        && !definition.getCreatedBy().equals(item.getActorRef()))
                .findFirst().orElseThrow(() -> conflict("No independent approval matches this definition revision."));
        try {
            return new Approved(approval.getId(), hash,
                    json.readValue(definition.getDefinition(), AuthorizationPolicyDefinition.class));
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                    "The approved authorization policy is invalid.", e);
        }
    }

    private void validateAccess(AuthorizationPolicyDefinition policy, DomainRuleGovernancePrincipal principal,
                                Set<String> services, Set<String> authorities) {
        List<DecisionPointDescriptor> admitted;
        try {
            admitted = pap.querySemanticCatalog(new PapCatalogQueryRequest(principal.actorRef(), authorities, services,
                    bootstrap.serviceKey())).admittedDecisionPoints();
        } catch (SecurityException e) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "The operator has no PAP catalog authority.");
        }
        if (policy.dualScopeDelegation() != null || policy.factRequirements().stream()
                .noneMatch(fact -> TENANT_FACT.equals(fact.factPath()) && fact.requiredInModes().containsAll(TARGET))) {
            throw invalidAccess();
        }
        Set<String> referenced = new LinkedHashSet<>();
        policy.factRequirements().forEach(fact -> referenced.add(fact.factPath()));
        policy.rules().forEach(rule -> collectConditionFacts(rule.when().expression(), referenced));
        for (var target : policy.targets()) {
            if (target.kind() != PolicyTargetSpecKind.EXACT || !TARGET.equals(target.evaluationModes())) {
                throw invalidAccess();
            }
            var point = registry.findRegisteredPoint(target.pointKey()).orElse(null);
            if (point == null || !bootstrap.serviceKey().equals(point.admissionRecord().serviceKey())
                    || !point.decisionPoint().equals(points.get(target.pointKey()))
                    || !admitted.contains(point.decisionPoint())
                    || !target.expectedDescriptorDigest().equals(point.decisionPoint().descriptorDigest())
                    || !point.decisionPoint().evaluationModes().contains(EvaluationMode.TARGET)
                    || !point.decisionPoint().supportedCapabilities().contains(EnforcementCapability.ACCESS)
                    || referenced.stream().anyMatch(path -> point.factContract().findFact(path)
                            .filter(fact -> fact.availableInPhases().contains(ContextEvaluationPhase.TARGET)).isEmpty())) {
                throw invalidAccess();
            }
        }
        for (var rule : policy.rules()) {
            var effects = rule.contributions();
            if (!TARGET.equals(rule.evaluationModes()) || effects.access() == null || effects.dataScope() != null
                    || !effects.fieldUse().isEmpty() || !effects.fieldWrite().isEmpty() || !effects.mask().isEmpty()
                    || !rule.obligations().isEmpty() || !enforcesTenant(rule.when().expression(), principal.tenantId())) {
                throw invalidAccess();
            }
        }
    }

    private void collectConditionFacts(Object term, Set<String> facts) {
        if (term instanceof Map<?, ?> node) {
            if (node.get("var") instanceof String path) {
                facts.add(path);
            }
            node.values().forEach(value -> collectConditionFacts(value, facts));
        } else if (term instanceof List<?> children) {
            children.forEach(child -> collectConditionFacts(child, facts));
        }
    }

    private void validateCorpus(AuthorizationPolicyDefinition policy, AccessPolicyVerificationCorpus.Cases cases) {
        if (Stream.concat(cases.activation().stream(), cases.restoration().stream())
                .anyMatch(example -> !example.isPositiveCase() && !isAccessRejection(example))) {
            throw new IllegalArgumentException("A verification case must assert an access decision");
        }
        Set<String> reasons = policy.rules().stream().map(rule -> rule.contributions().reasonCode())
                .collect(Collectors.toUnmodifiableSet());
        for (var target : policy.targets()) {
            DecisionPointDescriptor point = points.get(target.pointKey());
            var forward = cases.activation().stream().filter(example -> coversPoint(example, point)).toList();
            var restored = cases.restoration().stream().filter(example -> coversPoint(example, point)).toList();
            if (!coversAllowAndRejection(forward) || !coversAllowAndRejection(restored)
                    || forward.stream().noneMatch(example -> example.expectedReasonCode() != null && reasons.contains(example.expectedReasonCode())
                    && restored.stream().anyMatch(previous -> previous.inputProjection().equals(example.inputProjection())
                    && Objects.equals(previous.writeIntent(), example.writeIntent())
                    && previous.isPositiveCase() != example.isPositiveCase()))) {
                throw new IllegalArgumentException("Each affected point requires an independent ACCESS corpus for both revisions");
            }
        }
    }

    private boolean coversPoint(PolicyCandidateVerificationCorpusCase example, DecisionPointDescriptor point) {
        return example.evaluationMode() == EvaluationMode.TARGET
                && point.identity().pointKey().equals(example.inputProjection().decisionPointKey())
                && point.factContractRef().factContractDigest().equals(example.inputProjection().factContractDigest());
    }

    private boolean coversAllowAndRejection(List<PolicyCandidateVerificationCorpusCase> cases) {
        return cases.stream().anyMatch(PolicyCandidateVerificationCorpusCase::isPositiveCase)
                && cases.stream().anyMatch(this::isAccessRejection);
    }

    private boolean isAccessRejection(PolicyCandidateVerificationCorpusCase example) {
        return example.expectedGateOutcome() == GateOutcome.DENY
                || example.expectedGateOutcome() == GateOutcome.NOT_APPLICABLE;
    }

    private boolean enforcesTenant(Object condition, String tenantId) {
        if (!(condition instanceof Map<?, ?> expression) || expression.size() != 1) {
            return false;
        }
        var tenant = Map.of("var", TENANT_FACT);
        if (expression.get("==") instanceof List<?> operands) {
            return operands.equals(List.of(tenant, tenantId)) || operands.equals(List.of(tenantId, tenant));
        }
        return expression.get("and") instanceof List<?> terms
                && terms.stream().anyMatch(term -> enforcesTenant(term, tenantId));
    }

    private ResponseStatusException invalidAccess() {
        return new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY,
                "Release requires ACCESS rules in TARGET mode, exact service targets, and a mandatory tenant condition.");
    }

    private void requireScope(DomainRuleGovernancePrincipal principal) {
        if (!scope.tenantId().equals(principal.tenantId()) || !scope.environment().equals(principal.environment())
                || principal.actorRef() == null || principal.actorRef().isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Principal is outside the authorization deployment scope.");
        }
    }

    private void requireServing(OpaRuntimeHead expected) {
        try {
            opa.confirmRuntimeHead(expected);
        } catch (OpaEvaluationFailureException e) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "OPA has not confirmed the expected current runtime revision.", e);
        }
    }

    private Release visible(UUID id, Set<String> services) {
        return ledger.find(id).filter(release -> services.contains(release.serviceKey()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Authorization release unavailable."));
    }

    private boolean isSelected(Release release, Deployment deployment) {
        return deployment != null && release.id().equals(deployment.release().id());
    }

    private View view(Release release, Deployment deployment) {
        return new View(release.id(), release.definitionId(), release.approvalId(), release.definitionHash(),
                release.state(), isSelected(release, deployment),
                release.restoring() ? release.rollback().head() : release.forward().head(),
                release.restoring() ? release.rollbackObserved() : release.activationObserved());
    }

    private <T> T locked(DomainRuleGovernancePrincipal principal, Supplier<T> operation) {
        return transactions.execute(status -> {
            definitions.lockLifecycleScope(principal);
            return operation.get();
        });
    }

    private ResponseStatusException conflict(String description) {
        return new ResponseStatusException(HttpStatus.CONFLICT, description);
    }
}
