package org.praxisplatform.authz.host.metadata;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteViolationException;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.uischema.bulk.BulkDomainResourceAdapter;
import org.praxisplatform.uischema.bulk.BulkEditableFields;
import org.praxisplatform.uischema.bulk.BulkFieldChange;
import org.praxisplatform.uischema.bulk.BulkFieldChangeValidationException;
import org.praxisplatform.uischema.bulk.BulkMode;
import org.praxisplatform.uischema.concurrency.ResourceVersionPreconditionException;
import org.praxisplatform.uischema.service.base.ResourceMutationContext;
import jakarta.validation.ConstraintViolationException;

/**
 * Governed decorator for {@code praxis-metadata-starter}'s {@link BulkDomainResourceAdapter}
 * bridging {@code AbstractBaseResourceService.bulkDomainAdapter(...)} and
 * {@code selectBulkIdentities(...)} to the 15-step authorization pipeline
 * ({@code Fase P10.5}, {@code P05}, {@code P13}, {@code P14}, {@code P15}, {@code P18}, {@code P19}, {@code P34}).
 *
 * <p>Responsibilities:</p>
 * <ul>
 *   <li><b>Scoped Cohort Target Selection ({@link #selectBulkIdentities}):</b> delegates to
 *       {@code AbstractBaseResourceService.selectBulkIdentities} (which intersects {@code hardScope}
 *       and OPA {@code DataScopePlan} via {@code resolveResourceFilterAccessScope()}) and cleans up
 *       thread-local query state in {@code finally};</li>
 *   <li><b>Non-Persistent Proposal Evaluation ({@link #evaluate}):</b> executes {@code STEP_11}
 *       ({@code WriteIntent} + {@code DualScopeDelegationSpec}) and {@code STEP_12} domain validation
 *       on detached candidates without writing premature {@code BEFORE_COMMIT_OUTBOX} entries and
 *       clears transient mutation thread-locals after each candidate;</li>
 *   <li><b>2-Phase Proposal/Confirmation Grant &amp; Anti-Confused-Deputy ({@link GovernedBulkProposalGrant}):</b>
 *       verifies at confirmation time that {@code confirmPrincipalId == proposalPrincipalId},
 *       {@code confirmTenantId == proposalTenantId}, and {@code activePolicySetDigest == pinnedPolicySetDigest},
 *       preventing cross-actor proposal hijacking ({@code P15}, {@code P34}) and stale-policy execution ({@code P18});</li>
 *   <li><b>Per-Item Atomic Outbox Fulfillment ({@link #update}):</b> because
 *       {@code BulkDomainResourceAdapter.update(...)} returns {@code void} without invoking
 *       {@code ResourceMapper.toResponse(saved)} on its fast path, this decorator deterministically
 *       fulfills {@code BEFORE_COMMIT_OUTBOX} obligations at {@code STEP_14} for each admitted item
 *       and resets thread-local state before the next target in the cohort.</li>
 * </ul>
 *
 * @param <ID> resource identifier type
 * @param <F> filter DTO type
 */
public final class AuthzGovernedBulkDomainResourceAdapter<ID, F> implements BulkDomainResourceAdapter<ID, F> {

    /**
     * Immutable 2-phase bulk proposal grant pinning the proposing actor, tenant, policy digest,
     * batch mode, changes, and admitted target versions ({@code P15}, {@code P18}, {@code P34}).
     *
     * @param proposalId unique proposal identifier
     * @param proposalPrincipalId authenticated principal that evaluated the proposal
     * @param proposalTenantId authenticated tenant of the proposal
     * @param pinnedPolicySetDigest active policy set digest observed during proposal evaluation
     * @param pinnedRuntimeRevision active OPA runtime revision observed during proposal evaluation
     * @param batchMode {@link BatchAuthorizationMode#REJECT_ALL} or {@link BatchAuthorizationMode#PER_ITEM}
     * @param changes structural bulk field changes evaluated in the proposal
     * @param editableFields compiled {@link BulkEditableFields} allowlist
     * @param candidatesByTargetId map of admitted target IDs to their evaluated {@link Candidate}s
     * @param <ID> resource identifier type
     */
    public record GovernedBulkProposalGrant<ID>(
            String proposalId,
            String proposalPrincipalId,
            String proposalTenantId,
            String pinnedPolicySetDigest,
            String pinnedRuntimeRevision,
            BatchAuthorizationMode batchMode,
            List<BulkFieldChange> changes,
            BulkEditableFields editableFields,
            Map<ID, Candidate> candidatesByTargetId
    ) {
        /** Compact constructor enforcing non-null fields and defensive copies. */
        public GovernedBulkProposalGrant {
            Objects.requireNonNull(proposalId, "proposalId is required");
            Objects.requireNonNull(proposalPrincipalId, "proposalPrincipalId is required");
            Objects.requireNonNull(proposalTenantId, "proposalTenantId is required");
            Objects.requireNonNull(pinnedPolicySetDigest, "pinnedPolicySetDigest is required");
            Objects.requireNonNull(pinnedRuntimeRevision, "pinnedRuntimeRevision is required");
            Objects.requireNonNull(batchMode, "batchMode is required");
            changes = changes == null ? List.of() : List.copyOf(changes);
            Objects.requireNonNull(editableFields, "editableFields is required");
            candidatesByTargetId = candidatesByTargetId == null ? Map.of() : Map.copyOf(candidatesByTargetId);
        }
    }

    /**
     * Per-item execution outcome for {@link BatchAuthorizationMode#PER_ITEM} or
     * {@link BatchAuthorizationMode#REJECT_ALL} bulk confirmation ({@code P15}).
     *
     * @param targetId resource identifier
     * @param committed {@code true} when the item was updated and its outbox entry was recorded
     * @param certifiedVersion new certified ETag version when {@code committed == true}
     * @param reasonCode machine-readable rejection reason when {@code !committed}
     * @param <ID> resource identifier type
     */
    public record BulkCohortItemOutcome<ID>(
            ID targetId,
            boolean committed,
            String certifiedVersion,
            String reasonCode
    ) {}

    private final BulkDomainResourceAdapter<ID, F> delegate;
    private final AuthzGovernedResourceServiceSupport serviceSupport;
    private final IntrospectedDtoGovernanceContract governanceContract;
    private final AuthzResourceGovernanceSpec<?> governanceSpec;

    /**
     * Creates a governed decorator around a {@link BulkDomainResourceAdapter}.
     *
     * @param delegate underlying adapter created by {@code AbstractBaseResourceService.bulkDomainAdapter(...)}
     * @param serviceSupport governed resource service support bridge
     */
    public AuthzGovernedBulkDomainResourceAdapter(
            BulkDomainResourceAdapter<ID, F> delegate,
            AuthzGovernedResourceServiceSupport serviceSupport
    ) {
        this(delegate, serviceSupport, null, null);
    }

    /**
     * Creates a governed decorator around a {@link BulkDomainResourceAdapter} with an explicit
     * {@link IntrospectedDtoGovernanceContract} for masking {@code Candidate.facts()} during
     * proposal evaluation ({@code P10.6-R01}, {@code P11}, {@code P12}, {@code P15}, {@code P50}).
     *
     * @param delegate underlying adapter created by {@code AbstractBaseResourceService.bulkDomainAdapter(...)}
     * @param serviceSupport governed resource service support bridge
     * @param governanceContract optional introspected DTO governance contract
     */
    public AuthzGovernedBulkDomainResourceAdapter(
            BulkDomainResourceAdapter<ID, F> delegate,
            AuthzGovernedResourceServiceSupport serviceSupport,
            IntrospectedDtoGovernanceContract governanceContract
    ) {
        this(delegate, serviceSupport, governanceContract, null);
    }

    /**
     * Creates a governed decorator around a {@link BulkDomainResourceAdapter} with an explicit
     * {@link IntrospectedDtoGovernanceContract} and optional {@link AuthzResourceGovernanceSpec}
     * ({@code Fase P10.20-A}).
     */
    public AuthzGovernedBulkDomainResourceAdapter(
            BulkDomainResourceAdapter<ID, F> delegate,
            AuthzGovernedResourceServiceSupport serviceSupport,
            IntrospectedDtoGovernanceContract governanceContract,
            AuthzResourceGovernanceSpec<?> governanceSpec
    ) {
        this.delegate = Objects.requireNonNull(delegate, "delegate is required");
        this.serviceSupport = Objects.requireNonNull(serviceSupport, "serviceSupport is required");
        this.governanceContract = governanceContract;
        this.governanceSpec = governanceSpec;
    }

    @Override
    public F readFilter(JsonNode normalizedFilter) {
        return delegate.readFilter(normalizedFilter);
    }

    @Override
    public List<ID> selectBulkIdentities(F filter, Collection<ID> included, Collection<ID> excluded, int maxTargets) {
        Map<FieldUseCategory, Set<String>> extractedUses = serviceSupport.dtoIntrospector().extractQueryFieldUses(
                filter,
                null,
                governanceContract,
                governanceSpec
        );
        try {
            return serviceSupport.executeWithExtractedQueryFieldUses(
                    extractedUses,
                    () -> delegate.selectBulkIdentities(filter, included, excluded, maxTargets)
            );
        } finally {
            serviceSupport.clearTransientRequestContexts();
        }
    }

    @Override
    public String currentVersion(ID id) {
        try {
            return delegate.currentVersion(id);
        } finally {
            serviceSupport.clearTransientRequestContexts();
        }
    }

    @Override
    public Candidate evaluate(
            ID id,
            String expectedVersion,
            List<BulkFieldChange> changes,
            ResourceMutationContext context,
            BulkEditableFields fields
    ) {
        try {
            Candidate rawCandidate = delegate.evaluate(id, expectedVersion, changes, context, fields);
            if (rawCandidate == null) {
                return null;
            }
            // Sanitize/mask Candidate.facts() so proposal previews never leak raw restricted
            // values (e.g., cidCodigo), while preserving raw Candidate.plan() for confirmation (P10.6-R01).
            JsonNode sanitizedFacts = serviceSupport.sanitizeBulkCandidateFactsNode(
                    rawCandidate.facts(),
                    governanceContract
            );
            return new Candidate(rawCandidate.observedVersion(), sanitizedFacts, rawCandidate.plan());
        } finally {
            // Evaluation operates on a detached snapshot and never persists or discloses a response DTO;
            // always clean up transient query/mutation contexts so no dry-run state leaks.
            serviceSupport.clearTransientRequestContexts();
        }
    }

    @Override
    public void update(
            ID id,
            String expectedVersion,
            JsonNode candidate,
            ResourceMutationContext context
    ) {
        try {
            delegate.update(id, expectedVersion, candidate, context);
            // In AbstractBaseResourceService.bulkDomainAdapter, the prepared confirmation fast path
            // invokes afterUpdate(id, saved, dto) without calling getResourceMapper().toResponse(saved).
            // Fulfill the pending BEFORE_COMMIT_OUTBOX obligation here if not yet consumed by toResponse.
            serviceSupport.completePendingMutationOutboxIfNotDisclosed();
        } finally {
            serviceSupport.clearTransientRequestContexts();
        }
    }

    @Override
    public void discardEvaluationState() {
        try {
            delegate.discardEvaluationState();
        } finally {
            serviceSupport.clearTransientRequestContexts();
        }
    }

    /**
     * Evaluates a 2-phase bulk proposal across the given target IDs and issues an immutable
     * {@link GovernedBulkProposalGrant} bound to the caller's principal, tenant, and active
     * policy digest ({@code P15}, {@code P18}, {@code P34}).
     *
     * @param proposalId unique proposal identifier
     * @param proposalPrincipalId authenticated principal requesting the proposal
     * @param proposalTenantId authenticated tenant
     * @param pinnedPolicySetDigest current active policy set digest
     * @param pinnedRuntimeRevision current active OPA runtime revision
     * @param batchMode {@link BatchAuthorizationMode#REJECT_ALL} or {@link BatchAuthorizationMode#PER_ITEM}
     * @param mode {@link BulkMode#UNIFORM_UPDATE} or {@link BulkMode#PER_ITEM_UPDATE}
     * @param targetIds target resource identifiers (typically obtained via {@link #selectBulkIdentities})
     * @param changes bulk field changes to apply
     * @param editableFields compiled {@link BulkEditableFields} allowlist
     * @param referenceInstant reference instant for the proposal evaluation
     * @return immutable {@link GovernedBulkProposalGrant}
     */
    public GovernedBulkProposalGrant<ID> evaluateAndIssueProposalGrant(
            String proposalId,
            String proposalPrincipalId,
            String proposalTenantId,
            String pinnedPolicySetDigest,
            String pinnedRuntimeRevision,
            BatchAuthorizationMode batchMode,
            BulkMode mode,
            List<ID> targetIds,
            List<BulkFieldChange> changes,
            BulkEditableFields editableFields,
            Instant referenceInstant
    ) {
        Objects.requireNonNull(targetIds, "targetIds is required");
        ResourceMutationContext evalCtx = ResourceMutationContext.bulkEvaluation(mode, referenceInstant);
        Map<ID, Candidate> candidates = new LinkedHashMap<>();
        try {
            for (ID id : targetIds) {
                String expectedVersion = currentVersion(id);
                Candidate candidate = evaluate(id, expectedVersion, changes, evalCtx, editableFields);
                candidates.put(id, candidate);
            }
        } finally {
            discardEvaluationState();
        }
        return new GovernedBulkProposalGrant<>(
                proposalId,
                proposalPrincipalId,
                proposalTenantId,
                pinnedPolicySetDigest,
                pinnedRuntimeRevision,
                batchMode,
                changes,
                editableFields,
                candidates
        );
    }

    /**
     * Confirms and executes a previously issued {@link GovernedBulkProposalGrant}, enforcing:
     * <ol>
     *   <li><b>Anti-Confused-Deputy ({@code P15}, {@code P34}):</b> {@code confirmPrincipalId} and
     *       {@code confirmTenantId} must match the proposal's principal and tenant;</li>
     *   <li><b>Policy Digest Continuity ({@code P15}, {@code P18}):</b> {@code activePolicySetDigest}
     *       must match {@code grant.pinnedPolicySetDigest()};</li>
     *   <li><b>Live Locked Revalidation &amp; Execution:</b> for each item, runs locked
     *       {@code Stage.CONFIRMATION} evaluation + {@link #update}, honoring
     *       {@link BatchAuthorizationMode#REJECT_ALL} vs {@link BatchAuthorizationMode#PER_ITEM}.</li>
     * </ol>
     *
     * @param grant proposal grant issued by {@link #evaluateAndIssueProposalGrant}
     * @param confirmPrincipalId authenticated principal confirming the proposal
     * @param confirmTenantId authenticated tenant confirming the proposal
     * @param activePolicySetDigest active policy set digest at confirmation time
     * @param mode {@link BulkMode#UNIFORM_UPDATE} or {@link BulkMode#PER_ITEM_UPDATE}
     * @param referenceInstant confirmation reference instant
     * @return per-item outcomes in cohort order
     */
    public List<BulkCohortItemOutcome<ID>> confirmProposalGrant(
            GovernedBulkProposalGrant<ID> grant,
            String confirmPrincipalId,
            String confirmTenantId,
            String activePolicySetDigest,
            BulkMode mode,
            Instant referenceInstant
    ) {
        Objects.requireNonNull(grant, "grant is required");
        if (!Objects.equals(grant.proposalPrincipalId(), confirmPrincipalId)
                || !Objects.equals(grant.proposalTenantId(), confirmTenantId)) {
            throw new SecurityException("AUTHZ_BULK_CONFUSED_DEPUTY_DENIED: Bulk proposal '"
                    + grant.proposalId() + "' owned by '" + grant.proposalPrincipalId() + "@"
                    + grant.proposalTenantId() + "' cannot be confirmed by '"
                    + confirmPrincipalId + "@" + confirmTenantId + "' (P15/P34)");
        }
        if (!Objects.equals(grant.pinnedPolicySetDigest(), activePolicySetDigest)) {
            throw new SecurityException("AUTHZ_BULK_POLICY_REVOKED_OR_ROTATED: Bulk proposal '"
                    + grant.proposalId() + "' pinned digest '" + grant.pinnedPolicySetDigest()
                    + "' no longer matches active digest '" + activePolicySetDigest + "' (P15/P18)");
        }

        ResourceMutationContext confirmCtx = ResourceMutationContext.bulkConfirmation(mode, referenceInstant);
        List<BulkCohortItemOutcome<ID>> outcomes = new ArrayList<>(grant.candidatesByTargetId().size());

        for (Map.Entry<ID, Candidate> entry : grant.candidatesByTargetId().entrySet()) {
            ID targetId = entry.getKey();
            Candidate proposedCandidate = entry.getValue();
            try {
                Candidate revalidated = evaluate(
                        targetId,
                        proposedCandidate.observedVersion(),
                        grant.changes(),
                        confirmCtx,
                        grant.editableFields()
                );
                update(targetId, revalidated.observedVersion(), revalidated.plan(), confirmCtx);
                String newVersion = currentVersion(targetId);
                outcomes.add(new BulkCohortItemOutcome<>(targetId, true, newVersion, null));
            } catch (FieldWriteViolationException ex) {
                discardEvaluationState();
                if (grant.batchMode() == BatchAuthorizationMode.REJECT_ALL) {
                    throw ex;
                }
                outcomes.add(new BulkCohortItemOutcome<>(targetId, false, null, ex.getReasonCode()));
            } catch (SecurityException ex) {
                discardEvaluationState();
                if (grant.batchMode() == BatchAuthorizationMode.REJECT_ALL) {
                    throw ex;
                }
                outcomes.add(new BulkCohortItemOutcome<>(targetId, false, null, "AUTHZ_ITEM_SECURITY_DENIED"));
            } catch (ResourceVersionPreconditionException ex) {
                discardEvaluationState();
                if (grant.batchMode() == BatchAuthorizationMode.REJECT_ALL) {
                    throw ex;
                }
                outcomes.add(new BulkCohortItemOutcome<>(targetId, false, null, "VERSION_CONFLICT"));
            } catch (ConstraintViolationException | BulkFieldChangeValidationException ex) {
                discardEvaluationState();
                if (grant.batchMode() == BatchAuthorizationMode.REJECT_ALL) {
                    throw ex;
                }
                outcomes.add(new BulkCohortItemOutcome<>(targetId, false, null, "DOMAIN_VALIDATION_FAILED"));
            } catch (RuntimeException ex) {
                discardEvaluationState();
                throw ex;
            }
        }
        return List.copyOf(outcomes);
    }
}
