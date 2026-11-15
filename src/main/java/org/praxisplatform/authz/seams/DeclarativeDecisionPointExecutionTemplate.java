package org.praxisplatform.authz.seams;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import org.praxisplatform.authz.catalog.AdmittedInvocationChannel;
import org.praxisplatform.authz.channel.GovernedChannelInvocationExecutor;
import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.context.EvaluationContextSnapshot;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.enforcement.pipeline.NormalizedEnforcementOutcome;
import org.praxisplatform.authz.export.GovernedCollectionExportGuard.ExportFormat;
import org.praxisplatform.authz.export.GovernedCollectionExportGuard.SanitizedExportArtifact;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.AiGovernanceMetadataView;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.SanitizedAiToolProjection;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.AuthorizedPreMutationContext;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.AuthorizedQueryScopeContext;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.WorkerDelegationToken;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry.RegisteredDecisionPointContext;

/**
 * Declarative execution façade that resolves {@code DecisionPointDescriptor}, {@code FactContract},
 * {@code DualScopeDelegationSpec}, and mandatory scope anchors by {@code decisionPointKey} from
 * {@link RuntimeDecisionPointRegistry} and delegates to {@link MetadataResourceAuthorizationSeam},
 * {@link GovernedChannelInvocationExecutor}, and {@link GovernedExportAndAiToolAuthorizationSeam}
 * ({@code P11}, {@code P20}, {@code P34}, {@code P41}, {@code P42}, {@code P60}, {@code P62}).
 *
 * <p>Eliminates repetitive descriptor/contract wiring in host resource services while enforcing
 * fail-closed admission if an operation attempts to execute an unregistered {@code pointKey}.</p>
 */
public final class DeclarativeDecisionPointExecutionTemplate {

    private final RuntimeDecisionPointRegistry registry;
    private final MetadataResourceAuthorizationSeam seam;
    private final GovernedChannelInvocationExecutor channelExecutor;
    private final GovernedExportAndAiToolAuthorizationSeam exportAndAiSeam;

    public DeclarativeDecisionPointExecutionTemplate(
            RuntimeDecisionPointRegistry registry,
            MetadataResourceAuthorizationSeam seam,
            GovernedChannelInvocationExecutor channelExecutor
    ) {
        this(registry, seam, channelExecutor, null);
    }

    public DeclarativeDecisionPointExecutionTemplate(
            RuntimeDecisionPointRegistry registry,
            MetadataResourceAuthorizationSeam seam,
            GovernedChannelInvocationExecutor channelExecutor,
            GovernedExportAndAiToolAuthorizationSeam exportAndAiSeam
    ) {
        this.registry = Objects.requireNonNull(registry, "registry is required");
        this.seam = Objects.requireNonNull(seam, "seam is required");
        this.channelExecutor = Objects.requireNonNull(channelExecutor, "channelExecutor is required");
        this.exportAndAiSeam = exportAndAiSeam;
    }

    /**
     * Declaratively authorizes and compiles a JPA query scope by {@code decisionPointKey} alone.
     */
    public AuthorizedQueryScopeContext authorizeSearchByPointKey(
            String decisionPointKey,
            Set<String> incomingHeaderNames,
            Map<String, Object> trustedSubjectFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses,
            Map<FieldUseCategory, Set<String>> requestedQueryFieldUses,
            List<FieldUseEffectDirective> staticFieldUseDirectives,
            JpaDataScopeAdapter jpaDataScopeAdapter,
            String hardScopeJpql,
            Map<String, Object> hardScopeParameters,
            Predicate<Map<String, ResolvedFactValue>> targetParityOracle
    ) {
        RegisteredDecisionPointContext registered = registry.requireRegisteredPoint(decisionPointKey);
        if (!registered.decisionPoint().evaluationModes().contains(EvaluationMode.SEARCH)) {
            throw new SecurityException("AUTHZ_EVALUATION_MODE_NOT_ADMITTED: Decision point '"
                    + decisionPointKey + "' does not admit EvaluationMode.SEARCH (CC05/P20)");
        }
        return seam.authorizeAndCompileJpaQueryScope(
                registered.decisionPoint(),
                registered.factContract().factContractDigest(),
                incomingHeaderNames,
                trustedSubjectFacts,
                trustedFactStatuses,
                requestedQueryFieldUses,
                staticFieldUseDirectives,
                jpaDataScopeAdapter,
                hardScopeJpql,
                hardScopeParameters,
                targetParityOracle
        );
    }

    /**
     * Declaratively projects and masks query result rows into detached DTO projections ({@code P09}, {@code P12}, {@code P40}).
     */
    public List<DetachedDtoMaskingResult> projectAndMaskSearchResults(
            AuthorizedQueryScopeContext queryContext,
            List<?> rawEntities,
            Collection<DtoFieldSchemaMetadata> fieldSchemas
    ) {
        return seam.projectAndMaskQueryResults(queryContext, rawEntities, fieldSchemas);
    }

    /**
     * Declaratively authorizes a pre-hydration {@code POST}/{@code PUT}/{@code PATCH} mutation by
     * {@code decisionPointKey} alone, applying the registered {@code DualScopeDelegationSpec} and
     * mandatory scope anchor protections.
     */
    public AuthorizedPreMutationContext authorizeMutationByPointKey(
            String decisionPointKey,
            String operationVerb,
            boolean partialPatch,
            String rawJsonPayload,
            Map<String, String> attributeIdByWirePath,
            Set<String> ignoredTechnicalWirePaths,
            boolean callerMatchesCedente,
            boolean callerMatchesCessionario,
            Map<String, Object> trustedTargetFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses
    ) {
        RegisteredDecisionPointContext registered = registry.requireRegisteredPoint(decisionPointKey);
        if (!registered.decisionPoint().evaluationModes().contains(EvaluationMode.TARGET)) {
            throw new SecurityException("AUTHZ_EVALUATION_MODE_NOT_ADMITTED: Decision point '"
                    + decisionPointKey + "' does not admit EvaluationMode.TARGET (CC05/P20)");
        }
        return seam.authorizePreHydrationMutation(
                registered.decisionPoint(),
                registered.factContract().factContractDigest(),
                operationVerb,
                partialPatch,
                rawJsonPayload,
                attributeIdByWirePath,
                ignoredTechnicalWirePaths,
                registered.mandatoryScopeAnchorAttributes(),
                registered.dualScopeSpec(),
                callerMatchesCedente,
                callerMatchesCessionario,
                trustedTargetFacts,
                trustedFactStatuses
        );
    }

    /**
     * Declaratively completes post-mutation {@code BEFORE_COMMIT_OUTBOX} and {@code BEFORE_DISCLOSURE}
     * obligation barriers and returns the detached masked response DTO ({@code CC10}, {@code P19}, {@code P40}).
     */
    public DetachedDtoMaskingResult completeMutationAndMask(
            AuthorizedPreMutationContext preMutationContext,
            Object savedUnmaskedEntity,
            Collection<DtoFieldSchemaMetadata> fieldSchemas
    ) {
        return seam.completePostMutationAndMask(preMutationContext, savedUnmaskedEntity, fieldSchemas);
    }

    /**
     * Declaratively authorizes a durable bulk worker item by {@code decisionPointKey}, validating
     * the {@link WorkerDelegationToken} and performing a live OPA {@code TARGET} re-evaluation.
     */
    public ProviderEvaluationEnvelope authorizeBulkWorkerItemByPointKey(
            String decisionPointKey,
            WorkerDelegationToken delegationToken,
            String expectedAudience,
            String currentActivePolicySetDigest,
            Instant now,
            WriteIntent itemWriteIntent,
            Map<String, Object> itemTargetFacts,
            Map<String, FactResolutionStatus> itemFactStatuses
    ) {
        RegisteredDecisionPointContext registered = registry.requireRegisteredPoint(decisionPointKey);
        if (!registered.decisionPoint().evaluationModes().contains(EvaluationMode.TARGET)) {
            throw new SecurityException("AUTHZ_EVALUATION_MODE_NOT_ADMITTED: Decision point '"
                    + decisionPointKey + "' does not admit EvaluationMode.TARGET (CC05/P20)");
        }
        return seam.authorizeBulkDurableWorkerItem(
                delegationToken,
                expectedAudience,
                currentActivePolicySetDigest,
                now,
                registered.decisionPoint(),
                registered.factContract().factContractDigest(),
                itemWriteIntent,
                itemTargetFacts,
                itemFactStatuses
        );
    }

    /**
     * Declaratively invokes a non-REST internal channel by {@code decisionPointKey} through
     * {@link GovernedChannelInvocationExecutor}, blocking unproxied self-invocation and nested
     * context leakage ({@code P29}, {@code P34}, {@code P41}, {@code P42}).
     */
    public <T> T invokeInternalChannelByPointKey(
            String decisionPointKey,
            AdmittedInvocationChannel channel,
            boolean invokedThroughManagedProxy,
            EvaluationContextSnapshot contextSnapshot,
            Supplier<NormalizedEnforcementOutcome> authorizationEvaluation,
            Function<NormalizedEnforcementOutcome, T> targetInvocation
    ) {
        RegisteredDecisionPointContext registered = registry.requireRegisteredPoint(decisionPointKey);
        return channelExecutor.invokeAdmittedChannel(
                registered.admissionRecord(),
                channel,
                invokedThroughManagedProxy,
                contextSnapshot,
                authorizationEvaluation,
                targetInvocation
        );
    }

    /**
     * Declaratively executes a governed collection export ({@code CSV}, {@code JSON}, {@code EXCEL_TSV})
     * by {@code decisionPointKey} ({@code P11}, {@code P12}, {@code P17}, {@code P18}, {@code P19}, {@code P56}, {@code P60}).
     */
    public <T> SanitizedExportArtifact exportCollectionByPointKey(
            String decisionPointKey,
            String tenantId,
            String environment,
            ExportFormat format,
            Supplier<OpaRuntimeHead> liveHeadSupplier,
            List<DtoFieldSchemaMetadata> fieldSchemas,
            List<T> candidateRows,
            Function<T, Map<String, Object>> rowTargetFactsExtractor,
            Map<String, FactResolutionStatus> baseFactStatuses
    ) {
        return requireExportAndAiSeam().authorizeAndExecuteCollectionExportByPointKey(
                decisionPointKey,
                tenantId,
                environment,
                format,
                liveHeadSupplier,
                fieldSchemas,
                candidateRows,
                rowTargetFactsExtractor,
                baseFactStatuses
        );
    }

    /**
     * Declaratively authorizes and projects a detached payload for an AI tool by {@code decisionPointKey}
     * ({@code P11}, {@code P47}, {@code P56}, {@code P57}, {@code P62}).
     */
    public SanitizedAiToolProjection projectAiToolPayloadByPointKey(
            String decisionPointKey,
            String tenantId,
            String environment,
            Object rawTargetEntityOrDto,
            Collection<DtoFieldSchemaMetadata> fieldSchemas,
            Map<String, Object> trustedTargetFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses
    ) {
        return requireExportAndAiSeam().authorizeAndProjectAiToolPayloadByPointKey(
                decisionPointKey,
                tenantId,
                environment,
                rawTargetEntityOrDto,
                fieldSchemas,
                trustedTargetFacts,
                trustedFactStatuses
        );
    }

    /**
     * Declaratively inspects value-free governance classification metadata for AI policy authoring
     * by {@code decisionPointKey} ({@code P35}, {@code P43}, {@code P62}).
     */
    public List<AiGovernanceMetadataView> inspectAiGovernanceMetadataByPointKey(
            String decisionPointKey,
            String callerPrincipalId,
            Set<String> callerAuthorities,
            Set<String> allowedTenantIds,
            String requestedTenantId,
            String requiredCatalogAuthority
    ) {
        return requireExportAndAiSeam().inspectGovernanceMetadataForAiAuthoring(
                decisionPointKey,
                callerPrincipalId,
                callerAuthorities,
                allowedTenantIds,
                requestedTenantId,
                requiredCatalogAuthority
        );
    }

    private GovernedExportAndAiToolAuthorizationSeam requireExportAndAiSeam() {
        if (exportAndAiSeam == null) {
            throw new IllegalStateException("AUTHZ_EXPORT_AI_SEAM_NOT_CONFIGURED: GovernedExportAndAiToolAuthorizationSeam is not wired on DeclarativeDecisionPointExecutionTemplate");
        }
        return exportAndAiSeam;
    }
}
