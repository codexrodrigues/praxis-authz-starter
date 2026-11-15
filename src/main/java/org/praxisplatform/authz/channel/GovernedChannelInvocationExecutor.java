package org.praxisplatform.authz.channel;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Supplier;
import org.praxisplatform.authz.catalog.AdmittedInvocationChannel;
import org.praxisplatform.authz.catalog.MethodBindingAdmissionRecord;
import org.praxisplatform.authz.contracts.context.EvaluationContextSnapshot;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.enforcement.context.ScopedExecutionContextHolder;
import org.praxisplatform.authz.enforcement.pipeline.NormalizedEnforcementOutcome;

/**
 * Enforces channel admission, self-invocation blocking, nested context restoration, and cache-hit
 * re-authorization across REST endpoints, proxied internal services, and durable workers
 * ({@code P21}, {@code P26}, {@code P29}, {@code P34}, {@code P41}, {@code P42}).
 */
public final class GovernedChannelInvocationExecutor {

    private record ScopedEntityCacheKey(String cacheNamespace, Object entityId) {}

    private final Map<ScopedEntityCacheKey, Object> rawEntityCacheByKey = new ConcurrentHashMap<>();

    /**
     * Executes an operation on a governed decision point, verifying that:
     * <ul>
     *   <li>The call arrived via an admitted proxy/channel ({@code P34}, {@code P41});</li>
     *   <li>Any outer {@link EvaluationContextSnapshot} is preserved and restored even if the inner
     *       call throws an exception ({@code P29});</li>
     *   <li>An outer endpoint {@code PERMIT} never bypasses the inner point's own authorization
     *       evaluation ({@code P42}).</li>
     * </ul>
     */
    public <T> T invokeAdmittedChannel(
            MethodBindingAdmissionRecord admissionRecord,
            AdmittedInvocationChannel channel,
            boolean invokedThroughAdmittedProxy,
            EvaluationContextSnapshot innerContextSnapshot,
            Supplier<NormalizedEnforcementOutcome> innerAuthorizationEvaluator,
            Function<NormalizedEnforcementOutcome, T> authorizedAction
    ) {
        Objects.requireNonNull(admissionRecord, "admissionRecord is required");
        Objects.requireNonNull(channel, "channel is required");
        Objects.requireNonNull(innerContextSnapshot, "innerContextSnapshot is required");
        Objects.requireNonNull(innerAuthorizationEvaluator, "innerAuthorizationEvaluator is required");
        Objects.requireNonNull(authorizedAction, "authorizedAction is required");

        String pointKey = admissionRecord.decisionPoint().identity().pointKey();

        // 1. P41: Block self-invocation or unproxied method invocation
        if (!invokedThroughAdmittedProxy || !admissionRecord.proxyEnforcedWithoutSelfInvocationBypass()) {
            throw new SecurityException("AUTHZ_UNPROXIED_SELF_INVOCATION_DENIED: Direct or unproxied invocation of '"
                    + pointKey + "' is not admitted (P41)");
        }

        // 2. P34: Verify channel is admitted for this decision point
        if (!admissionRecord.admittedChannels().contains(channel)) {
            throw new SecurityException("AUTHZ_CHANNEL_NOT_ADMITTED: Channel '" + channel
                    + "' is not admitted for decision point '" + pointKey + "' (P34)");
        }

        // 3. P29 & P42: Open nested scope (preserving outer snapshot) and always evaluate inner point
        Optional<EvaluationContextSnapshot> outerBefore = ScopedExecutionContextHolder.current();
        try (ScopedExecutionContextHolder.ScopeToken ignored =
                     ScopedExecutionContextHolder.open(innerContextSnapshot)) {
            NormalizedEnforcementOutcome innerOutcome = innerAuthorizationEvaluator.get();
            if (!innerOutcome.isPermitted()) {
                throw new SecurityException("AUTHZ_INNER_POINT_DENIED: Inner decision point '"
                        + pointKey + "' denied access despite outer context (P42)");
            }
            return authorizedAction.apply(innerOutcome);
        } finally {
            Optional<EvaluationContextSnapshot> outerAfter = ScopedExecutionContextHolder.current();
            if (!Objects.equals(outerBefore, outerAfter)) {
                throw new IllegalStateException("AUTHZ_NESTED_CONTEXT_RESTORATION_FAILURE (P29)");
            }
        }
    }

    /**
     * Loads a raw entity by ID (caching only the raw entity in the default namespace) and executes
     * mandatory authorization and detached projection on EVERY call — including cache hits ({@code P21}, {@code P26}).
     */
    public <ID, E> NormalizedEnforcementOutcome getByIdWithCacheHitAuthorization(
            ID entityId,
            Function<ID, E> repositoryLoader,
            Function<E, NormalizedEnforcementOutcome> targetAuthorizationAndMaskingPipeline
    ) {
        return getByIdWithCacheHitAuthorization(
                "default",
                entityId,
                repositoryLoader,
                targetAuthorizationAndMaskingPipeline
        );
    }

    /**
     * Loads a raw entity by namespace + ID (caching only the raw entity isolated by resource/tenant
     * namespace) and executes mandatory authorization and detached projection on EVERY call —
     * including cache hits ({@code P21}, {@code P26}).
     */
    public <ID, E> NormalizedEnforcementOutcome getByIdWithCacheHitAuthorization(
            String cacheNamespace,
            ID entityId,
            Function<ID, E> repositoryLoader,
            Function<E, NormalizedEnforcementOutcome> targetAuthorizationAndMaskingPipeline
    ) {
        Objects.requireNonNull(cacheNamespace, "cacheNamespace is required");
        Objects.requireNonNull(entityId, "entityId is required");
        Objects.requireNonNull(repositoryLoader, "repositoryLoader is required");
        Objects.requireNonNull(targetAuthorizationAndMaskingPipeline, "targetAuthorizationAndMaskingPipeline is required");

        ScopedEntityCacheKey cacheKey = new ScopedEntityCacheKey(cacheNamespace, entityId);
        @SuppressWarnings("unchecked")
        E rawEntity = (E) rawEntityCacheByKey.computeIfAbsent(cacheKey, k -> repositoryLoader.apply(entityId));

        // P26: Always execute full authorization & detached masking even on a warm cache hit!
        return targetAuthorizationAndMaskingPipeline.apply(rawEntity);
    }

    /**
     * Computes a collision-resistant cache/ETag key isolated by decision point, subject principal,
     * organizational scope, runtime revision, and policy set digest using length-prefixed framing ({@code P21}).
     */
    public String computeScopedArtifactKey(
            String pointKey,
            String principalId,
            String orgScopeKey,
            String runtimeRevision,
            String policySetDigest,
            String targetId
    ) {
        String preimage = frame(pointKey)
                + frame(principalId)
                + frame(orgScopeKey)
                + frame(runtimeRevision)
                + frame(policySetDigest)
                + frame(targetId);
        return CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST,
                preimage
        );
    }

    private static String frame(String value) {
        String safe = Objects.requireNonNull(value, "Scoped artifact key segment must not be null");
        return safe.length() + ":" + safe + "|";
    }
}
