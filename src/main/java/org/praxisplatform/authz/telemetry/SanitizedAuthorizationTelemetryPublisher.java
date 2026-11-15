package org.praxisplatform.authz.telemetry;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.PointAuthorityMode;
import org.praxisplatform.authz.contracts.envelope.EvaluationIssue;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.envelope.PolicyConflictIssue;
import org.praxisplatform.authz.contracts.envelope.PolicyUnitContributionTrace;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;

/**
 * Publishes strictly sanitized authorization decision telemetry envelopes without ever exposing
 * raw restricted attribute values, masked payloads, or cross-subject secrets in logs or metrics
 * ({@code CC07}, {@code P03}, {@code P21}).
 */
public final class SanitizedAuthorizationTelemetryPublisher {

    /**
     * Immutable, value-free telemetry record suitable for structured logging, metrics, and SIEM
     * correlation ({@code CC07}, {@code P03}, {@code P21}).
     */
    public record SanitizedDecisionTelemetryEvent(
            String evaluationId,
            String decisionPointKey,
            String tenantId,
            String environment,
            EvaluationMode evaluationMode,
            PointAuthorityMode authorityMode,
            GateOutcome gateOutcome,
            String runtimeRevision,
            String policySetDigest,
            String factContractDigest,
            Set<String> deniedAttributeIds,
            Set<String> maskedAttributeIds,
            Set<String> obligationCodes,
            Set<String> reasonCodes,
            Set<String> conflictAndIssueCodes,
            long latencyMicros,
            Instant evaluatedAt
    ) {
        public SanitizedDecisionTelemetryEvent {
            Objects.requireNonNull(evaluationId, "evaluationId is required");
            Objects.requireNonNull(decisionPointKey, "decisionPointKey is required");
            Objects.requireNonNull(tenantId, "tenantId is required");
            Objects.requireNonNull(environment, "environment is required");
            Objects.requireNonNull(evaluationMode, "evaluationMode is required");
            Objects.requireNonNull(authorityMode, "authorityMode is required");
            Objects.requireNonNull(gateOutcome, "gateOutcome is required");
            Objects.requireNonNull(runtimeRevision, "runtimeRevision is required");
            Objects.requireNonNull(policySetDigest, "policySetDigest is required");
            Objects.requireNonNull(factContractDigest, "factContractDigest is required");
            deniedAttributeIds = deniedAttributeIds == null ? Set.of() : Set.copyOf(deniedAttributeIds);
            maskedAttributeIds = maskedAttributeIds == null ? Set.of() : Set.copyOf(maskedAttributeIds);
            obligationCodes = obligationCodes == null ? Set.of() : Set.copyOf(obligationCodes);
            reasonCodes = reasonCodes == null ? Set.of() : Set.copyOf(reasonCodes);
            conflictAndIssueCodes = conflictAndIssueCodes == null ? Set.of() : Set.copyOf(conflictAndIssueCodes);
            evaluatedAt = evaluatedAt == null ? Instant.now() : evaluatedAt;
        }
    }

    private final List<AuthorizationTelemetrySinkPort> sinks;
    private final int maxBufferedEvents;
    private final Deque<SanitizedDecisionTelemetryEvent> recentBuffer = new ArrayDeque<>();
    private final AtomicLong failedSinkDeliveries = new AtomicLong(0L);
    private final ObjectMapper objectMapper;

    public SanitizedAuthorizationTelemetryPublisher(
            List<AuthorizationTelemetrySinkPort> sinks,
            int maxBufferedEvents
    ) {
        this.sinks = sinks == null ? List.of() : List.copyOf(sinks);
        if (maxBufferedEvents <= 0) {
            throw new IllegalArgumentException("maxBufferedEvents must be > 0");
        }
        this.maxBufferedEvents = maxBufferedEvents;
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /**
     * Extracts only structural metadata, digests, attribute IDs, obligation codes, reason codes,
     * and conflict/issue codes from a {@link ProviderEvaluationEnvelope} and publishes a
     * {@link SanitizedDecisionTelemetryEvent} ({@code CC07}, {@code P03}, {@code P21}).
     *
     * <p>Individual sink failures are isolated and counted via {@link #failedSinkDeliveriesCount()}
     * so a misbehaving external telemetry sink never aborts subsequent sinks or masks an
     * authoritative security decision.</p>
     */
    public SanitizedDecisionTelemetryEvent recordEnvelope(
            String tenantId,
            String environment,
            PointAuthorityMode authorityMode,
            ProviderEvaluationEnvelope envelope
    ) {
        Objects.requireNonNull(tenantId, "tenantId is required");
        Objects.requireNonNull(environment, "environment is required");
        Objects.requireNonNull(authorityMode, "authorityMode is required");
        Objects.requireNonNull(envelope, "envelope is required");

        Set<String> deniedAttributes = new LinkedHashSet<>();
        if (envelope.combinedFieldUseEffects() != null) {
            for (FieldUseEffectDirective d : envelope.combinedFieldUseEffects()) {
                if (d.effect() == RuleEffect.DENY) {
                    deniedAttributes.add(d.attributeId());
                }
            }
        }

        Set<String> maskedAttributes = new LinkedHashSet<>();
        if (envelope.combinedMaskDirectives() != null) {
            for (MaskDirective m : envelope.combinedMaskDirectives()) {
                maskedAttributes.add(m.attributeId());
            }
        }

        Set<String> obligationCodes = new LinkedHashSet<>();
        if (envelope.combinedObligationDirectives() != null) {
            for (ObligationDirective o : envelope.combinedObligationDirectives()) {
                obligationCodes.add(o.obligationType());
            }
        }

        Set<String> reasonCodes = new LinkedHashSet<>();
        if (envelope.unitContributions() != null) {
            for (PolicyUnitContributionTrace trace : envelope.unitContributions()) {
                if (trace.reasonCode() != null && !trace.reasonCode().isBlank()) {
                    reasonCodes.add(trace.reasonCode());
                }
            }
        }

        Set<String> conflictAndIssueCodes = new LinkedHashSet<>();
        if (envelope.unresolvedConflicts() != null) {
            for (PolicyConflictIssue conflict : envelope.unresolvedConflicts()) {
                conflictAndIssueCodes.add(conflict.conflictKind() + ":" + conflict.targetKey());
            }
        }
        if (envelope.evaluationIssues() != null) {
            for (EvaluationIssue issue : envelope.evaluationIssues()) {
                conflictAndIssueCodes.add(issue.issueCode());
            }
        }

        SanitizedDecisionTelemetryEvent event = new SanitizedDecisionTelemetryEvent(
                envelope.providerEvaluationId(),
                envelope.decisionPointKey(),
                tenantId.trim(),
                environment.trim(),
                envelope.evaluationMode(),
                authorityMode,
                envelope.gateOutcome(),
                envelope.runtimeRevision(),
                envelope.policySetDigest(),
                envelope.factContractDigest(),
                deniedAttributes,
                maskedAttributes,
                obligationCodes,
                reasonCodes,
                conflictAndIssueCodes,
                envelope.durationMicros(),
                envelope.evaluatedAt()
        );

        synchronized (recentBuffer) {
            while (recentBuffer.size() >= maxBufferedEvents) {
                recentBuffer.removeFirst();
            }
            recentBuffer.addLast(event);
        }

        for (AuthorizationTelemetrySinkPort sink : sinks) {
            try {
                sink.publish(event);
            } catch (RuntimeException ignored) {
                failedSinkDeliveries.incrementAndGet();
            }
        }

        return event;
    }

    /**
     * Returns the total count of external telemetry sink deliveries that threw a runtime exception.
     */
    public long failedSinkDeliveriesCount() {
        return failedSinkDeliveries.get();
    }

    /**
     * Returns up to {@code limit} most recent sanitized telemetry events in chronological order.
     */
    public List<SanitizedDecisionTelemetryEvent> recentEvents(int limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be > 0");
        }
        synchronized (recentBuffer) {
            List<SanitizedDecisionTelemetryEvent> all = new ArrayList<>(recentBuffer);
            if (all.size() <= limit) {
                return List.copyOf(all);
            }
            return List.copyOf(all.subList(all.size() - limit, all.size()));
        }
    }

    /**
     * Serializes a {@link SanitizedDecisionTelemetryEvent} to canonical JSON for structured log output.
     */
    public String toStructuredJsonLog(SanitizedDecisionTelemetryEvent event) {
        Objects.requireNonNull(event, "event is required");
        try {
            return objectMapper.writeValueAsString(event);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to serialize SanitizedDecisionTelemetryEvent: " + ex.getMessage(), ex);
        }
    }
}
