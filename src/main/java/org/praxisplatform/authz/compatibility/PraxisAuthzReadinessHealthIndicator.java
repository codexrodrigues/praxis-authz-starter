package org.praxisplatform.authz.compatibility;

import java.util.Objects;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;

/**
 * Spring Boot Actuator {@link HealthIndicator} exposing the fail-closed readiness state of
 * {@link HostPolicyCompatibilityStartupVerifier} ({@code CC08}, {@code P20}).
 */
public final class PraxisAuthzReadinessHealthIndicator implements HealthIndicator {

    private final HostPolicyCompatibilityStartupVerifier startupVerifier;

    public PraxisAuthzReadinessHealthIndicator(HostPolicyCompatibilityStartupVerifier startupVerifier) {
        this.startupVerifier = Objects.requireNonNull(startupVerifier, "startupVerifier is required");
    }

    @Override
    public Health health() {
        PraxisAuthzReadinessStatus status = startupVerifier.currentStatus();
        Health.Builder builder = status.ready() ? Health.up() : Health.outOfService();
        return builder
                .withDetail("statusCode", status.statusCode())
                .withDetail("runtimeRevision", status.runtimeRevision())
                .withDetail("policySetDigest", status.policySetDigest())
                .withDetail("verifiedDecisionPointCount", status.verifiedDecisionPointCount())
                .withDetail("diagnostics", status.diagnostics())
                .withDetail("verifiedAt", status.verifiedAt().toString())
                .build();
    }
}
