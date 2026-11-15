package org.praxisplatform.authz.telemetry;

/**
 * Outbound SPI port for receiving sanitized authorization decision telemetry events
 * ({@code CC07}, {@code P21}).
 *
 * <p>Implementations may forward events to Micrometer, OpenTelemetry, or structured audit logs.
 * Events passed to this port are guaranteed to contain only metadata, digests, attribute IDs,
 * and outcome codes — never raw entity attribute values or secret tokens ({@code P21}).</p>
 */
@FunctionalInterface
public interface AuthorizationTelemetrySinkPort {

    /**
     * Publishes a sanitized decision telemetry event.
     *
     * @param event immutable, value-sanitized telemetry record
     */
    void publish(SanitizedAuthorizationTelemetryPublisher.SanitizedDecisionTelemetryEvent event);
}
