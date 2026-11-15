package org.praxisplatform.authz.host.metadata;

import java.util.Objects;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;

/**
 * Exception raised fail-closed when the authorization decision provider returns
 * {@link GateOutcome#TECHNICAL_ERROR} or {@link GateOutcome#INCONCLUSIVE}, or fails unexpectedly
 * ({@code HTTP 503 Service Unavailable}).
 *
 * <p>Extends {@link SecurityException} so fail-closed internal boundaries remain safe while
 * {@link PraxisAuthzExceptionHandler} distinguishes provider outages ({@code 503}) from policy
 * denials ({@code 403}) and missing authentication ({@code 401}).</p>
 */
public class AuthzProviderUnavailableException extends SecurityException {

    private final String reasonCode;
    private final String decisionPointKey;
    private final GateOutcome gateOutcome;

    public AuthzProviderUnavailableException(String message) {
        this("AUTHZ_PROVIDER_UNAVAILABLE", null, GateOutcome.TECHNICAL_ERROR, message);
    }

    public AuthzProviderUnavailableException(
            String reasonCode,
            String decisionPointKey,
            GateOutcome gateOutcome,
            String message
    ) {
        super(Objects.requireNonNull(message, "message is required"));
        this.reasonCode = (reasonCode == null || reasonCode.isBlank())
                ? "AUTHZ_PROVIDER_UNAVAILABLE"
                : reasonCode.trim();
        this.decisionPointKey = (decisionPointKey == null || decisionPointKey.isBlank())
                ? null
                : decisionPointKey.trim();
        this.gateOutcome = gateOutcome;
    }

    public AuthzProviderUnavailableException(
            String reasonCode,
            String decisionPointKey,
            GateOutcome gateOutcome,
            String message,
            Throwable cause
    ) {
        super(Objects.requireNonNull(message, "message is required"), cause);
        this.reasonCode = (reasonCode == null || reasonCode.isBlank())
                ? "AUTHZ_PROVIDER_UNAVAILABLE"
                : reasonCode.trim();
        this.decisionPointKey = (decisionPointKey == null || decisionPointKey.isBlank())
                ? null
                : decisionPointKey.trim();
        this.gateOutcome = gateOutcome;
    }

    public String getReasonCode() {
        return reasonCode;
    }

    public String getDecisionPointKey() {
        return decisionPointKey;
    }

    public GateOutcome getGateOutcome() {
        return gateOutcome;
    }
}
