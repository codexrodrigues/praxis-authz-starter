package org.praxisplatform.authz.host.metadata;

import java.util.Objects;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;

/**
 * Exception raised when authorization explicitly denies access to a decision point, action,
 * target entity, or write operation ({@code GateOutcome.DENY} -> {@code HTTP 403}).
 *
 * <p>Extends {@link SecurityException} so existing fail-closed handlers continue to work while
 * {@link PraxisAuthzExceptionHandler} returns structured {@code HTTP 403 Forbidden} responses.</p>
 */
public class AuthzAccessDeniedException extends SecurityException {

    private final String reasonCode;
    private final String decisionPointKey;
    private final GateOutcome gateOutcome;

    public AuthzAccessDeniedException(String message) {
        this("AUTHZ_ACCESS_DENIED", null, GateOutcome.DENY, message);
    }

    public AuthzAccessDeniedException(String reasonCode, String message) {
        this(reasonCode, null, GateOutcome.DENY, message);
    }

    public AuthzAccessDeniedException(
            String reasonCode,
            String decisionPointKey,
            GateOutcome gateOutcome,
            String message
    ) {
        super(Objects.requireNonNull(message, "message is required"));
        this.reasonCode = (reasonCode == null || reasonCode.isBlank()) ? "AUTHZ_ACCESS_DENIED" : reasonCode.trim();
        this.decisionPointKey = (decisionPointKey == null || decisionPointKey.isBlank()) ? null : decisionPointKey.trim();
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
