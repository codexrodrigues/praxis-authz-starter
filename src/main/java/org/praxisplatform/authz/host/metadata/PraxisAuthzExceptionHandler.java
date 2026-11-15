package org.praxisplatform.authz.host.metadata;

import java.util.List;
import org.praxisplatform.uischema.rest.exceptionhandler.ErrorCategory;
import org.praxisplatform.uischema.rest.response.CustomProblemDetail;
import org.praxisplatform.uischema.rest.response.RestApiResponse;
import org.praxisplatform.authz.enforcement.context.UntrustedHeaderSpoofingException;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseViolationException;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteViolationException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * High-priority Spring MVC exception handler mapping Praxis Authorization security exceptions
 * into canonical {@link RestApiResponse} failure envelopes with accurate HTTP semantics
 * ({@code 401 Unauthorized}, {@code 403 Forbidden}, and {@code 503 Service Unavailable}).
 *
 * <p>Ordered at {@link Ordered#HIGHEST_PRECEDENCE} so authorization and provider-availability
 * failures are intercepted before {@code praxis-metadata-starter}'s generic {@code GlobalExceptionHandler}
 * fallback maps unhandled runtime exceptions to {@code HTTP 500}.</p>
 */
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class PraxisAuthzExceptionHandler {

    @ExceptionHandler(AuthzUnauthenticatedException.class)
    public ResponseEntity<RestApiResponse<Object>> handleUnauthenticated(AuthzUnauthenticatedException ex) {
        return buildFailureResponse(
                HttpStatus.UNAUTHORIZED,
                ErrorCategory.SECURITY,
                ex.getReasonCode(),
                null,
                ex.getMessage(),
                null
        );
    }

    @ExceptionHandler(AuthzProviderUnavailableException.class)
    public ResponseEntity<RestApiResponse<Object>> handleProviderUnavailable(AuthzProviderUnavailableException ex) {
        CustomProblemDetail detail = createDetail(
                HttpStatus.SERVICE_UNAVAILABLE,
                ErrorCategory.SYSTEM,
                ex.getReasonCode(),
                ex.getDecisionPointKey(),
                ex.getMessage()
        );
        if (ex.getDecisionPointKey() != null) {
            detail.setProperty("decisionPointKey", ex.getDecisionPointKey());
        }
        if (ex.getGateOutcome() != null) {
            detail.setProperty("gateOutcome", ex.getGateOutcome().name());
        }
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(RestApiResponse.failure(ex.getMessage(), List.of(detail)));
    }

    @ExceptionHandler(UntrustedHeaderSpoofingException.class)
    public ResponseEntity<RestApiResponse<Object>> handleHeaderSpoofing(UntrustedHeaderSpoofingException ex) {
        CustomProblemDetail detail = createDetail(
                HttpStatus.FORBIDDEN,
                ErrorCategory.SECURITY,
                "AUTHZ_HEADER_SPOOFING",
                ex.getHeaderName(),
                ex.getMessage()
        );
        detail.setProperty("attemptedTargetFactPath", ex.getAttemptedTargetFactPath());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(RestApiResponse.failure(ex.getMessage(), List.of(detail)));
    }

    @ExceptionHandler(FieldUseViolationException.class)
    public ResponseEntity<RestApiResponse<Object>> handleFieldUseViolation(FieldUseViolationException ex) {
        CustomProblemDetail detail = createDetail(
                HttpStatus.FORBIDDEN,
                ErrorCategory.SECURITY,
                "AUTHZ_FIELD_USE_DENIED",
                null,
                ex.getMessage()
        );
        detail.setProperty("fieldUseCategory", ex.getCategory().name());
        detail.setProperty("forbiddenAttributeIds", ex.getForbiddenAttributeIds());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(RestApiResponse.failure(ex.getMessage(), List.of(detail)));
    }

    @ExceptionHandler(FieldWriteViolationException.class)
    public ResponseEntity<RestApiResponse<Object>> handleFieldWriteViolation(FieldWriteViolationException ex) {
        CustomProblemDetail detail = createDetail(
                HttpStatus.FORBIDDEN,
                ErrorCategory.SECURITY,
                ex.getReasonCode(),
                null,
                ex.getMessage()
        );
        detail.setProperty("forbiddenAttributeIds", ex.getForbiddenAttributeIds());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(RestApiResponse.failure(ex.getMessage(), List.of(detail)));
    }

    @ExceptionHandler(AuthzAccessDeniedException.class)
    public ResponseEntity<RestApiResponse<Object>> handleAccessDenied(AuthzAccessDeniedException ex) {
        CustomProblemDetail detail = createDetail(
                HttpStatus.FORBIDDEN,
                ErrorCategory.SECURITY,
                ex.getReasonCode(),
                ex.getDecisionPointKey(),
                ex.getMessage()
        );
        if (ex.getDecisionPointKey() != null) {
            detail.setProperty("decisionPointKey", ex.getDecisionPointKey());
        }
        if (ex.getGateOutcome() != null) {
            detail.setProperty("gateOutcome", ex.getGateOutcome().name());
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(RestApiResponse.failure(ex.getMessage(), List.of(detail)));
    }

    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<RestApiResponse<Object>> handleSecurityException(SecurityException ex) {
        String message = ex.getMessage() != null ? ex.getMessage() : "Authorization denied";
        String extractedCode = extractPrefixCode(message);
        if (message.startsWith("AUTHZ_CALLER_CONTEXT_MISSING")
                || message.startsWith("AUTHZ_AI_METADATA_UNAUTHENTICATED")) {
            return buildFailureResponse(
                    HttpStatus.UNAUTHORIZED,
                    ErrorCategory.SECURITY,
                    extractedCode != null ? extractedCode : "AUTHZ_UNAUTHENTICATED",
                    null,
                    message,
                    null
            );
        }
        return buildFailureResponse(
                HttpStatus.FORBIDDEN,
                ErrorCategory.SECURITY,
                extractedCode != null ? extractedCode : "AUTHZ_ACCESS_DENIED",
                null,
                message,
                null
        );
    }

    /**
     * Maps any authorization or security runtime exception into the canonical HTTP response
     * envelope so servlet filter boundaries and MVC controllers share identical semantics.
     */
    public ResponseEntity<RestApiResponse<Object>> mapAuthorizationFailure(Throwable ex) {
        if (ex instanceof AuthzUnauthenticatedException unauth) {
            return handleUnauthenticated(unauth);
        }
        if (ex instanceof AuthzProviderUnavailableException unavailable) {
            return handleProviderUnavailable(unavailable);
        }
        if (ex instanceof UntrustedHeaderSpoofingException spoofing) {
            return handleHeaderSpoofing(spoofing);
        }
        if (ex instanceof FieldUseViolationException fieldUse) {
            return handleFieldUseViolation(fieldUse);
        }
        if (ex instanceof FieldWriteViolationException fieldWrite) {
            return handleFieldWriteViolation(fieldWrite);
        }
        if (ex instanceof AuthzAccessDeniedException denied) {
            return handleAccessDenied(denied);
        }
        if (ex instanceof SecurityException sec) {
            return handleSecurityException(sec);
        }
        throw new IllegalArgumentException("Unsupported authorization failure type: " + (ex == null ? "null" : ex.getClass().getName()), ex);
    }

    private static ResponseEntity<RestApiResponse<Object>> buildFailureResponse(
            HttpStatus status,
            ErrorCategory category,
            String code,
            String target,
            String message,
            String decisionPointKey
    ) {
        CustomProblemDetail detail = createDetail(status, category, code, target, message);
        if (decisionPointKey != null) {
            detail.setProperty("decisionPointKey", decisionPointKey);
        }
        return ResponseEntity.status(status)
                .body(RestApiResponse.failure(message, List.of(detail)));
    }

    private static CustomProblemDetail createDetail(
            HttpStatus status,
            ErrorCategory category,
            String code,
            String target,
            String message
    ) {
        CustomProblemDetail detail = new CustomProblemDetail(message);
        detail.setStatus(status.value());
        detail.setCategory(category);
        detail.setCode(code);
        if (target != null && !target.isBlank()) {
            detail.setTarget(target);
        }
        return detail;
    }

    private static String extractPrefixCode(String message) {
        int colon = message.indexOf(':');
        if (colon > 0) {
            String candidate = message.substring(0, colon).trim();
            if (!candidate.isBlank() && candidate.startsWith("AUTHZ_") && !candidate.contains(" ")) {
                return candidate;
            }
        }
        return null;
    }
}
