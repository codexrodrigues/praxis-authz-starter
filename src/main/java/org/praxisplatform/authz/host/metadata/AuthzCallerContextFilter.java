package org.praxisplatform.authz.host.metadata;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.praxisplatform.authz.enforcement.context.UntrustedRequestHeaderGuard;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Servlet filter that enforces fail-closed HTTP header anti-spoofing at the entry boundary
 * ({@link UntrustedRequestHeaderGuard#assertNoAuthoritySpoofingHeaders}, {@code P02}, {@code CC01},
 * {@code Fase P10.15-D}), resolves an {@link AuthzCallerContext} per HTTP request via
 * {@link AuthzCallerContextHttpResolver}, enriches {@link AuthzCallerContext#incomingHeaderNames()}
 * from {@link HttpServletRequest#getHeaderNames()}, and binds the context into
 * {@link ThreadLocalAuthzCallerContextProvider} with deterministic {@code finally} cleanup
 * ({@code Fase P10.9}).
 */
public final class AuthzCallerContextFilter extends OncePerRequestFilter {

    private final AuthzCallerContextHttpResolver resolver;
    private final ThreadLocalAuthzCallerContextProvider callerContextProvider;
    private final PraxisAuthzExceptionHandler exceptionHandler;
    private final com.fasterxml.jackson.databind.ObjectMapper objectMapper;

    /**
     * Creates a new {@link AuthzCallerContextFilter}.
     *
     * @param resolver authoritative HTTP caller context resolver
     * @param callerContextProvider thread-local caller context provider
     */
    public AuthzCallerContextFilter(
            AuthzCallerContextHttpResolver resolver,
            ThreadLocalAuthzCallerContextProvider callerContextProvider
    ) {
        this(resolver, callerContextProvider, null, null);
    }

    /**
     * Creates a new {@link AuthzCallerContextFilter} that translates pre-controller
     * authorization failures into structured JSON {@code RestApiResponse} errors when both
     * {@code exceptionHandler} and {@code objectMapper} are available.
     *
     * @param resolver authoritative HTTP caller context resolver
     * @param callerContextProvider thread-local caller context provider
     * @param exceptionHandler canonical exception-to-response mapper
     * @param objectMapper Jackson mapper used to write JSON responses at the filter boundary
     */
    public AuthzCallerContextFilter(
            AuthzCallerContextHttpResolver resolver,
            ThreadLocalAuthzCallerContextProvider callerContextProvider,
            PraxisAuthzExceptionHandler exceptionHandler,
            com.fasterxml.jackson.databind.ObjectMapper objectMapper
    ) {
        this.resolver = Objects.requireNonNull(resolver, "resolver is required");
        this.callerContextProvider = Objects.requireNonNull(callerContextProvider, "callerContextProvider is required");
        this.exceptionHandler = exceptionHandler;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        Set<String> headerNames = extractHeaderNames(request);
        Map<String, String> rawHeaders = extractRawHeaders(request, headerNames);

        Optional<AuthzCallerContext> resolved;
        try {
            resolved = resolver.resolve(request);
            Map<String, org.praxisplatform.authz.contracts.context.ResolvedFactValue> authoritativeSubjectFacts =
                    toAuthoritativeSubjectFacts(resolved);
            if (!rawHeaders.isEmpty()) {
                UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(rawHeaders, authoritativeSubjectFacts);
            }
        } catch (AuthzUnauthenticatedException
                | org.praxisplatform.authz.enforcement.context.UntrustedHeaderSpoofingException
                | AuthzAccessDeniedException
                | AuthzProviderUnavailableException ex) {
            callerContextProvider.clearContext();
            if (writeAuthorizationFailureIfConfigured(response, ex)) {
                return;
            }
            throw ex;
        } catch (SecurityException ex) {
            callerContextProvider.clearContext();
            if (writeAuthorizationFailureIfConfigured(response, ex)) {
                return;
            }
            throw ex;
        }

        if (resolved == null || resolved.isEmpty()) {
            callerContextProvider.clearContext();
            try {
                filterChain.doFilter(request, response);
            } finally {
                callerContextProvider.clearContext();
            }
            return;
        }

        AuthzCallerContext callerContext = resolved.get();
        if (callerContext.incomingHeaderNames().isEmpty() && !headerNames.isEmpty()) {
            callerContext = callerContext.withIncomingHeaderNames(headerNames);
        }
        if (callerContext.incomingHeaders().isEmpty() && !rawHeaders.isEmpty()) {
            callerContext = callerContext.withIncomingHeaders(rawHeaders);
        }

        IOException[] ioEx = new IOException[1];
        ServletException[] servletEx = new ServletException[1];
        callerContextProvider.runWithContext(callerContext, () -> {
            try {
                filterChain.doFilter(request, response);
            } catch (IOException ex) {
                ioEx[0] = ex;
            } catch (ServletException ex) {
                servletEx[0] = ex;
            }
        });
        if (ioEx[0] != null) {
            throw ioEx[0];
        }
        if (servletEx[0] != null) {
            throw servletEx[0];
        }
    }

    private boolean writeAuthorizationFailureIfConfigured(HttpServletResponse response, Throwable ex)
            throws IOException {
        if (exceptionHandler == null || objectMapper == null) {
            return false;
        }
        org.springframework.http.ResponseEntity<org.praxisplatform.uischema.rest.response.RestApiResponse<Object>> entity =
                exceptionHandler.mapAuthorizationFailure(ex);
        response.setStatus(entity.getStatusCode().value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(entity.getBody()));
        return true;
    }

    private static Map<String, org.praxisplatform.authz.contracts.context.ResolvedFactValue> toAuthoritativeSubjectFacts(
            Optional<AuthzCallerContext> resolved
    ) {
        if (resolved == null || resolved.isEmpty()) {
            return Map.of();
        }
        AuthzCallerContext ctx = resolved.get();
        Map<String, org.praxisplatform.authz.contracts.context.ResolvedFactValue> facts = new LinkedHashMap<>();
        if (ctx.tenantId() != null && !ctx.tenantId().isBlank()) {
            facts.put(
                    "subject.tenantId",
                    org.praxisplatform.authz.contracts.context.ResolvedFactValue.present("subject.tenantId", ctx.tenantId())
            );
        }
        if (ctx.subjectAndEnvironmentFacts() != null) {
            for (Map.Entry<String, Object> entry : ctx.subjectAndEnvironmentFacts().entrySet()) {
                String key = entry.getKey();
                if (key == null || !key.startsWith("subject.")) {
                    continue;
                }
                org.praxisplatform.authz.contracts.context.FactResolutionStatus explicitStatus =
                        ctx.factStatuses() != null ? ctx.factStatuses().get(key) : null;
                if (explicitStatus != null
                        && explicitStatus != org.praxisplatform.authz.contracts.context.FactResolutionStatus.PRESENT) {
                    continue;
                }
                if (entry.getValue() != null) {
                    facts.put(
                            key,
                            org.praxisplatform.authz.contracts.context.ResolvedFactValue.present(key, entry.getValue())
                    );
                }
            }
        }
        return Map.copyOf(facts);
    }

    private static Map<String, String> extractRawHeaders(HttpServletRequest request, Set<String> headerNames) {
        if (headerNames.isEmpty()) {
            return Map.of();
        }
        Map<String, String> raw = new LinkedHashMap<>();
        for (String name : headerNames) {
            Enumeration<String> valuesEnum = request.getHeaders(name);
            if (valuesEnum != null && valuesEnum.hasMoreElements()) {
                raw.put(name, String.join(",", Collections.list(valuesEnum)));
            } else {
                String single = request.getHeader(name);
                if (single != null) {
                    raw.put(name, single);
                }
            }
        }
        return raw;
    }

    private static Set<String> extractHeaderNames(HttpServletRequest request) {
        Enumeration<String> namesEnum = request.getHeaderNames();
        if (namesEnum == null) {
            return Set.of();
        }
        Set<String> names = new LinkedHashSet<>(Collections.list(namesEnum));
        return Set.copyOf(names);
    }
}
