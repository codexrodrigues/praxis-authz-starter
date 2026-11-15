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
        this.resolver = Objects.requireNonNull(resolver, "resolver is required");
        this.callerContextProvider = Objects.requireNonNull(callerContextProvider, "callerContextProvider is required");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        Set<String> headerNames = extractHeaderNames(request);
        if (!headerNames.isEmpty()) {
            Map<String, String> headerProbe = new LinkedHashMap<>();
            for (String h : headerNames) {
                headerProbe.put(h, "__untrusted_client_header_probe__");
            }
            UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(headerProbe, Map.of());
        }

        Optional<AuthzCallerContext> resolved = resolver.resolve(request);
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

    private static Set<String> extractHeaderNames(HttpServletRequest request) {
        Enumeration<String> namesEnum = request.getHeaderNames();
        if (namesEnum == null) {
            return Set.of();
        }
        Set<String> names = new LinkedHashSet<>(Collections.list(namesEnum));
        return Set.copyOf(names);
    }
}
