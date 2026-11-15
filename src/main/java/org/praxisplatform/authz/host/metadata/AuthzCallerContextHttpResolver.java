package org.praxisplatform.authz.host.metadata;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * SPI for resolving an authoritative {@link AuthzCallerContext} from an incoming
 * {@link HttpServletRequest} ({@code Fase P10.9}, {@code CC01}, {@code CC02}, {@code P01}, {@code P02}).
 *
 * <p>Host applications register a single {@link AuthzCallerContextHttpResolver} bean (for example,
 * extracting tenant and subject claims from Spring Security's {@code SecurityContextHolder} or
 * a verified gateway token) and {@link AuthzCallerContextFilter} automatically binds the resolved
 * context into {@link ThreadLocalAuthzCallerContextProvider} for the duration of the HTTP request,
 * enriching {@link AuthzCallerContext#incomingHeaderNames()} for anti-spoofing validation and
 * guaranteeing {@code ThreadLocal} cleanup in {@code finally}.</p>
 */
@FunctionalInterface
public interface AuthzCallerContextHttpResolver {

    /**
     * Resolves the authoritative {@link AuthzCallerContext} for the given {@code request}, or
     * returns {@link Optional#empty()} when the request is unauthenticated.
     *
     * @param request incoming HTTP servlet request
     * @return resolved caller context or {@link Optional#empty()}
     */
    Optional<AuthzCallerContext> resolve(HttpServletRequest request);
}
