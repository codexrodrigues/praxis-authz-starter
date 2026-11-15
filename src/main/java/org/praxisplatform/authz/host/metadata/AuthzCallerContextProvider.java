package org.praxisplatform.authz.host.metadata;

/**
 * Strategy interface for resolving the active {@link AuthzCallerContext} for governed resource
 * operations ({@code Fase P10.8}, {@code CC01}, {@code CC02}, {@code P01..P03}).
 *
 * <p>Host applications may supply a custom bean backed by Spring Security's
 * {@code SecurityContextHolder} / JWT claims, or rely on the default
 * {@link ThreadLocalAuthzCallerContextProvider} registered by
 * {@code PraxisAuthzHostBridgeAutoConfiguration}.</p>
 */
@FunctionalInterface
public interface AuthzCallerContextProvider {

    /**
     * Resolves the authoritative {@link AuthzCallerContext} for the current execution thread.
     *
     * @return non-null {@link AuthzCallerContext}
     * @throws SecurityException if no authenticated caller context is available (fail-closed)
     */
    AuthzCallerContext currentCallerContext();
}
