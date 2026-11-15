package org.praxisplatform.authz.host.metadata;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Default {@link ThreadLocal}-backed {@link AuthzCallerContextProvider} with fail-closed resolution
 * and scoped execution helpers ({@code Fases P10.8..P10.9}, {@code P01}, {@code P02}).
 */
public final class ThreadLocalAuthzCallerContextProvider implements AuthzCallerContextProvider {

    private final ThreadLocal<AuthzCallerContext> contextHolder = new ThreadLocal<>();

    @Override
    public AuthzCallerContext currentCallerContext() {
        AuthzCallerContext current = contextHolder.get();
        if (current == null) {
            throw new SecurityException(
                    "AUTHZ_CALLER_CONTEXT_MISSING: No AuthzCallerContext bound on current thread (fail-closed P01/P02)");
        }
        return current;
    }

    /**
     * Returns the {@link AuthzCallerContext} currently bound on this thread, or
     * {@link Optional#empty()} if none is bound.
     */
    public Optional<AuthzCallerContext> currentCallerContextOptional() {
        return Optional.ofNullable(contextHolder.get());
    }

    /**
     * Binds the given {@link AuthzCallerContext} to the current thread.
     *
     * @param context non-null caller context
     */
    public void setContext(AuthzCallerContext context) {
        contextHolder.set(Objects.requireNonNull(context, "context is required"));
    }

    /**
     * Clears any {@link AuthzCallerContext} bound to the current thread.
     */
    public void clearContext() {
        contextHolder.remove();
    }

    /**
     * Executes {@code action} with {@code context} bound on the current thread, restoring the
     * previous context afterwards.
     *
     * @param context caller context to bind
     * @param action runnable action
     */
    public void runWithContext(AuthzCallerContext context, Runnable action) {
        Objects.requireNonNull(context, "context is required");
        Objects.requireNonNull(action, "action is required");
        AuthzCallerContext previous = contextHolder.get();
        contextHolder.set(context);
        try {
            action.run();
        } finally {
            if (previous == null) {
                contextHolder.remove();
            } else {
                contextHolder.set(previous);
            }
        }
    }

    /**
     * Executes {@code supplier} with {@code context} bound on the current thread, restoring the
     * previous context afterwards.
     *
     * @param <T> return type
     * @param context caller context to bind
     * @param supplier supplier to execute
     * @return result of {@code supplier}
     */
    public <T> T callWithContext(AuthzCallerContext context, Supplier<T> supplier) {
        Objects.requireNonNull(context, "context is required");
        Objects.requireNonNull(supplier, "supplier is required");
        AuthzCallerContext previous = contextHolder.get();
        contextHolder.set(context);
        try {
            return supplier.get();
        } finally {
            if (previous == null) {
                contextHolder.remove();
            } else {
                contextHolder.set(previous);
            }
        }
    }
}
