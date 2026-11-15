package org.praxisplatform.authz.pilot;

import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

/**
 * Enforces database connection/session context binding before the first SQL statement, prevents
 * concurrent cross-thread reuse of the same pooled connection slot, and guarantees connection-pool
 * scrubbing on transaction completion or failure ({@code P27}, {@code P33}).
 *
 * <p>Prevents residual tenant/principal variables from a previous pooled connection borrow from
 * leaking into a subsequent request or allowing an unprivileged DB role to bypass policy guards.</p>
 */
public final class JdbcSessionContextIsolationGuard {

    /** Represents a physical connection borrowed from a connection pool. */
    public static final class PooledConnectionSlot {
        private final String connectionId;
        private final String dbRole;
        private final Map<String, String> sessionVariables = new ConcurrentHashMap<>();
        private final AtomicBoolean inUse = new AtomicBoolean(false);
        private volatile boolean transactionActive;
        private volatile boolean contextBoundForCurrentTx;

        public PooledConnectionSlot(String connectionId, String dbRole) {
            this.connectionId = Objects.requireNonNull(connectionId, "connectionId is required");
            this.dbRole = Objects.requireNonNull(dbRole, "dbRole is required");
        }

        public String connectionId() {
            return connectionId;
        }

        public String dbRole() {
            return dbRole;
        }

        public Map<String, String> sessionVariables() {
            return Map.copyOf(sessionVariables);
        }

        public boolean isContextBoundForCurrentTx() {
            return contextBoundForCurrentTx;
        }

        public boolean isInUse() {
            return inUse.get();
        }
    }

    private final Set<String> admittedNonBypassDbRoles;

    public JdbcSessionContextIsolationGuard(Set<String> admittedNonBypassDbRoles) {
        this.admittedNonBypassDbRoles = admittedNonBypassDbRoles == null
                ? Set.of()
                : Set.copyOf(admittedNonBypassDbRoles);
    }

    /**
     * Executes a transactional SQL callback on {@code slot}, guaranteeing that:
     * <ul>
     *   <li>The connection slot is not concurrently borrowed by another active thread ({@code P27}, {@code P33});</li>
     *   <li>The connection's DB role is an admitted non-superuser/non-BYPASSRLS role ({@code P33});</li>
     *   <li>Any residual session variables from a prior pool borrow are scrubbed before binding ({@code P27}, {@code P33});</li>
     *   <li>The current transaction's {@code app.current_tenant_id}, {@code app.current_principal_id},
     *       and {@code app.current_org_scope} are bound before the first SQL runs ({@code P27});</li>
     *   <li>On return or exception, the pooled connection slot is scrubbed clean and released ({@code P27}, {@code P33}).</li>
     * </ul>
     */
    public <T> T executeInProtectedTransaction(
            PooledConnectionSlot slot,
            String tenantId,
            String principalId,
            String orgScopeId,
            Function<PooledConnectionSlot, T> sqlCallback
    ) {
        Objects.requireNonNull(slot, "slot is required");
        Objects.requireNonNull(tenantId, "tenantId is required");
        Objects.requireNonNull(principalId, "principalId is required");
        Objects.requireNonNull(orgScopeId, "orgScopeId is required");
        Objects.requireNonNull(sqlCallback, "sqlCallback is required");

        // 0. P27 & P33: Reject concurrent double-borrow of the same physical connection slot across threads
        if (!slot.inUse.compareAndSet(false, true)) {
            throw new SecurityException("AUTHZ_CONCURRENT_CONNECTION_SLOT_REUSE: Pooled connection slot '"
                    + slot.connectionId() + "' is already leased by another active transaction (P27/P33)");
        }

        try {
            // 1. P33: Reject superuser / BYPASSRLS / unadmitted DB roles
            String upperRole = slot.dbRole().toUpperCase(Locale.ROOT);
            if (!admittedNonBypassDbRoles.contains(slot.dbRole())
                    || upperRole.contains("SUPERUSER")
                    || upperRole.contains("BYPASSRLS")) {
                slot.sessionVariables.clear();
                slot.contextBoundForCurrentTx = false;
                throw new SecurityException("AUTHZ_DB_ROLE_NOT_ADMITTED_FOR_RLS: DB role '"
                        + slot.dbRole() + "' is not admitted or permits RLS bypass (P33)");
            }

            // 2. P27 & P33: Scrub any residual state left on the pooled connection before binding
            slot.sessionVariables.clear();
            slot.transactionActive = true;
            slot.sessionVariables.put("app.current_tenant_id", tenantId);
            slot.sessionVariables.put("app.current_principal_id", principalId);
            slot.sessionVariables.put("app.current_org_scope", orgScopeId);
            slot.contextBoundForCurrentTx = true;

            return sqlCallback.apply(slot);
        } finally {
            // Always scrub pooled connection state and release lease on commit/rollback/exception (P27, P33)
            slot.sessionVariables.clear();
            slot.contextBoundForCurrentTx = false;
            slot.transactionActive = false;
            slot.inUse.set(false);
        }
    }

    /**
     * Verifies that a connection slot has an active, bound transactional security context before
     * executing any SQL statement ({@code P27}).
     */
    public void assertFirstSqlProtected(PooledConnectionSlot slot, String expectedTenantId, String expectedPrincipalId) {
        if (!slot.transactionActive || !slot.contextBoundForCurrentTx) {
            throw new SecurityException("AUTHZ_UNBOUND_DB_SESSION_CONTEXT: SQL execution attempted before binding session context (P27)");
        }
        if (!expectedTenantId.equals(slot.sessionVariables.get("app.current_tenant_id"))
                || !expectedPrincipalId.equals(slot.sessionVariables.get("app.current_principal_id"))) {
            throw new SecurityException("AUTHZ_DB_SESSION_CONTEXT_MISMATCH: Connection context does not match active principal/tenant (P27/P33)");
        }
    }
}
