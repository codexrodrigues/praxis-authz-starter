package org.praxisplatform.authz.autoconfigure;

import java.time.Duration;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed configuration properties for {@code praxis-authz-starter} ({@code praxis.authz.*}).
 *
 * <p>Provides safe, fail-closed defaults for bootstrap readiness, OPA transport, compatibility
 * verification, and PAP catalog discovery ({@code P20}, {@code P35}, {@code P64}).</p>
 */
@ConfigurationProperties(prefix = "praxis.authz")
public class PraxisAuthzProperties {

    /** Whether Praxis Authorization enforcement and auto-configuration are enabled. */
    private boolean enabled = true;

    /** Whether startup must fail closed if provider, binding, or compatibility verification fails (P20). */
    private boolean failClosedOnBootstrapError = true;

    /** Whether at least one registered RuntimeEnforcementBinding is required at startup when enabled (P20). */
    private boolean requireBindingsOnStartup = true;

    /** Cryptographic HMAC-SHA256 secret used by HASH_TOKEN_KEYED masking strategy (CC09). */
    private String maskingHmacSecret = "praxis-default-hmac-key-2026";

    private final Opa opa = new Opa();
    private final Compatibility compatibility = new Compatibility();
    private final Discovery discovery = new Discovery();
    private final Jdbc jdbc = new Jdbc();
    private final Outbox outbox = new Outbox();
    private final AdminEndpoints adminEndpoints = new AdminEndpoints();
    private final Telemetry telemetry = new Telemetry();
    private final ReadinessGate readinessGate = new ReadinessGate();
    private final Interceptor interceptor = new Interceptor();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isFailClosedOnBootstrapError() {
        return failClosedOnBootstrapError;
    }

    public void setFailClosedOnBootstrapError(boolean failClosedOnBootstrapError) {
        this.failClosedOnBootstrapError = failClosedOnBootstrapError;
    }

    public boolean isRequireBindingsOnStartup() {
        return requireBindingsOnStartup;
    }

    public void setRequireBindingsOnStartup(boolean requireBindingsOnStartup) {
        this.requireBindingsOnStartup = requireBindingsOnStartup;
    }

    public String getMaskingHmacSecret() {
        return maskingHmacSecret;
    }

    public void setMaskingHmacSecret(String maskingHmacSecret) {
        if (maskingHmacSecret == null || maskingHmacSecret.isBlank()) {
            throw new IllegalArgumentException("maskingHmacSecret must not be blank");
        }
        this.maskingHmacSecret = maskingHmacSecret;
    }

    public Opa getOpa() {
        return opa;
    }

    public Compatibility getCompatibility() {
        return compatibility;
    }

    public Discovery getDiscovery() {
        return discovery;
    }

    public Jdbc getJdbc() {
        return jdbc;
    }

    public Outbox getOutbox() {
        return outbox;
    }

    public AdminEndpoints getAdminEndpoints() {
        return adminEndpoints;
    }

    public Telemetry getTelemetry() {
        return telemetry;
    }

    public ReadinessGate getReadinessGate() {
        return readinessGate;
    }

    public Interceptor getInterceptor() {
        return interceptor;
    }

    /** OPA client and revision-guard configuration. */
    public static class Opa {
        /** Whether to auto-configure the production HttpClientOpaTransport bean (false by default so missing transport fails closed per P20). */
        private boolean httpTransportEnabled = false;

        /** Base URL of the primary OPA instance when HTTP transport is used. */
        private String baseUrl = "http://127.0.0.1:8181";

        /** Primary OPA instance identifier. */
        private String instanceId = "opa-primary-1";

        /** Per-request HTTP timeout for OPA queries (P03). */
        private Duration requestTimeout = Duration.ofMillis(1500);

        /** Bounded same-instance retry count for 3-step SEARCH evaluations (CC11, P17). */
        private int searchMaxSameInstanceRetries = 1;

        public String getBaseUrl() {
            return baseUrl;
        }

        public boolean isHttpTransportEnabled() {
            return httpTransportEnabled;
        }

        public void setHttpTransportEnabled(boolean httpTransportEnabled) {
            this.httpTransportEnabled = httpTransportEnabled;
        }

        public void setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
        }

        public String getInstanceId() {
            return instanceId;
        }

        public void setInstanceId(String instanceId) {
            this.instanceId = instanceId;
        }

        public Duration getRequestTimeout() {
            return requestTimeout;
        }

        public void setRequestTimeout(Duration requestTimeout) {
            this.requestTimeout = requestTimeout;
        }

        public int getSearchMaxSameInstanceRetries() {
            return searchMaxSameInstanceRetries;
        }

        public void setSearchMaxSameInstanceRetries(int searchMaxSameInstanceRetries) {
            this.searchMaxSameInstanceRetries = searchMaxSameInstanceRetries;
        }
    }

    /** Host-policy compatibility handshake settings (CC08, P20, P39). */
    public static class Compatibility {
        /** Whether to verify HostPolicyCompatibilityManifest against OpaRuntimeRelease on startup. */
        private boolean verifyOnStartup = true;

        public boolean isVerifyOnStartup() {
            return verifyOnStartup;
        }

        public void setVerifyOnStartup(boolean verifyOnStartup) {
            this.verifyOnStartup = verifyOnStartup;
        }
    }

    /** PAP semantic catalog discovery and lineage expansion limits (P34, P35, P43, P62, P64). */
    public static class Discovery {
        /** Authority required to query the PAP semantic decision point catalog (P35, P43). */
        private String requiredCatalogAuthority = "praxis:authz:pap:catalog:read";

        /** Maximum lineage selector graph depth before rejecting cyclic or runaway expansion (P64). */
        private int maxLineageDepth = 8;

        /** Maximum lineage selector branch count per decision point before rejecting expansion (P64). */
        private int maxLineageBranches = 64;

        public String getRequiredCatalogAuthority() {
            return requiredCatalogAuthority;
        }

        public void setRequiredCatalogAuthority(String requiredCatalogAuthority) {
            this.requiredCatalogAuthority = requiredCatalogAuthority;
        }

        public int getMaxLineageDepth() {
            return maxLineageDepth;
        }

        public void setMaxLineageDepth(int maxLineageDepth) {
            this.maxLineageDepth = maxLineageDepth;
        }

        public int getMaxLineageBranches() {
            return maxLineageBranches;
        }

        public void setMaxLineageBranches(int maxLineageBranches) {
            this.maxLineageBranches = maxLineageBranches;
        }
    }

    /** JDBC session context and Row-Level Security (RLS) role isolation settings (P27, P33). */
    public static class Jdbc {
        /** Non-superuser, non-BYPASSRLS database roles admitted for transactional RLS session binding. */
        private Set<String> admittedDbRoles = Set.of("praxis_app_rls_user");

        public Set<String> getAdmittedDbRoles() {
            return admittedDbRoles;
        }

        public void setAdmittedDbRoles(Set<String> admittedDbRoles) {
            this.admittedDbRoles = admittedDbRoles == null ? Set.of() : Set.copyOf(admittedDbRoles);
        }
    }

    /** Durable JDBC transactional audit outbox configuration (CC10, P19, P10.15-B). */
    public static class Outbox {
        /** Whether to prefer JdbcTransactionalAuditOutbox when a JdbcOperations bean is present (true by default). */
        private boolean jdbcEnabled = true;

        /** SQL table name for durable obligation audit evidence. */
        private String tableName = "praxis_authz_obligation_outbox";

        /** Whether to automatically create the outbox table on startup when jdbcEnabled=true (true by default). */
        private boolean initializeSchema = true;

        /** Whether BEFORE_COMMIT_OUTBOX writes must fail closed if no actual Spring transaction is active. */
        private boolean requireActiveTransaction = true;

        /** Maximum delivery attempts before a PENDING outbox row transitions to DEAD_LETTER (P8 / P19). */
        private int maxDeliveryAttempts = 3;

        /** Maximum number of PENDING outbox rows drained per relay cycle (P8 / P19). */
        private int relayBatchSize = 100;

        public boolean isJdbcEnabled() {
            return jdbcEnabled;
        }

        public void setJdbcEnabled(boolean jdbcEnabled) {
            this.jdbcEnabled = jdbcEnabled;
        }

        public String getTableName() {
            return tableName;
        }

        public void setTableName(String tableName) {
            this.tableName = tableName;
        }

        public boolean isInitializeSchema() {
            return initializeSchema;
        }

        public void setInitializeSchema(boolean initializeSchema) {
            this.initializeSchema = initializeSchema;
        }

        public boolean isRequireActiveTransaction() {
            return requireActiveTransaction;
        }

        public void setRequireActiveTransaction(boolean requireActiveTransaction) {
            this.requireActiveTransaction = requireActiveTransaction;
        }

        public int getMaxDeliveryAttempts() {
            return maxDeliveryAttempts;
        }

        public void setMaxDeliveryAttempts(int maxDeliveryAttempts) {
            this.maxDeliveryAttempts = maxDeliveryAttempts;
        }

        public int getRelayBatchSize() {
            return relayBatchSize;
        }

        public void setRelayBatchSize(int relayBatchSize) {
            this.relayBatchSize = relayBatchSize;
        }
    }

    /** Opt-in administrative PAP control-plane surface settings (G0, P28, P32, P35). */
    public static class AdminEndpoints {
        /** Whether PAP administrative operations are enabled on this host (false by default per G0/P32). */
        private boolean enabled = false;

        /** Authority required to trigger governed materialization reconciliation/withdrawal (P28, P32). */
        private String requiredReconcileAuthority = "POLICY_ADMIN_PUBLISH";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getRequiredReconcileAuthority() {
            return requiredReconcileAuthority;
        }

        public void setRequiredReconcileAuthority(String requiredReconcileAuthority) {
            this.requiredReconcileAuthority = requiredReconcileAuthority;
        }
    }

    /** Value-sanitized authorization telemetry ring-buffer and sink configuration (CC07, P21). */
    public static class Telemetry {
        /** Maximum number of recent sanitized decision telemetry events kept in memory for diagnostics. */
        private int maxBufferedEvents = 256;

        public int getMaxBufferedEvents() {
            return maxBufferedEvents;
        }

        public void setMaxBufferedEvents(int maxBufferedEvents) {
            this.maxBufferedEvents = maxBufferedEvents;
        }
    }

    /** Host service architectural readiness gate configuration ({@code Fase P10.14}, {@code AUTHZ-HOST-001..009}). */
    public static class ReadinessGate {
        /** Whether to automatically run {@code AuthzHostReadinessReviewer} across all governed services on startup. */
        private boolean verifyOnStartup = false;

        /** Whether startup verification must also fail closed on {@code WARNING} findings (e.g. manual override mode). */
        private boolean failOnWarning = false;

        public boolean isVerifyOnStartup() {
            return verifyOnStartup;
        }

        public void setVerifyOnStartup(boolean verifyOnStartup) {
            this.verifyOnStartup = verifyOnStartup;
        }

        public boolean isFailOnWarning() {
            return failOnWarning;
        }

        public void setFailOnWarning(boolean failOnWarning) {
            this.failOnWarning = failOnWarning;
        }
    }

    /** Automatic {@code ResourceGovernanceInterceptor} configuration for plain Praxis services ({@code Wave 1.4B}). */
    public static class Interceptor {
        /** Whether to fail closed when a plain service has neither {@code AuthzResourceGovernanceSpec} nor {@code @AuthzTenantScope}. */
        private boolean failClosedOnUnconfiguredServices = false;

        public boolean isFailClosedOnUnconfiguredServices() {
            return failClosedOnUnconfiguredServices;
        }

        public void setFailClosedOnUnconfiguredServices(boolean failClosedOnUnconfiguredServices) {
            this.failClosedOnUnconfiguredServices = failClosedOnUnconfiguredServices;
        }
    }
}
