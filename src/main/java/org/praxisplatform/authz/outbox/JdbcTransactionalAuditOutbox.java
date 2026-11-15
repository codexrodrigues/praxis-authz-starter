package org.praxisplatform.authz.outbox;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.enforcement.obligation.TransactionalAuditOutboxPort;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Production-grade JDBC implementation of {@link TransactionalAuditOutboxPort} participating in the
 * active Spring database transaction at the {@code BEFORE_COMMIT_OUTBOX} barrier ({@code CC10},
 * {@code P19}, {@code ENF-OBL-003}).
 *
 * <p>Guarantees that mandatory {@code ON_PERMIT} audit evidence is persisted in the same ACID
 * writable transaction as the business mutation; if no writable transaction is active (when
 * {@code requireActiveTransaction} is enabled) or if the SQL insert fails,
 * {@link #appendAuditOutboxRecord} returns {@code false} so {@code ObligationBarrierCoordinator}
 * converts {@code PERMIT} into fail-closed {@code DENY} ({@code OBLIGATION_UNFULFILLED}) and rolls
 * back the business transaction.</p>
 */
public final class JdbcTransactionalAuditOutbox implements TransactionalAuditOutboxPort {

    /** Delivery lifecycle state of an outbox record (P8 / CC10 / P19). */
    public enum OutboxDeliveryStatus {
        PENDING,
        DELIVERED,
        DEAD_LETTER
    }

    /** Immutable persisted row read back from the JDBC outbox table. */
    public record PersistedOutboxRecord(
            String entryId,
            String decisionPointKey,
            String runtimeRevision,
            String payloadDigest,
            Map<String, Object> obligationParameters,
            Instant createdAt,
            OutboxDeliveryStatus deliveryStatus,
            int attemptCount,
            Instant deliveredAt,
            String lastErrorCode
    ) {
        public PersistedOutboxRecord(
                String entryId,
                String decisionPointKey,
                String runtimeRevision,
                String payloadDigest,
                Map<String, Object> obligationParameters,
                Instant createdAt
        ) {
            this(
                    entryId,
                    decisionPointKey,
                    runtimeRevision,
                    payloadDigest,
                    obligationParameters,
                    createdAt,
                    OutboxDeliveryStatus.PENDING,
                    0,
                    null,
                    null
            );
        }
    }

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private final JdbcOperations jdbcOperations;
    private final String tableName;
    private final boolean requireActiveTransaction;
    private final ObjectMapper objectMapper = new ObjectMapper()
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    public JdbcTransactionalAuditOutbox(
            JdbcOperations jdbcOperations,
            String tableName,
            boolean initializeSchema,
            boolean requireActiveTransaction
    ) {
        this.jdbcOperations = Objects.requireNonNull(jdbcOperations, "jdbcOperations is required");
        this.tableName = validateSafeSqlIdentifier(tableName);
        this.requireActiveTransaction = requireActiveTransaction;
        if (initializeSchema) {
            ensureSchemaCreated();
        }
    }

    /** Creates the outbox table and indexes if they do not yet exist (PostgreSQL and H2 compatible). */
    public void ensureSchemaCreated() {
        jdbcOperations.execute("CREATE TABLE IF NOT EXISTS " + tableName + " ("
                + "entry_id VARCHAR(64) PRIMARY KEY, "
                + "decision_point_key VARCHAR(512) NOT NULL, "
                + "runtime_revision VARCHAR(255) NOT NULL, "
                + "payload_digest VARCHAR(128) NOT NULL, "
                + "obligation_payload_json TEXT NOT NULL, "
                + "created_at TIMESTAMP NOT NULL, "
                + "delivery_status VARCHAR(32) NOT NULL DEFAULT 'PENDING', "
                + "attempt_count INT NOT NULL DEFAULT 0, "
                + "delivered_at TIMESTAMP NULL, "
                + "last_error_code VARCHAR(128) NULL"
                + ")");
        jdbcOperations.execute("CREATE INDEX IF NOT EXISTS idx_" + tableName + "_created_at "
                + "ON " + tableName + " (created_at, entry_id)");
        jdbcOperations.execute("CREATE INDEX IF NOT EXISTS idx_" + tableName + "_status_created "
                + "ON " + tableName + " (delivery_status, created_at, entry_id)");
    }

    /** Returns the validated SQL table name used by this outbox. */
    public String getTableName() {
        return tableName;
    }

    /** Returns the underlying {@link JdbcOperations} template. */
    public JdbcOperations getJdbcOperations() {
        return jdbcOperations;
    }

    @Override
    public boolean appendAuditOutboxRecord(
            String decisionPointKey,
            String runtimeRevision,
            Map<String, Object> obligationParameters
    ) {
        Objects.requireNonNull(decisionPointKey, "decisionPointKey is required");
        Objects.requireNonNull(runtimeRevision, "runtimeRevision is required");
        if (requireActiveTransaction
                && (!TransactionSynchronizationManager.isActualTransactionActive()
                        || TransactionSynchronizationManager.isCurrentTransactionReadOnly())) {
            return false;
        }
        try {
            Map<String, Object> safeParams = obligationParameters == null
                    ? Map.of()
                    : new TreeMap<>(obligationParameters);
            String payloadJson = objectMapper.writeValueAsString(safeParams);
            String payloadDigest = CanonicalDigestCalculator.computeDigest(
                    DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST,
                    decisionPointKey + "|" + runtimeRevision + "|" + payloadJson
            );
            String entryId = obligationParameters != null && obligationParameters.get("idempotencyEntryId") instanceof String explicitId
                    && !explicitId.isBlank()
                    ? explicitId
                    : UUID.randomUUID().toString();
            int rows = jdbcOperations.update(
                    "INSERT INTO " + tableName
                            + " (entry_id, decision_point_key, runtime_revision, payload_digest, obligation_payload_json, created_at, delivery_status, attempt_count) "
                            + "VALUES (?, ?, ?, ?, ?, ?, 'PENDING', 0)",
                    entryId,
                    decisionPointKey,
                    runtimeRevision,
                    payloadDigest,
                    payloadJson,
                    Timestamp.from(Instant.now())
            );
            return rows == 1;
        } catch (DataAccessException | JsonProcessingException ex) {
            return false;
        }
    }

    /** Reads all committed outbox records ordered by creation time. */
    public List<PersistedOutboxRecord> listCommittedEntries() {
        return jdbcOperations.query(
                "SELECT entry_id, decision_point_key, runtime_revision, payload_digest, obligation_payload_json, "
                        + "created_at, delivery_status, attempt_count, delivered_at, last_error_code "
                        + "FROM " + tableName + " ORDER BY created_at ASC, entry_id ASC",
                this::mapOutboxRow
        );
    }

    /**
     * Reads up to {@code limit} {@code PENDING} outbox records directly via SQL pushdown using
     * {@code idx_<tableName>_status_created} without scanning already-delivered rows in memory ({@code P8-R01}).
     */
    public List<PersistedOutboxRecord> listPendingEntries(int limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be > 0");
        }
        return jdbcOperations.query(
                "SELECT entry_id, decision_point_key, runtime_revision, payload_digest, obligation_payload_json, "
                        + "created_at, delivery_status, attempt_count, delivered_at, last_error_code "
                        + "FROM " + tableName + " WHERE delivery_status = 'PENDING' "
                        + "ORDER BY created_at ASC, entry_id ASC FETCH FIRST ? ROWS ONLY",
                this::mapOutboxRow,
                limit
        );
    }

    private PersistedOutboxRecord mapOutboxRow(java.sql.ResultSet rs, int rowNum) throws java.sql.SQLException {
        try {
            Map<String, Object> params = objectMapper.readValue(
                    rs.getString("obligation_payload_json"),
                    MAP_TYPE
            );
            Timestamp deliveredTs = rs.getTimestamp("delivered_at");
            return new PersistedOutboxRecord(
                    rs.getString("entry_id"),
                    rs.getString("decision_point_key"),
                    rs.getString("runtime_revision"),
                    rs.getString("payload_digest"),
                    Map.copyOf(params),
                    rs.getTimestamp("created_at").toInstant(),
                    OutboxDeliveryStatus.valueOf(rs.getString("delivery_status")),
                    rs.getInt("attempt_count"),
                    deliveredTs != null ? deliveredTs.toInstant() : null,
                    rs.getString("last_error_code")
            );
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Corrupted obligation_payload_json in outbox table " + tableName, ex);
        }
    }

    private static String validateSafeSqlIdentifier(String identifier) {
        Objects.requireNonNull(identifier, "tableName is required");
        String trimmed = identifier.trim();
        if (!trimmed.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            throw new IllegalArgumentException("Invalid SQL table identifier for outbox: " + identifier);
        }
        return trimmed;
    }
}
