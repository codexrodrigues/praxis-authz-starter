package org.praxisplatform.authz.outbox;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import org.praxisplatform.authz.outbox.JdbcTransactionalAuditOutbox.PersistedOutboxRecord;
import org.springframework.jdbc.core.JdbcOperations;

/**
 * Bounded batch relay executor that drains {@code PENDING} audit evidence rows from
 * {@link JdbcTransactionalAuditOutbox} into an {@link AuditOutboxDeliverySinkPort}, tracking
 * retry counts with optimistic concurrency, transitioning exhausted rows to {@code DEAD_LETTER},
 * supporting operator DLQ replay, and purging old {@code DELIVERED} rows without touching
 * {@code PENDING} or {@code DEAD_LETTER} evidence ({@code CC10}, {@code P19}, {@code P21}).
 */
public final class JdbcAuditOutboxRelayExecutor {

    /** Summary of a single relay drain cycle. */
    public record RelayBatchResult(
            int inspectedCount,
            int deliveredCount,
            int retriedPendingCount,
            int deadLetteredCount
    ) {}

    private final JdbcTransactionalAuditOutbox outbox;
    private final AuditOutboxDeliverySinkPort sinkPort;
    private final int defaultBatchSize;
    private final int defaultMaxAttempts;

    public JdbcAuditOutboxRelayExecutor(
            JdbcTransactionalAuditOutbox outbox,
            AuditOutboxDeliverySinkPort sinkPort
    ) {
        this(outbox, sinkPort, 100, 3);
    }

    public JdbcAuditOutboxRelayExecutor(
            JdbcTransactionalAuditOutbox outbox,
            AuditOutboxDeliverySinkPort sinkPort,
            int defaultBatchSize,
            int defaultMaxAttempts
    ) {
        if (defaultBatchSize <= 0) {
            throw new IllegalArgumentException("defaultBatchSize must be > 0");
        }
        if (defaultMaxAttempts <= 0) {
            throw new IllegalArgumentException("defaultMaxAttempts must be > 0");
        }
        this.outbox = Objects.requireNonNull(outbox, "outbox is required");
        this.sinkPort = Objects.requireNonNull(sinkPort, "sinkPort is required");
        this.defaultBatchSize = defaultBatchSize;
        this.defaultMaxAttempts = defaultMaxAttempts;
    }

    /** Returns the configured default batch size drained per relay cycle ({@code P10.15-B}). */
    public int getDefaultBatchSize() {
        return defaultBatchSize;
    }

    /** Returns the configured default maximum delivery attempts before {@code DEAD_LETTER} ({@code P10.15-B}). */
    public int getDefaultMaxAttempts() {
        return defaultMaxAttempts;
    }

    /**
     * Drains a batch of {@code PENDING} rows using {@link #getDefaultBatchSize()} and
     * {@link #getDefaultMaxAttempts()} ({@code Fase P10.15-B}).
     */
    public RelayBatchResult drainPendingBatch(Instant now) {
        return drainPendingBatch(defaultBatchSize, defaultMaxAttempts, now);
    }

    /**
     * Drains up to {@code batchSize} {@code PENDING} rows ordered by creation time using SQL pushdown,
     * marks acknowledged rows as {@code DELIVERED}, increments {@code attempt_count} on transient
     * failures, and transitions rows reaching {@code maxAttempts} to {@code DEAD_LETTER}.
     */
    public RelayBatchResult drainPendingBatch(int batchSize, int maxAttempts, Instant now) {
        if (batchSize <= 0) {
            throw new IllegalArgumentException("batchSize must be > 0");
        }
        if (maxAttempts <= 0) {
            throw new IllegalArgumentException("maxAttempts must be > 0");
        }
        Objects.requireNonNull(now, "now is required");

        List<PersistedOutboxRecord> pendingBatch = outbox.listPendingEntries(batchSize);

        JdbcOperations jdbc = outbox.getJdbcOperations();
        String table = outbox.getTableName();
        int delivered = 0;
        int retried = 0;
        int deadLettered = 0;

        for (PersistedOutboxRecord row : pendingBatch) {
            int expectedAttempt = row.attemptCount();
            int nextAttempt = expectedAttempt + 1;
            boolean accepted = false;
            String errorCode = null;
            try {
                accepted = sinkPort.publishAuditEvidence(row);
                if (!accepted) {
                    errorCode = "SINK_NACK";
                }
            } catch (RuntimeException ex) {
                accepted = false;
                errorCode = "SINK_EXCEPTION:" + ex.getClass().getSimpleName();
            }

            if (accepted) {
                int updated = jdbc.update(
                        "UPDATE " + table
                                + " SET delivery_status = 'DELIVERED', attempt_count = ?, delivered_at = ?, last_error_code = NULL "
                                + "WHERE entry_id = ? AND delivery_status = 'PENDING' AND attempt_count = ?",
                        nextAttempt,
                        Timestamp.from(now),
                        row.entryId(),
                        expectedAttempt
                );
                if (updated == 1) {
                    delivered++;
                }
            } else if (nextAttempt >= maxAttempts) {
                int updated = jdbc.update(
                        "UPDATE " + table
                                + " SET delivery_status = 'DEAD_LETTER', attempt_count = ?, last_error_code = ? "
                                + "WHERE entry_id = ? AND delivery_status = 'PENDING' AND attempt_count = ?",
                        nextAttempt,
                        errorCode,
                        row.entryId(),
                        expectedAttempt
                );
                if (updated == 1) {
                    deadLettered++;
                }
            } else {
                int updated = jdbc.update(
                        "UPDATE " + table
                                + " SET attempt_count = ?, last_error_code = ? "
                                + "WHERE entry_id = ? AND delivery_status = 'PENDING' AND attempt_count = ?",
                        nextAttempt,
                        errorCode,
                        row.entryId(),
                        expectedAttempt
                );
                if (updated == 1) {
                    retried++;
                }
            }
        }

        return new RelayBatchResult(pendingBatch.size(), delivered, retried, deadLettered);
    }

    /**
     * Requeues specific {@code DEAD_LETTER} outbox rows back to {@code PENDING} with
     * {@code attempt_count = 0} for durable operator recovery after a downstream sink outage ({@code P19}).
     */
    public int requeueDeadLetterEntries(Collection<String> entryIds) {
        if (entryIds == null || entryIds.isEmpty()) {
            return 0;
        }
        int requeued = 0;
        JdbcOperations jdbc = outbox.getJdbcOperations();
        String table = outbox.getTableName();
        for (String id : entryIds) {
            if (id != null && !id.isBlank()) {
                requeued += jdbc.update(
                        "UPDATE " + table
                                + " SET delivery_status = 'PENDING', attempt_count = 0, last_error_code = NULL "
                                + "WHERE entry_id = ? AND delivery_status = 'DEAD_LETTER'",
                        id
                );
            }
        }
        return requeued;
    }

    /**
     * Purges {@code DELIVERED} outbox rows whose {@code delivered_at} timestamp is strictly before
     * {@code deliveredBeforeCutoff}. Never deletes {@code PENDING} or {@code DEAD_LETTER} rows.
     */
    public int purgeDeliveredBefore(Instant deliveredBeforeCutoff) {
        Objects.requireNonNull(deliveredBeforeCutoff, "deliveredBeforeCutoff is required");
        return outbox.getJdbcOperations().update(
                "DELETE FROM " + outbox.getTableName()
                        + " WHERE delivery_status = 'DELIVERED' AND delivered_at < ?",
                Timestamp.from(deliveredBeforeCutoff)
        );
    }
}
