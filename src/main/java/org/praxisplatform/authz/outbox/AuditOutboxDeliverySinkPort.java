package org.praxisplatform.authz.outbox;

import org.praxisplatform.authz.outbox.JdbcTransactionalAuditOutbox.PersistedOutboxRecord;

/**
 * SPI port for delivering committed audit evidence rows from {@link JdbcTransactionalAuditOutbox}
 * to an external enterprise SIEM, audit log collector, or durable message broker ({@code CC10},
 * {@code P19}, {@code P21}).
 */
@FunctionalInterface
public interface AuditOutboxDeliverySinkPort {

    /**
     * Publishes a single committed outbox record to the downstream audit sink.
     *
     * @param record committed outbox record with canonical {@code payloadDigest}
     * @return {@code true} if the sink durably acknowledged receipt; {@code false} to trigger retry or dead-letter transition
     */
    boolean publishAuditEvidence(PersistedOutboxRecord record);
}
