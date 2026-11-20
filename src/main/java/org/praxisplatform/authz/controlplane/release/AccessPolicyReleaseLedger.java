package org.praxisplatform.authz.controlplane.release;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.springframework.jdbc.core.JdbcOperations;

/** Config-owned transaction storage. Only the selected deployment is fetched by the bundle consumer. */
final class AccessPolicyReleaseLedger {
    record Scope(String instanceId, String tenantId, String environment) {}

    record Revision(OpaRuntimeHead head, byte[] archive, List<AuthorizationPolicyDefinition> policies,
                    Map<String, String> pins, JsonNode verification) {}

    record Release(UUID id, UUID definitionId, UUID approvalId, String definitionHash, String serviceKey,
                   String state, OpaRuntimeHead basedOn, Revision forward, Revision rollback,
                   OpaRuntimeHead activationObserved, OpaRuntimeHead rollbackObserved) {
        boolean restoring() {
            return "reverting".equals(state) || "reverted".equals(state);
        }
    }

    record Deployment(Release release, String direction) {
        Revision revision() {
            return "rollback".equals(direction) ? release.rollback() : release.forward();
        }

        boolean pending() {
            return "activating".equals(release.state()) || "reverting".equals(release.state());
        }
    }

    record Bundle(byte[] archive, String etag) {}

    private final JdbcOperations jdbc;
    private final ObjectMapper json;
    private final Scope scope;

    AccessPolicyReleaseLedger(JdbcOperations jdbc, ObjectMapper json, Scope scope) {
        this.jdbc = jdbc;
        this.json = json;
        this.scope = scope;
    }

    Optional<Release> find(UUID id) {
        return jdbc.query("""
                select * from authz_policy_release
                where instance_id = ? and tenant_id = ? and environment = ? and id = ?
                """, (row, index) -> release(row), scope.instanceId(), scope.tenantId(), scope.environment(), id)
                .stream().findFirst();
    }

    Optional<Release> findPublished(UUID definitionId, String hash, OpaRuntimeHead base) {
        return jdbc.query("""
                select * from authz_policy_release
                where instance_id = ? and tenant_id = ? and environment = ?
                  and definition_id = ? and definition_hash = ? and based_on = cast(? as jsonb)
                """, (row, index) -> release(row),
                scope.instanceId(), scope.tenantId(), scope.environment(), definitionId, hash, encode(base))
                .stream().findFirst();
    }

    Optional<Deployment> deployment() {
        return jdbc.query("""
                select d.direction, r.* from authz_policy_deployment d
                join authz_policy_release r on r.id = d.release_id
                where d.instance_id = ?
                """, (row, index) -> {
            checkScope(row);
            return new Deployment(release(row), row.getString("direction"));
        }, scope.instanceId()).stream().findFirst();
    }

    Optional<Bundle> bundle() {
        return jdbc.query("""
                select d.tenant_id, d.environment,
                  case d.direction when 'forward' then r.forward_archive else r.rollback_archive end as archive,
                  (case d.direction when 'forward' then r.forward_head else r.rollback_head end)
                    ->> 'headEtag' as etag
                from authz_policy_deployment d join authz_policy_release r on r.id = d.release_id
                where d.instance_id = ?
                """, (row, index) -> {
            checkScope(row);
            return new Bundle(row.getBytes("archive"), row.getString("etag"));
        }, scope.instanceId()).stream().findFirst();
    }

    void insert(Release release, String actor) {
        Revision forward = release.forward();
        Revision rollback = release.rollback();
        jdbc.update("""
                insert into authz_policy_release (
                  id, instance_id, tenant_id, environment, service_key, definition_id, approval_id,
                  definition_hash, published_by, based_on, forward_head, forward_archive,
                  forward_policies, forward_pins, forward_verification, rollback_head, rollback_archive,
                  rollback_policies, rollback_pins, rollback_verification, state
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, cast(? as jsonb), cast(? as jsonb), ?,
                  cast(? as jsonb), cast(? as jsonb), cast(? as jsonb), cast(? as jsonb), ?,
                  cast(? as jsonb), cast(? as jsonb), cast(? as jsonb), 'published')
                """, release.id(), scope.instanceId(), scope.tenantId(), scope.environment(), release.serviceKey(),
                release.definitionId(), release.approvalId(), release.definitionHash(), actor,
                encode(release.basedOn()), encode(forward.head()), forward.archive(), encode(forward.policies()),
                encode(forward.pins()), encode(forward.verification()), encode(rollback.head()), rollback.archive(),
                encode(rollback.policies()), encode(rollback.pins()), encode(rollback.verification()));
    }

    void request(Release release, boolean restoring, String actor) {
        String sql = restoring
                ? "update authz_policy_release set state = 'reverting', rollback_requested_by = ? where id = ? and state in ('active','activating')"
                : "update authz_policy_release set state = 'activating', activation_requested_by = ? where id = ? and state = 'published'";
        requireOne(jdbc.update(sql, actor, release.id()));
        requireOne(jdbc.update("""
                insert into authz_policy_deployment (instance_id, tenant_id, environment, release_id, direction)
                values (?, ?, ?, ?, ?)
                on conflict (instance_id) do update set release_id = excluded.release_id, direction = excluded.direction
                where authz_policy_deployment.tenant_id = excluded.tenant_id
                  and authz_policy_deployment.environment = excluded.environment
                """, scope.instanceId(), scope.tenantId(), scope.environment(), release.id(),
                restoring ? "rollback" : "forward"));
    }

    void observe(Release release, boolean restoring, OpaRuntimeHead observed) {
        String sql = restoring
                ? """
                  update authz_policy_release set state = 'reverted', rollback_observed_head = cast(? as jsonb),
                    rollback_observed_at = current_timestamp where id = ? and state = 'reverting'
                  """
                : """
                  update authz_policy_release set state = 'active', activation_observed_head = cast(? as jsonb),
                    activation_observed_at = current_timestamp where id = ? and state = 'activating'
                  """;
        requireOne(jdbc.update(sql, encode(observed), release.id()));
    }

    private void checkScope(ResultSet row) throws SQLException {
        if (!scope.tenantId().equals(row.getString("tenant_id"))
                || !scope.environment().equals(row.getString("environment"))) {
            throw new IllegalStateException("OPA instance is already bound to a different control-plane scope");
        }
    }

    private Release release(ResultSet row) throws SQLException {
        return new Release(row.getObject("id", UUID.class), row.getObject("definition_id", UUID.class),
                row.getObject("approval_id", UUID.class), row.getString("definition_hash"),
                row.getString("service_key"), row.getString("state"), head(row.getString("based_on")),
                revision(row, "forward"), revision(row, "rollback"),
                head(row.getString("activation_observed_head")), head(row.getString("rollback_observed_head")));
    }

    private Revision revision(ResultSet row, String prefix) throws SQLException {
        try {
            return new Revision(head(row.getString(prefix + "_head")), row.getBytes(prefix + "_archive"),
                    json.readValue(row.getString(prefix + "_policies"), new TypeReference<>() {}),
                    json.readValue(row.getString(prefix + "_pins"), new TypeReference<>() {}),
                    json.readTree(row.getString(prefix + "_verification")));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Persisted authorization release projection is invalid", e);
        }
    }

    private OpaRuntimeHead head(String value) {
        try {
            return value == null ? null : json.readValue(value, OpaRuntimeHead.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Persisted authorization head is invalid", e);
        }
    }

    private String encode(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not persist authorization release projection", e);
        }
    }

    private void requireOne(int affected) {
        if (affected != 1) {
            throw new IllegalStateException("Authorization deployment changed during its lifecycle transaction");
        }
    }
}
