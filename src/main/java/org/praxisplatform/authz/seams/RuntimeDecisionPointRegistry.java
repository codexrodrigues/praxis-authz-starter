package org.praxisplatform.authz.seams;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.praxisplatform.authz.catalog.FieldLineageCatalogEntry;
import org.praxisplatform.authz.catalog.MethodBindingAdmissionRecord;
import org.praxisplatform.authz.compatibility.HostRuntimePolicyCoordinates;
import org.praxisplatform.authz.contracts.binding.RuntimeEnforcementBinding;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;

/**
 * Canonical runtime registry indexing admitted {@link MethodBindingAdmissionRecord}s,
 * {@link DecisionPointDescriptor}s, {@link FactContract}s, {@link QueryableResourceProjection}s,
 * {@link RuntimeEnforcementBinding}s, and optional {@link DualScopeDelegationSpec}s by
 * {@code decisionPointKey} ({@code CC05}, {@code CC06}, {@code P20}, {@code P34}, {@code P41}).
 *
 * <p>Guarantees fail-closed resolution: any attempt to execute an unregistered or un-admitted
 * decision point throws {@link SecurityException} ({@code AUTHZ_UNREGISTERED_DECISION_POINT}).</p>
 */
public final class RuntimeDecisionPointRegistry {

    /** Resolved runtime bundle for a single admitted decision point. */
    public record RegisteredDecisionPointContext(
            String pointKey,
            MethodBindingAdmissionRecord admissionRecord,
            DecisionPointDescriptor decisionPoint,
            RuntimeEnforcementBinding enforcementBinding,
            FactContract factContract,
            QueryableResourceProjection queryProjection,
            DualScopeDelegationSpec dualScopeSpec,
            Set<String> mandatoryScopeAnchorAttributes
    ) {
        public RegisteredDecisionPointContext {
            Objects.requireNonNull(pointKey, "pointKey is required");
            Objects.requireNonNull(admissionRecord, "admissionRecord is required");
            Objects.requireNonNull(decisionPoint, "decisionPoint is required");
            Objects.requireNonNull(enforcementBinding, "enforcementBinding is required");
            Objects.requireNonNull(factContract, "factContract is required");
            mandatoryScopeAnchorAttributes = mandatoryScopeAnchorAttributes == null
                    ? Set.of()
                    : Set.copyOf(mandatoryScopeAnchorAttributes);
        }
    }

    private final Map<String, RegisteredDecisionPointContext> pointsByKey = new ConcurrentHashMap<>();
    private final Map<String, FactContract> factContractsById;
    private final Map<String, QueryableResourceProjection> queryProjectionsById;

    public RuntimeDecisionPointRegistry(
            Collection<MethodBindingAdmissionRecord> admissionRecords,
            HostRuntimePolicyCoordinates coordinates
    ) {
        Map<String, FactContract> fcMap = new LinkedHashMap<>();
        Map<String, QueryableResourceProjection> qpMap = new LinkedHashMap<>();
        if (coordinates != null) {
            fcMap.putAll(coordinates.factContractsById());
            qpMap.putAll(coordinates.queryProjectionsByRef());
        }
        this.factContractsById = Map.copyOf(fcMap);
        this.queryProjectionsById = Map.copyOf(qpMap);

        if (admissionRecords != null) {
            for (MethodBindingAdmissionRecord record : admissionRecords) {
                registerAdmissionRecord(record, null, Set.of());
            }
        }
    }

    /**
     * Registers or enriches an admitted decision point with optional dual-scope delegation and
     * mandatory scope anchor attributes.
     */
    public void registerAdmissionRecord(
            MethodBindingAdmissionRecord record,
            DualScopeDelegationSpec dualScopeSpec,
            Set<String> mandatoryScopeAnchorAttributes
    ) {
        Objects.requireNonNull(record, "record is required");
        DecisionPointDescriptor dp = record.decisionPoint();
        String pointKey = dp.identity().pointKey();
        if (!record.proxyEnforcedWithoutSelfInvocationBypass()) {
            throw new IllegalStateException("AUTHZ_REGISTRY_UNPROXIED_SELF_INVOCATION_FORBIDDEN: Decision point '"
                    + pointKey + "' does not guarantee proxy enforcement without self-invocation bypass (P41)");
        }
        String fcId = dp.factContractRef().factContractId();
        FactContract fc = factContractsById.get(fcId);
        if (fc == null) {
            throw new IllegalStateException("AUTHZ_REGISTRY_MISSING_FACT_CONTRACT: Decision point '"
                    + pointKey + "' references unknown FactContract '" + fcId + "' (P20/P39)");
        }
        if (!fc.factContractDigest().equals(dp.factContractRef().factContractDigest())) {
            throw new IllegalStateException("AUTHZ_REGISTRY_FACT_CONTRACT_DIGEST_MISMATCH: Decision point '"
                    + pointKey + "' expects FactContract digest '" + dp.factContractRef().factContractDigest()
                    + "' but found '" + fc.factContractDigest() + "' (P39/P59)");
        }
        QueryableResourceProjection qp = null;
        if (dp.queryProjectionRef() != null) {
            String qpId = dp.queryProjectionRef().projectionId();
            qp = queryProjectionsById.get(qpId);
            if (qp == null) {
                throw new IllegalStateException("AUTHZ_REGISTRY_MISSING_QUERY_PROJECTION: Decision point '"
                        + pointKey + "' references unknown QueryableResourceProjection '" + qpId + "' (P20/P39)");
            }
            if (!qp.projectionDigest().equals(dp.queryProjectionRef().projectionDigest())) {
                throw new IllegalStateException("AUTHZ_REGISTRY_QUERY_PROJECTION_DIGEST_MISMATCH: Decision point '"
                        + pointKey + "' expects QueryableResourceProjection digest '"
                        + dp.queryProjectionRef().projectionDigest() + "' but found '" + qp.projectionDigest() + "' (P39/P59)");
            }
        }
        pointsByKey.put(pointKey, new RegisteredDecisionPointContext(
                pointKey,
                record,
                dp,
                record.enforcementBinding(),
                fc,
                qp,
                dualScopeSpec,
                mandatoryScopeAnchorAttributes
        ));
    }

    /**
     * Enriches an already-registered decision point with declarative {@link DualScopeDelegationSpec},
     * mandatory scope anchor attributes, and introspected {@link FieldLineageCatalogEntry} list
     * from a governed resource service ({@code Fase P10.13}).
     *
     * @param pointKey canonical decision point key
     * @param dualScopeSpec optional dual-scope delegation spec from {@code AuthzResourceGovernanceSpec}
     * @param mandatoryScopeAnchorAttributes optional mandatory scope anchor attributes
     * @param fieldLineageEntries optional introspected field lineage catalog entries
     * @return {@code true} if the decision point was found and enriched
     */
    public boolean enrichRegisteredPointGovernance(
            String pointKey,
            DualScopeDelegationSpec dualScopeSpec,
            Set<String> mandatoryScopeAnchorAttributes,
            List<FieldLineageCatalogEntry> fieldLineageEntries
    ) {
        if (pointKey == null || pointKey.isBlank()) {
            return false;
        }
        RegisteredDecisionPointContext existing = pointsByKey.get(pointKey);
        if (existing == null) {
            return false;
        }
        MethodBindingAdmissionRecord existingRecord = existing.admissionRecord();
        List<FieldLineageCatalogEntry> mergedLineage = mergeFieldLineageEntries(
                existingRecord.fieldLineageEntries(),
                fieldLineageEntries
        );
        MethodBindingAdmissionRecord enrichedRecord = new MethodBindingAdmissionRecord(
                existingRecord.serviceKey(),
                existingRecord.decisionPoint(),
                existingRecord.enforcementBinding(),
                existingRecord.admittedChannels(),
                existingRecord.proxyEnforcedWithoutSelfInvocationBypass(),
                mergedLineage
        );
        DualScopeDelegationSpec effectiveDualScope = dualScopeSpec != null
                ? dualScopeSpec
                : existing.dualScopeSpec();
        Set<String> effectiveAnchors = (mandatoryScopeAnchorAttributes != null && !mandatoryScopeAnchorAttributes.isEmpty())
                ? mandatoryScopeAnchorAttributes
                : existing.mandatoryScopeAnchorAttributes();
        pointsByKey.put(pointKey, new RegisteredDecisionPointContext(
                pointKey,
                enrichedRecord,
                existing.decisionPoint(),
                existing.enforcementBinding(),
                existing.factContract(),
                existing.queryProjection(),
                effectiveDualScope,
                effectiveAnchors
        ));
        return true;
    }

    private static List<FieldLineageCatalogEntry> mergeFieldLineageEntries(
            List<FieldLineageCatalogEntry> existing,
            List<FieldLineageCatalogEntry> additional
    ) {
        if (additional == null || additional.isEmpty()) {
            return existing == null ? List.of() : List.copyOf(existing);
        }
        if (existing == null || existing.isEmpty()) {
            return List.copyOf(additional);
        }
        Map<String, FieldLineageCatalogEntry> merged = new LinkedHashMap<>();
        Map<String, FieldLineageCatalogEntry> existingByAttributeId = new LinkedHashMap<>();
        for (FieldLineageCatalogEntry entry : existing) {
            String key = entry.schemaRef() + "|" + entry.operationRole() + "|" + entry.wirePath();
            merged.put(key, entry);
            existingByAttributeId.putIfAbsent(entry.attributeId(), entry);
        }
        for (FieldLineageCatalogEntry entry : additional) {
            String key = entry.schemaRef() + "|" + entry.operationRole() + "|" + entry.wirePath();
            FieldLineageCatalogEntry canonicalForAttr = existingByAttributeId.get(entry.attributeId());
            FieldLineageCatalogEntry normalized = harmonizeWithCanonicalAttributeIfCompatible(entry, canonicalForAttr);
            merged.putIfAbsent(key, normalized);
        }
        return List.copyOf(merged.values());
    }

    private static FieldLineageCatalogEntry harmonizeWithCanonicalAttributeIfCompatible(
            FieldLineageCatalogEntry candidate,
            FieldLineageCatalogEntry canonical
    ) {
        if (canonical == null) {
            return candidate;
        }
        String defaultConceptId = "concept:" + candidate.attributeId();
        boolean hasDefaultConcept = defaultConceptId.equals(candidate.conceptId());
        boolean sameRank = sensitivityRank(candidate.sensitivityClassification())
                == sensitivityRank(canonical.sensitivityClassification());
        boolean sameAiUsage = Objects.equals(candidate.aiUsageMode(), canonical.aiUsageMode());
        boolean sameExportable = candidate.exportable() == canonical.exportable();
        if (hasDefaultConcept && sameRank && sameAiUsage && sameExportable) {
            return new FieldLineageCatalogEntry(
                    candidate.attributeId(),
                    canonical.conceptId(),
                    candidate.schemaRef(),
                    candidate.wirePath(),
                    candidate.operationRole(),
                    canonical.sensitivityClassification(),
                    candidate.aiUsageMode(),
                    candidate.exportable(),
                    candidate.allowedUseCategories(),
                    candidate.upstreamAttributeRefs(),
                    candidate.explicitGovernanceDeclared()
            );
        }
        return candidate;
    }

    private static int sensitivityRank(String classification) {
        if (classification == null) {
            return 0;
        }
        return switch (classification.trim().toUpperCase()) {
            case "SECRET", "HEALTH_SENSITIVE", "SENSITIVE_PERSONAL" -> 4;
            case "PII_RESTRICTED", "FINANCIAL_RESTRICTED", "RESTRICTED" -> 3;
            case "OPERATIONAL_INTERNAL", "INTERNAL" -> 2;
            default -> 1;
        };
    }

    /**
     * Resolves a registered decision point by its canonical {@code pointKey}, failing closed if
     * the decision point is not registered or admitted ({@code P20}, {@code P34}, {@code P41}).
     */
    public RegisteredDecisionPointContext requireRegisteredPoint(String pointKey) {
        if (pointKey == null || pointKey.isBlank()) {
            throw new SecurityException("AUTHZ_UNREGISTERED_DECISION_POINT: Blank decisionPointKey rejected fail-closed (P20/P41)");
        }
        RegisteredDecisionPointContext ctx = pointsByKey.get(pointKey);
        if (ctx == null) {
            throw new SecurityException("AUTHZ_UNREGISTERED_DECISION_POINT: Decision point '"
                    + pointKey + "' is not registered or admitted in RuntimeDecisionPointRegistry (P20/P34/P41)");
        }
        return ctx;
    }

    /** Returns an optional registered decision point context for inspection. */
    public Optional<RegisteredDecisionPointContext> findRegisteredPoint(String pointKey) {
        return Optional.ofNullable(pointsByKey.get(pointKey));
    }

    /** Returns an immutable snapshot of all registered decision points by key. */
    public Map<String, DecisionPointDescriptor> getDecisionPointsByKey() {
        Map<String, DecisionPointDescriptor> map = new LinkedHashMap<>();
        pointsByKey.forEach((k, v) -> map.put(k, v.decisionPoint()));
        return Map.copyOf(map);
    }

    /** Returns an immutable snapshot of all registered {@link FactContract}s by ID. */
    public Map<String, FactContract> getFactContractsById() {
        return factContractsById;
    }

    /** Returns an immutable snapshot of all registered {@link QueryableResourceProjection}s by ID. */
    public Map<String, QueryableResourceProjection> getQueryProjectionsById() {
        return queryProjectionsById;
    }
}
