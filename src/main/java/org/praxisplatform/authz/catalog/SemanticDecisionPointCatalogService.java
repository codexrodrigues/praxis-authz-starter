package org.praxisplatform.authz.catalog;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzProperties;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;

/**
 * Serves the semantic decision-point and field-lineage catalog to the Policy Administration Point (PAP)
 * without executing business methods, reading live domain samples, or creating HTTP routes
 * ({@code P34}, {@code P35}, {@code P41}, {@code P43}, {@code P44}, {@code P45}, {@code P54},
 * {@code P57}, {@code P58}, {@code P62}, {@code P64}).
 */
public final class SemanticDecisionPointCatalogService {

    private final PraxisAuthzProperties properties;
    private final List<MethodBindingAdmissionRecord> registeredRecords;

    public SemanticDecisionPointCatalogService(
            PraxisAuthzProperties properties,
            List<MethodBindingAdmissionRecord> registeredRecords
    ) {
        this.properties = Objects.requireNonNull(properties, "properties is required");
        this.registeredRecords = new CopyOnWriteArrayList<>(
                registeredRecords == null ? List.of() : registeredRecords
        );
    }

    /**
     * Returns an immutable snapshot of all registered {@link MethodBindingAdmissionRecord}s.
     */
    public List<MethodBindingAdmissionRecord> registeredAdmissionRecords() {
        return List.copyOf(registeredRecords);
    }

    /**
     * Enriches an already-registered {@link MethodBindingAdmissionRecord} matching {@code pointKey}
     * with introspected {@link FieldLineageCatalogEntry} records from a governed resource service
     * ({@code Fase P10.13}).
     *
     * <p>Existing explicit {@link FieldLineageCatalogEntry} slots on the admission record take
     * precedence for the same {@code (schemaRef, operationRole, wirePath)}, while missing DTO
     * properties introspected from {@code ResponseDTO}, {@code CreateDTO}, and {@code UpdateDTO}
     * are appended deterministically.</p>
     *
     * @param pointKey canonical decision point key
     * @param additionalLineageEntries introspected field lineage catalog entries
     * @return {@code true} if a matching record was found and enriched
     */
    public boolean enrichFieldLineageForPointKey(
            String pointKey,
            List<FieldLineageCatalogEntry> additionalLineageEntries
    ) {
        if (pointKey == null || pointKey.isBlank()
                || additionalLineageEntries == null || additionalLineageEntries.isEmpty()) {
            return false;
        }
        for (int i = 0; i < registeredRecords.size(); i++) {
            MethodBindingAdmissionRecord current = registeredRecords.get(i);
            if (pointKey.equals(current.decisionPoint().identity().pointKey())) {
                Map<String, FieldLineageCatalogEntry> merged = new LinkedHashMap<>();
                Map<String, FieldLineageCatalogEntry> existingByAttributeId = new LinkedHashMap<>();
                for (FieldLineageCatalogEntry existing : current.fieldLineageEntries()) {
                    String slot = existing.schemaRef() + "|" + existing.operationRole() + "|" + existing.wirePath();
                    merged.put(slot, existing);
                    existingByAttributeId.putIfAbsent(existing.attributeId(), existing);
                }
                for (FieldLineageCatalogEntry extra : additionalLineageEntries) {
                    String slot = extra.schemaRef() + "|" + extra.operationRole() + "|" + extra.wirePath();
                    FieldLineageCatalogEntry canonicalForAttr = existingByAttributeId.get(extra.attributeId());
                    FieldLineageCatalogEntry normalized = harmonizeWithCanonicalAttributeIfCompatible(extra, canonicalForAttr);
                    merged.putIfAbsent(slot, normalized);
                }
                MethodBindingAdmissionRecord enriched = new MethodBindingAdmissionRecord(
                        current.serviceKey(),
                        current.decisionPoint(),
                        current.enforcementBinding(),
                        current.admittedChannels(),
                        current.proxyEnforcedWithoutSelfInvocationBypass(),
                        List.copyOf(merged.values())
                );
                registeredRecords.set(i, enriched);
                return true;
            }
        }
        return false;
    }

    /**
     * Registers a new {@link MethodBindingAdmissionRecord} or enriches an existing one with matching
     * {@code pointKey} ({@code Fase P10.13}).
     */
    public void registerOrEnrichAdmissionRecord(MethodBindingAdmissionRecord record) {
        Objects.requireNonNull(record, "record is required");
        String pointKey = record.decisionPoint().identity().pointKey();
        if (!enrichFieldLineageForPointKey(pointKey, record.fieldLineageEntries())) {
            for (MethodBindingAdmissionRecord existing : registeredRecords) {
                if (pointKey.equals(existing.decisionPoint().identity().pointKey())) {
                    return;
                }
            }
            registeredRecords.add(record);
        }
    }

    /**
     * Queries the admitted semantic catalog for a specific {@code serviceKey}, enforcing
     * administrative authority, service scope isolation, proxy enforcement, explicit lineage,
     * and graph expansion budgets ({@code P34..P64}).
     */
    public PapCatalogViewResponse queryCatalogForPap(PapCatalogQueryRequest request) {
        Objects.requireNonNull(request, "request is required");

        // 1. P35, P54, P62: Verify administrative catalog authority
        String requiredAuth = properties.getDiscovery().getRequiredCatalogAuthority();
        if (!request.callerAuthorities().contains(requiredAuth)) {
            throw new SecurityException("AUTHZ_PAP_CATALOG_AUTHORITY_DENIED: Caller '"
                    + request.callerPrincipalId() + "' lacks required authority '" + requiredAuth + "' (P35/P62)");
        }

        // 2. P35, P43, P54: Enforce service-scope isolation (author cannot inspect another scope)
        if (!request.allowedServiceScopes().contains(request.requestedServiceKey())) {
            throw new SecurityException("AUTHZ_PAP_CATALOG_SCOPE_DENIED: Caller '"
                    + request.callerPrincipalId() + "' is not authorized for service scope '"
                    + request.requestedServiceKey() + "' (P43/P54)");
        }

        List<DecisionPointDescriptor> admittedPoints = new ArrayList<>();
        Map<String, List<FieldLineageCatalogEntry>> lineageByPointKey = new LinkedHashMap<>();
        List<String> rejectedDiagnostics = new ArrayList<>();

        for (MethodBindingAdmissionRecord record : registeredRecords) {
            if (!request.requestedServiceKey().equals(record.serviceKey())) {
                continue;
            }
            String pointKey = record.decisionPoint().identity().pointKey();
            List<String> pointErrors = validateAdmissionRecord(record);
            if (!pointErrors.isEmpty()) {
                // P57: Reject only the dependent/offending decision point with actionable diagnostics
                rejectedDiagnostics.addAll(pointErrors);
                continue;
            }
            admittedPoints.add(record.decisionPoint());
            lineageByPointKey.put(pointKey, record.fieldLineageEntries());
        }

        String catalogDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST,
                request.requestedServiceKey() + "|"
                        + admittedPoints.stream().map(dp -> dp.identity().pointKey()).toList() + "|"
                        + rejectedDiagnostics
        );

        return new PapCatalogViewResponse(
                request.requestedServiceKey(),
                catalogDigest,
                admittedPoints,
                lineageByPointKey,
                rejectedDiagnostics
        );
    }

    private List<String> validateAdmissionRecord(MethodBindingAdmissionRecord record) {
        List<String> errors = new ArrayList<>();
        String pointKey = record.decisionPoint().identity().pointKey();

        // P41: Self-invocation or unproxied method without real enforcement binding is rejected
        if (record.admittedChannels().isEmpty() || !record.proxyEnforcedWithoutSelfInvocationBypass()) {
            errors.add("CATALOG_REJECT_UNPROXIED_OR_SELF_INVOCATION:" + pointKey);
        }

        Map<String, String> attributeBySchemaRoleAndWirePath = new LinkedHashMap<>();
        Map<String, String> classificationByAttributeId = new LinkedHashMap<>();
        Map<String, String> conceptByAttributeId = new LinkedHashMap<>();
        Map<String, String> aiUsageByAttributeId = new LinkedHashMap<>();
        Map<String, FieldLineageCatalogEntry> entryByAttributeId = new LinkedHashMap<>();
        Map<String, List<String>> upstreamGraph = new LinkedHashMap<>();

        for (FieldLineageCatalogEntry field : record.fieldLineageEntries()) {
            // P57: Heuristic or permissive-default AI usage/governance is rejected
            if (!field.explicitGovernanceDeclared()
                    || "DEFAULT_PERMISSIVE".equalsIgnoreCase(field.aiUsageMode())
                    || "HEURISTIC".equalsIgnoreCase(field.sensitivityClassification())) {
                errors.add("CATALOG_REJECT_HEURISTIC_OR_PERMISSIVE_DEFAULT:" + pointKey + ":" + field.wirePath());
            }

            // P45 & P58: Detect ambiguous homonyms on the same (schemaRef, operationRole, wirePath)
            String wireSlotKey = field.schemaRef() + "|" + field.operationRole() + "|" + field.wirePath();
            String existingAttr = attributeBySchemaRoleAndWirePath.putIfAbsent(wireSlotKey, field.attributeId());
            if (existingAttr != null && !existingAttr.equals(field.attributeId())) {
                errors.add("CATALOG_REJECT_AMBIGUOUS_HOMONYM_WIRE_PATH:" + pointKey + ":" + wireSlotKey);
            }

            // P44 & P49: Same attributeId across DTOs/roles must not have contradictory sensitivity classification, conceptId, or aiUsageMode
            String existingClass = classificationByAttributeId.putIfAbsent(
                    field.attributeId(), field.sensitivityClassification());
            if (existingClass != null && !existingClass.equals(field.sensitivityClassification())) {
                errors.add("CATALOG_REJECT_CONTRADICTORY_ATTRIBUTE_CLASSIFICATION:" + pointKey + ":" + field.attributeId());
            }
            if (field.conceptId() != null) {
                String existingConcept = conceptByAttributeId.putIfAbsent(field.attributeId(), field.conceptId());
                if (existingConcept != null && !existingConcept.equals(field.conceptId())) {
                    errors.add("CATALOG_REJECT_CONTRADICTORY_ATTRIBUTE_CONCEPT:" + pointKey + ":" + field.attributeId());
                }
            }
            String existingAiUsage = aiUsageByAttributeId.putIfAbsent(field.attributeId(), field.aiUsageMode());
            if (existingAiUsage != null && !existingAiUsage.equals(field.aiUsageMode())) {
                errors.add("CATALOG_REJECT_CONTRADICTORY_ATTRIBUTE_AI_USAGE:" + pointKey + ":" + field.attributeId());
            }

            entryByAttributeId.putIfAbsent(field.attributeId(), field);
            upstreamGraph.put(field.attributeId(), field.upstreamAttributeRefs());
        }

        // P4-R02 (P46, P49, P56): Verify derived fields do not widen export/AI usage or declassify ancestor sensitivity
        for (FieldLineageCatalogEntry field : record.fieldLineageEntries()) {
            for (String upstreamAttrId : field.upstreamAttributeRefs()) {
                FieldLineageCatalogEntry upstream = entryByAttributeId.get(upstreamAttrId);
                if (upstream == null) {
                    continue;
                }
                if (!upstream.exportable() && field.exportable()) {
                    errors.add("CATALOG_REJECT_DERIVED_EXPORT_WIDENING:" + pointKey + ":" + field.attributeId());
                }
                if ("DENIED".equalsIgnoreCase(upstream.aiUsageMode())
                        && !"DENIED".equalsIgnoreCase(field.aiUsageMode())) {
                    errors.add("CATALOG_REJECT_DERIVED_AI_USAGE_WIDENING:" + pointKey + ":" + field.attributeId());
                }
                if (sensitivityRank(field.sensitivityClassification())
                        < sensitivityRank(upstream.sensitivityClassification())) {
                    errors.add("CATALOG_REJECT_UNAPPROVED_DERIVED_DECLASSIFICATION:" + pointKey + ":" + field.attributeId());
                }
            }
        }

        // P64: Cycle detection and depth/branch budget check on lineage selector graph before expansion
        int maxDepth = properties.getDiscovery().getMaxLineageDepth();
        int maxBranches = properties.getDiscovery().getMaxLineageBranches();

        for (String rootAttr : upstreamGraph.keySet()) {
            int[] totalBranches = {0};
            if (!checkLineageGraphRecursive(
                    rootAttr,
                    upstreamGraph,
                    new HashSet<>(),
                    0,
                    maxDepth,
                    maxBranches,
                    totalBranches,
                    pointKey,
                    errors)) {
                break;
            }
        }

        return errors;
    }

    private static boolean checkLineageGraphRecursive(
            String currentAttr,
            Map<String, List<String>> graph,
            Set<String> visitingPath,
            int currentDepth,
            int maxDepth,
            int maxBranches,
            int[] totalBranches,
            String pointKey,
            List<String> errors
    ) {
        if (!visitingPath.add(currentAttr)) {
            errors.add("CATALOG_REJECT_LINEAGE_CYCLE:" + pointKey + ":" + currentAttr);
            return false;
        }
        if (currentDepth > maxDepth) {
            errors.add("CATALOG_REJECT_LINEAGE_DEPTH_EXCEEDED:" + pointKey + ":" + currentAttr);
            visitingPath.remove(currentAttr);
            return false;
        }
        List<String> parents = graph.getOrDefault(currentAttr, List.of());
        for (String parent : parents) {
            totalBranches[0]++;
            if (totalBranches[0] > maxBranches) {
                errors.add("CATALOG_REJECT_LINEAGE_BRANCH_BUDGET_EXCEEDED:" + pointKey);
                visitingPath.remove(currentAttr);
                return false;
            }
            if (!checkLineageGraphRecursive(
                    parent, graph, visitingPath, currentDepth + 1, maxDepth, maxBranches, totalBranches, pointKey, errors)) {
                visitingPath.remove(currentAttr);
                return false;
            }
        }
        visitingPath.remove(currentAttr);
        return true;
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
        int candidateAiRank = aiUsageRestrictivenessRank(candidate.aiUsageMode());
        int canonicalAiRank = aiUsageRestrictivenessRank(canonical.aiUsageMode());
        boolean compatibleAiUsage = Objects.equals(candidate.aiUsageMode(), canonical.aiUsageMode())
                || (candidateAiRank > 0 && canonicalAiRank >= candidateAiRank);
        boolean sameExportable = candidate.exportable() == canonical.exportable();
        if (hasDefaultConcept && sameRank && compatibleAiUsage && sameExportable) {
            return new FieldLineageCatalogEntry(
                    candidate.attributeId(),
                    canonical.conceptId(),
                    candidate.schemaRef(),
                    candidate.wirePath(),
                    candidate.operationRole(),
                    canonical.sensitivityClassification(),
                    canonical.aiUsageMode(),
                    candidate.exportable(),
                    candidate.allowedUseCategories(),
                    candidate.upstreamAttributeRefs(),
                    candidate.explicitGovernanceDeclared()
            );
        }
        return candidate;
    }

    private static int aiUsageRestrictivenessRank(String aiUsageMode) {
        if (aiUsageMode == null) {
            return 0;
        }
        return switch (aiUsageMode.trim().toUpperCase(java.util.Locale.ROOT)) {
            case "DENIED", "FORBIDDEN" -> 4;
            case "SCHEMA_METADATA_ONLY", "METADATA_ONLY" -> 3;
            case "MASKED_ONLY" -> 2;
            case "ALLOWED", "VALUE_ALLOWED" -> 1;
            default -> 0;
        };
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
}
