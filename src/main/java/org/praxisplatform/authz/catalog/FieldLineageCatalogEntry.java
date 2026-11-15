package org.praxisplatform.authz.catalog;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;

/**
 * Canonical field lineage and governance entry published in the semantic PAP catalog
 * ({@code P36}, {@code P44}, {@code P45}, {@code P57}, {@code P58}, {@code P62}, {@code P64}).
 *
 * @param attributeId canonical {@code @DomainLineage.attributeId} (must not be inferred by field name — {@code P45})
 * @param conceptId canonical semantic concept identifier
 * @param schemaRef canonical DTO schema reference ({@code P58}, {@code P59})
 * @param wirePath JSON wire path on the given schema (e.g. {@code "cidCodigo"}, {@code "servidor.cpf"} — {@code P44}, {@code P58})
 * @param operationRole role of the field in the operation ({@code READ_PROJECTION}, {@code CREATE_INPUT}, {@code UPDATE_INPUT}, {@code FILTER_PREDICATE} — {@code P44}, {@code P58})
 * @param sensitivityClassification explicit domain sensitivity classification (e.g. {@code "HEALTH_SENSITIVE"}, {@code "PII_RESTRICTED"}, {@code "PUBLIC_OPERATIONAL"})
 * @param aiUsageMode explicit AI usage policy (never defaults permissively — {@code P57}, {@code P62})
 * @param exportable whether static governance allows collection export ({@code P56}, {@code P60})
 * @param allowedUseCategories admitted {@link FieldUseCategory} values for policy authoring ({@code P43}, {@code P50})
 * @param upstreamAttributeRefs upstream lineage attribute IDs used for derived/computed fields ({@code P46}, {@code P64})
 * @param explicitGovernanceDeclared whether governance metadata was explicitly declared rather than heuristically inferred ({@code P57})
 */
public record FieldLineageCatalogEntry(
        String attributeId,
        String conceptId,
        String schemaRef,
        String wirePath,
        String operationRole,
        String sensitivityClassification,
        String aiUsageMode,
        boolean exportable,
        Set<FieldUseCategory> allowedUseCategories,
        List<String> upstreamAttributeRefs,
        boolean explicitGovernanceDeclared
) {

    /** Validates required lineage identifiers and explicit governance flags. */
    public FieldLineageCatalogEntry {
        attributeId = requireNonBlank(attributeId, "attributeId");
        conceptId = requireNonBlank(conceptId, "conceptId");
        schemaRef = requireNonBlank(schemaRef, "schemaRef");
        wirePath = requireNonBlank(wirePath, "wirePath");
        operationRole = requireNonBlank(operationRole, "operationRole");
        sensitivityClassification = requireNonBlank(sensitivityClassification, "sensitivityClassification");
        aiUsageMode = requireNonBlank(aiUsageMode, "aiUsageMode");
        allowedUseCategories = allowedUseCategories == null ? Set.of() : Set.copyOf(allowedUseCategories);
        upstreamAttributeRefs = upstreamAttributeRefs == null ? List.of() : List.copyOf(upstreamAttributeRefs);
    }

    private static String requireNonBlank(String value, String field) {
        Objects.requireNonNull(value, field + " is required");
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return trimmed;
    }
}
