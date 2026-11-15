package org.praxisplatform.authz.export;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import org.praxisplatform.authz.catalog.FieldLineageCatalogEntry;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor.RowMaskingInput;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;

/**
 * Enforces static lineage exportability ({@code exportable = false} and inherited ancestor
 * restrictions), dynamic per-row masking/redaction, and active policy revision freshness across
 * {@code CSV}, {@code JSON}, and {@code EXCEL_TSV} collection exports ({@code P11}, {@code P12},
 * {@code P18}, {@code P25}, {@code P56}, {@code P60}).
 */
public final class GovernedCollectionExportGuard {

    /** Supported export serialization formats. */
    public enum ExportFormat {
        CSV,
        JSON,
        EXCEL_TSV
    }

    /** Sanitized export payload with headers, detached rows, and serialized bytes. */
    public record SanitizedExportArtifact(
            ExportFormat format,
            String runtimeRevision,
            String policySetDigest,
            List<String> exportedColumns,
            List<Map<String, Object>> sanitizedRows,
            byte[] bytes
    ) {}

    private final DetachedDtoMaskingProcessor maskingProcessor;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public GovernedCollectionExportGuard(DetachedDtoMaskingProcessor maskingProcessor) {
        this.maskingProcessor = Objects.requireNonNull(maskingProcessor, "maskingProcessor is required");
    }

    /**
     * Executes governed per-row projection, static + inherited exportability filtering, and
     * revision freshness verification before serializing export bytes ({@code P11}, {@code P12},
     * {@code P18}, {@code P25}, {@code P60}).
     */
    public SanitizedExportArtifact exportCollection(
            ExportFormat format,
            String expectedRuntimeRevision,
            String expectedPolicySetDigest,
            Supplier<OpaRuntimeHead> liveHeadSupplier,
            List<DtoFieldSchemaMetadata> fieldSchemas,
            List<FieldLineageCatalogEntry> lineageEntries,
            List<RowMaskingInput> rowInputs
    ) {
        Objects.requireNonNull(format, "format is required");
        Objects.requireNonNull(expectedRuntimeRevision, "expectedRuntimeRevision is required");
        Objects.requireNonNull(expectedPolicySetDigest, "expectedPolicySetDigest is required");
        Objects.requireNonNull(liveHeadSupplier, "liveHeadSupplier is required");
        Objects.requireNonNull(fieldSchemas, "fieldSchemas is required");
        Objects.requireNonNull(lineageEntries, "lineageEntries is required");
        Objects.requireNonNull(rowInputs, "rowInputs is required");

        // 1. P18: Verify policy freshness / non-revocation before generating export stream/file
        OpaRuntimeHead liveHead = liveHeadSupplier.get();
        if (liveHead == null
                || !expectedRuntimeRevision.equals(liveHead.runtimeRevision())
                || !expectedPolicySetDigest.equals(liveHead.policySetDigest())) {
            throw new SecurityException("AUTHZ_EXPORT_REVOKED_OR_REVISION_DRIFT: Policy revision changed or was revoked during export generation (P18)");
        }

        // 2. P56 & P60: Resolve static + inherited non-exportable attributeIds from lineage catalog
        Set<String> nonExportableAttributeIds = resolveNonExportableAttributes(lineageEntries);

        // 3. Augment each row's valueDeniedAttributeIds with static non-exportable attributes (P11, P60)
        List<RowMaskingInput> effectiveRows = new ArrayList<>(rowInputs.size());
        for (RowMaskingInput row : rowInputs) {
            Set<String> combinedDenied = new LinkedHashSet<>(row.valueDeniedAttributeIds());
            combinedDenied.addAll(nonExportableAttributeIds);
            effectiveRows.add(new RowMaskingInput(row.rowDtoOrMap(), combinedDenied, row.maskDirectives()));
        }

        // 4. P12 & P25: Apply per-row detached masking without cross-row leakage
        List<DetachedDtoMaskingResult> maskedResults = maskingProcessor.projectAndMaskPage(effectiveRows, fieldSchemas);

        // 5. Re-check live head after row processing before byte emission (P18 stream guard)
        OpaRuntimeHead postHead = liveHeadSupplier.get();
        if (postHead == null
                || !expectedRuntimeRevision.equals(postHead.runtimeRevision())
                || !expectedPolicySetDigest.equals(postHead.policySetDigest())) {
            throw new SecurityException("AUTHZ_EXPORT_REVOKED_OR_REVISION_DRIFT: Policy revoked before export byte completion (P18)");
        }

        // 6. Determine allowed export columns (excluding statically non-exportable fields from headers/bytes — P11, P60)
        List<String> exportedColumns = new ArrayList<>();
        for (DtoFieldSchemaMetadata schema : fieldSchemas) {
            if (!nonExportableAttributeIds.contains(schema.attributeId())) {
                exportedColumns.add(schema.wireFieldName());
            }
        }

        List<Map<String, Object>> sanitizedRows = new ArrayList<>(maskedResults.size());
        for (DetachedDtoMaskingResult res : maskedResults) {
            Map<String, Object> cleanRow = new LinkedHashMap<>();
            for (String col : exportedColumns) {
                OptionalValue extracted = extractNestedValue(res.detachedProjection(), col);
                if (extracted.present()) {
                    cleanRow.put(col, extracted.value());
                }
            }
            sanitizedRows.add(cleanRow);
        }

        byte[] bytes = serializeExportBytes(format, exportedColumns, sanitizedRows);
        return new SanitizedExportArtifact(
                format,
                expectedRuntimeRevision,
                expectedPolicySetDigest,
                List.copyOf(exportedColumns),
                List.copyOf(sanitizedRows),
                bytes
        );
    }

    private record OptionalValue(boolean present, Object value) {}

    @SuppressWarnings("unchecked")
    private static OptionalValue extractNestedValue(Map<String, Object> projection, String wireFieldName) {
        if (projection.containsKey(wireFieldName)) {
            return new OptionalValue(true, projection.get(wireFieldName));
        }
        String normalized = wireFieldName.startsWith("/") ? wireFieldName.substring(1) : wireFieldName;
        String[] segments = normalized.contains("/") ? normalized.split("/") : normalized.split("\\.");
        if (segments.length <= 1) {
            return new OptionalValue(false, null);
        }
        Object current = projection;
        for (int i = 0; i < segments.length; i++) {
            if (!(current instanceof Map<?, ?> rawMap)) {
                return new OptionalValue(false, null);
            }
            Map<String, Object> map = (Map<String, Object>) rawMap;
            String seg = segments[i];
            if (!map.containsKey(seg)) {
                return new OptionalValue(false, null);
            }
            current = map.get(seg);
        }
        return new OptionalValue(true, current);
    }

    private static Set<String> resolveNonExportableAttributes(List<FieldLineageCatalogEntry> entries) {
        Map<String, List<FieldLineageCatalogEntry>> byAttr = new LinkedHashMap<>();
        for (FieldLineageCatalogEntry entry : entries) {
            byAttr.computeIfAbsent(entry.attributeId(), k -> new ArrayList<>()).add(entry);
        }
        Set<String> nonExportable = new LinkedHashSet<>();
        for (FieldLineageCatalogEntry entry : entries) {
            if (!entry.exportable() || hasNonExportableAncestor(entry, byAttr, new LinkedHashSet<>())) {
                nonExportable.add(entry.attributeId());
            }
        }
        return nonExportable;
    }

    private static boolean hasNonExportableAncestor(
            FieldLineageCatalogEntry current,
            Map<String, List<FieldLineageCatalogEntry>> byAttr,
            Set<String> visited
    ) {
        if (!visited.add(current.attributeId())) {
            return false;
        }
        for (String parentId : current.upstreamAttributeRefs()) {
            List<FieldLineageCatalogEntry> parents = byAttr.getOrDefault(parentId, List.of());
            if (parents.isEmpty()) {
                // P45 / P56 / P60: Unresolved or missing upstream lineage parent fails closed as non-exportable
                return true;
            }
            for (FieldLineageCatalogEntry parent : parents) {
                if (!parent.exportable() || hasNonExportableAncestor(parent, byAttr, visited)) {
                    return true;
                }
            }
        }
        return false;
    }

    private byte[] serializeExportBytes(
            ExportFormat format,
            List<String> columns,
            List<Map<String, Object>> rows
    ) {
        try {
            return switch (format) {
                case JSON -> objectMapper.writeValueAsBytes(rows);
                case CSV -> buildDelimitedText(columns, rows, ',').getBytes(StandardCharsets.UTF_8);
                case EXCEL_TSV -> buildDelimitedText(columns, rows, '\t').getBytes(StandardCharsets.UTF_8);
            };
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to serialize governed export artifact: " + ex.getMessage(), ex);
        }
    }

    private static String buildDelimitedText(
            List<String> columns,
            List<Map<String, Object>> rows,
            char delimiter
    ) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < columns.size(); i++) {
            if (i > 0) {
                sb.append(delimiter);
            }
            sb.append(escapeDelimitedCell(columns.get(i), delimiter));
        }
        sb.append('\n');
        for (Map<String, Object> row : rows) {
            for (int i = 0; i < columns.size(); i++) {
                if (i > 0) {
                    sb.append(delimiter);
                }
                Object val = row.get(columns.get(i));
                sb.append(val == null ? "" : escapeDelimitedCell(String.valueOf(val), delimiter));
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    private static String escapeDelimitedCell(String raw, char delimiter) {
        if (raw.isEmpty()) {
            return "";
        }
        String sanitized = raw;
        char first = sanitized.charAt(0);
        if ((first == '=' || first == '+' || first == '@' || (first == '-' && !sanitized.matches("^-[0-9]+(\\.[0-9]+)?$")))) {
            sanitized = "'" + sanitized;
        }
        boolean mustQuote = sanitized.indexOf(delimiter) >= 0
                || sanitized.indexOf('"') >= 0
                || sanitized.indexOf('\n') >= 0
                || sanitized.indexOf('\r') >= 0;
        if (!mustQuote) {
            return sanitized;
        }
        return "\"" + sanitized.replace("\"", "\"\"") + "\"";
    }
}
