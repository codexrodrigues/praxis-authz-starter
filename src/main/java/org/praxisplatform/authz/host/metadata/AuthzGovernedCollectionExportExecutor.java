package org.praxisplatform.authz.host.metadata;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.uischema.exporting.CollectionExportExecutor;
import org.praxisplatform.uischema.exporting.CollectionExportField;
import org.praxisplatform.uischema.exporting.CollectionExportRequest;
import org.praxisplatform.uischema.exporting.CollectionExportResult;
import org.praxisplatform.uischema.exporting.CollectionExportValueResolver;

/**
 * Decorator around {@code praxis-metadata-starter}'s {@link CollectionExportExecutor}
 * (such as {@code DefaultCollectionExportExecutor}) that enforces attribute-level export
 * eligibility ({@code @DomainGovernance(exportable = false)}), strips dynamically or statically
 * value-denied ({@code VALUE + DENY}) and {@code OMIT_FIELD} columns, and applies
 * active OPA {@link MaskDirective}s on every exported row before delegating to the CSV/JSON/Excel
 * engine ({@code CC07}, {@code P11}, {@code P12}, {@code P16}, {@code Fase P10.17-A}).
 */
public final class AuthzGovernedCollectionExportExecutor implements CollectionExportExecutor {

    private final CollectionExportExecutor delegate;
    private final DetachedDtoMaskingProcessor maskingProcessor;
    private final List<DtoFieldSchemaMetadata> fieldSchemas;
    private final Set<String> nonExportableFieldNames;
    private final Set<String> staticValueDeniedAttributeIds;
    private final List<MaskDirective> activeMaskDirectives;
    private final Supplier<List<MaskDirective>> dynamicMaskDirectivesSupplier;
    private final Supplier<Set<String>> dynamicValueDeniedSupplier;
    private final ObjectMapper objectMapper;

    /**
     * Creates a governed export executor wrapping a {@link CollectionExportExecutor} delegate.
     *
     * @param delegate underlying {@link CollectionExportExecutor} (e.g., {@code DefaultCollectionExportExecutor})
     * @param maskingProcessor detached DTO masking processor
     * @param fieldSchemas canonical DTO field schema descriptors
     * @param nonExportableFieldNames DTO property names with {@code exportable = false}
     * @param activeMaskDirectives active {@link MaskDirective}s to apply to exported rows
     */
    public AuthzGovernedCollectionExportExecutor(
            CollectionExportExecutor delegate,
            DetachedDtoMaskingProcessor maskingProcessor,
            List<DtoFieldSchemaMetadata> fieldSchemas,
            Set<String> nonExportableFieldNames,
            List<MaskDirective> activeMaskDirectives
    ) {
        this(
                delegate,
                maskingProcessor,
                fieldSchemas,
                nonExportableFieldNames,
                Set.of(),
                activeMaskDirectives,
                List::of,
                Set::of
        );
    }

    /**
     * Creates a governed export executor from an {@link IntrospectedDtoGovernanceContract} and
     * a dynamic per-request {@link MaskDirective} supplier ({@code P10.2-R03}).
     *
     * @param delegate underlying {@link CollectionExportExecutor}
     * @param maskingProcessor detached DTO masking processor
     * @param dtoContract introspected DTO governance contract
     * @param dynamicMaskDirectivesSupplier supplier of per-request OPA {@link MaskDirective}s
     */
    public AuthzGovernedCollectionExportExecutor(
            CollectionExportExecutor delegate,
            DetachedDtoMaskingProcessor maskingProcessor,
            IntrospectedDtoGovernanceContract dtoContract,
            Supplier<List<MaskDirective>> dynamicMaskDirectivesSupplier
    ) {
        this(
                delegate,
                maskingProcessor,
                dtoContract,
                dynamicMaskDirectivesSupplier,
                Set::of
        );
    }

    /**
     * Creates a governed export executor from an {@link IntrospectedDtoGovernanceContract} with
     * dynamic per-request OPA {@link MaskDirective} and {@code VALUE + DENY} attribute suppliers
     * ({@code Fase P10.17-A}).
     *
     * @param delegate underlying {@link CollectionExportExecutor}
     * @param maskingProcessor detached DTO masking processor
     * @param dtoContract introspected DTO governance contract
     * @param dynamicMaskDirectivesSupplier supplier of per-request OPA {@link MaskDirective}s
     * @param dynamicValueDeniedSupplier supplier of per-request dynamically value-denied attribute IDs
     */
    public AuthzGovernedCollectionExportExecutor(
            CollectionExportExecutor delegate,
            DetachedDtoMaskingProcessor maskingProcessor,
            IntrospectedDtoGovernanceContract dtoContract,
            Supplier<List<MaskDirective>> dynamicMaskDirectivesSupplier,
            Supplier<Set<String>> dynamicValueDeniedSupplier
    ) {
        this(
                delegate,
                maskingProcessor,
                Objects.requireNonNull(dtoContract, "dtoContract is required").fieldSchemas(),
                dtoContract.nonExportableFieldNames(),
                extractStaticValueDeniedAttributes(dtoContract),
                List.of(),
                dynamicMaskDirectivesSupplier,
                dynamicValueDeniedSupplier
        );
    }

    private AuthzGovernedCollectionExportExecutor(
            CollectionExportExecutor delegate,
            DetachedDtoMaskingProcessor maskingProcessor,
            List<DtoFieldSchemaMetadata> fieldSchemas,
            Set<String> nonExportableFieldNames,
            Set<String> staticValueDeniedAttributeIds,
            List<MaskDirective> activeMaskDirectives,
            Supplier<List<MaskDirective>> dynamicMaskDirectivesSupplier,
            Supplier<Set<String>> dynamicValueDeniedSupplier
    ) {
        this.delegate = Objects.requireNonNull(delegate, "delegate is required");
        this.maskingProcessor = Objects.requireNonNull(maskingProcessor, "maskingProcessor is required");
        this.fieldSchemas = fieldSchemas == null ? List.of() : List.copyOf(fieldSchemas);
        Set<String> combinedNonExportable = new LinkedHashSet<>();
        if (nonExportableFieldNames != null) {
            combinedNonExportable.addAll(nonExportableFieldNames);
        }
        for (DtoFieldSchemaMetadata schema : this.fieldSchemas) {
            if (combinedNonExportable.contains(schema.wireFieldName())
                    || combinedNonExportable.contains(schema.attributeId())) {
                combinedNonExportable.add(schema.wireFieldName());
                combinedNonExportable.add(schema.attributeId());
            }
        }
        this.nonExportableFieldNames = Set.copyOf(combinedNonExportable);
        this.staticValueDeniedAttributeIds = staticValueDeniedAttributeIds == null
                ? Set.of()
                : Set.copyOf(staticValueDeniedAttributeIds);
        this.activeMaskDirectives = activeMaskDirectives == null ? List.of() : List.copyOf(activeMaskDirectives);
        this.dynamicMaskDirectivesSupplier =
                Objects.requireNonNull(dynamicMaskDirectivesSupplier, "dynamicMaskDirectivesSupplier is required");
        this.dynamicValueDeniedSupplier =
                Objects.requireNonNull(dynamicValueDeniedSupplier, "dynamicValueDeniedSupplier is required");
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }

    /**
     * Filters a raw list of {@link CollectionExportField}s at capability/schema discovery time
     * ({@code exportFields()} / {@code supportsCollectionExport()}), removing fields marked
     * {@code exportable = false} or statically denied for {@link FieldUseCategory#VALUE}
     * ({@code SECRET} / {@code CREDENTIAL}) in {@code dtoContract} ({@code Fase P10.22-A}, {@code P10}, {@code P16}, {@code P46}).
     */
    public static List<CollectionExportField> filterDiscoveryExportFields(
            List<CollectionExportField> rawFields,
            IntrospectedDtoGovernanceContract dtoContract
    ) {
        if (rawFields == null || rawFields.isEmpty()) {
            return List.of();
        }
        if (dtoContract == null) {
            return rawFields.stream()
                    .filter(Objects::nonNull)
                    .filter(f -> f.exportable() != Boolean.FALSE)
                    .toList();
        }
        Set<String> forbidden = new LinkedHashSet<>();
        if (dtoContract.nonExportableFieldNames() != null) {
            forbidden.addAll(dtoContract.nonExportableFieldNames());
        }
        forbidden.addAll(extractStaticValueDeniedAttributes(dtoContract));
        if (dtoContract.fieldSchemas() != null) {
            for (DtoFieldSchemaMetadata schema : dtoContract.fieldSchemas()) {
                if (forbidden.contains(schema.wireFieldName()) || forbidden.contains(schema.attributeId())) {
                    forbidden.add(schema.wireFieldName());
                    forbidden.add(schema.attributeId());
                }
            }
        }
        return rawFields.stream()
                .filter(Objects::nonNull)
                .filter(f -> f.exportable() != Boolean.FALSE)
                .filter(f -> {
                    if (f.key() != null && forbidden.contains(f.key().trim())) {
                        return false;
                    }
                    if (f.valuePath() != null && !f.valuePath().isBlank() && forbidden.contains(f.valuePath().trim())) {
                        return false;
                    }
                    return true;
                })
                .toList();
    }

    private static Set<String> extractStaticValueDeniedAttributes(IntrospectedDtoGovernanceContract dtoContract) {
        if (dtoContract == null || dtoContract.baselineFieldUseDirectives() == null) {
            return Set.of();
        }
        Set<String> denied = new LinkedHashSet<>();
        for (FieldUseEffectDirective dir : dtoContract.baselineFieldUseDirectives()) {
            if (dir != null
                    && dir.category() == FieldUseCategory.VALUE
                    && dir.effect() == RuleEffect.DENY
                    && dir.attributeId() != null) {
                denied.add(dir.attributeId());
            }
        }
        return Set.copyOf(denied);
    }

    @Override
    public <T> CollectionExportResult export(
            CollectionExportRequest<?> request,
            List<T> rows,
            List<CollectionExportField> defaultFields,
            CollectionExportValueResolver<T> valueResolver,
            Map<String, Object> metadata
    ) {
        Objects.requireNonNull(valueResolver, "valueResolver must not be null");
        List<MaskDirective> effectiveMaskDirectives = resolveEffectiveMaskDirectives();
        Set<String> effectiveValueDeniedAttributeIds = resolveEffectiveValueDeniedAttributeIds();
        Set<String> effectiveForbiddenFieldNames = resolveEffectiveForbiddenExportFields(
                effectiveValueDeniedAttributeIds,
                effectiveMaskDirectives
        );
        List<CollectionExportField> sanitizedDefaultFields =
                filterExportableFields(defaultFields, effectiveForbiddenFieldNames);
        CollectionExportRequest<?> sanitizedRequest = request == null ? null : new CollectionExportRequest<>(
                request.componentType(),
                request.componentId(),
                request.resourcePath(),
                request.format(),
                request.scope(),
                request.selection(),
                request.fields() == null ? null : filterExportableFields(request.fields(), effectiveForbiddenFieldNames),
                request.filters(),
                request.sort(),
                request.pagination(),
                request.query(),
                request.includeHeaders(),
                request.applyFormatting(),
                request.maxRows(),
                request.fileName(),
                request.formatOptions(),
                request.localization(),
                request.metadata()
        );

        List<T> safeRows = rows == null ? List.of() : rows;
        List<Map<String, Object>> maskedProjections = new ArrayList<>(safeRows.size());
        for (T row : safeRows) {
            Map<String, Object> rawMap = objectMapper.convertValue(row, new TypeReference<Map<String, Object>>() {});
            DetachedDtoMaskingResult masked = maskingProcessor.projectAndMask(
                    rawMap, fieldSchemas, effectiveValueDeniedAttributeIds, effectiveMaskDirectives
            );
            Map<String, Object> cleanRow = new LinkedHashMap<>(masked.detachedProjection());
            for (String forbiddenField : effectiveForbiddenFieldNames) {
                cleanRow.remove(forbiddenField);
            }
            maskedProjections.add(cleanRow);
        }

        Map<Object, Map<String, Object>> maskedByRowIdentity = new java.util.IdentityHashMap<>();
        for (int i = 0; i < safeRows.size(); i++) {
            maskedByRowIdentity.put(safeRows.get(i), maskedProjections.get(i));
        }

        CollectionExportValueResolver<T> maskedValueResolver = (row, field) -> {
            if (isFieldNonExportable(field, effectiveForbiddenFieldNames)) {
                return null;
            }
            String valueKey = field.valuePath() != null && !field.valuePath().isBlank() ? field.valuePath() : field.key();
            Map<String, Object> maskedRow = maskedByRowIdentity.get(row);
            if (maskedRow != null) {
                if (maskedRow.containsKey(valueKey)) {
                    return maskedRow.get(valueKey);
                }
                if (field.key() != null && maskedRow.containsKey(field.key())) {
                    return maskedRow.get(field.key());
                }
                // Fail-closed: if the field was omitted by OMIT_FIELD or redacted from the detached projection,
                // never fall back to reading the raw unmasked row!
                return null;
            }
            return null;
        };

        Map<String, Object> enrichedMetadata = new LinkedHashMap<>(metadata == null ? Map.of() : metadata);
        enrichedMetadata.put("authzExportSanitized", true);
        enrichedMetadata.put("maskedDirectiveCount", effectiveMaskDirectives.size());
        enrichedMetadata.put("valueDeniedAttributeCount", effectiveValueDeniedAttributeIds.size());

        return delegate.export(
                sanitizedRequest,
                safeRows,
                sanitizedDefaultFields,
                maskedValueResolver,
                enrichedMetadata
        );
    }

    private List<MaskDirective> resolveEffectiveMaskDirectives() {
        List<MaskDirective> dynamic = dynamicMaskDirectivesSupplier.get();
        if (dynamic == null || dynamic.isEmpty()) {
            return activeMaskDirectives;
        }
        if (activeMaskDirectives.isEmpty()) {
            return List.copyOf(dynamic);
        }
        List<MaskDirective> merged = new ArrayList<>(activeMaskDirectives.size() + dynamic.size());
        merged.addAll(activeMaskDirectives);
        merged.addAll(dynamic);
        return List.copyOf(merged);
    }

    private Set<String> resolveEffectiveValueDeniedAttributeIds() {
        Set<String> dynamic = dynamicValueDeniedSupplier.get();
        if (dynamic == null || dynamic.isEmpty()) {
            return staticValueDeniedAttributeIds;
        }
        if (staticValueDeniedAttributeIds.isEmpty()) {
            return Set.copyOf(dynamic);
        }
        Set<String> merged = new LinkedHashSet<>(staticValueDeniedAttributeIds);
        merged.addAll(dynamic);
        return Set.copyOf(merged);
    }

    private Set<String> resolveEffectiveForbiddenExportFields(
            Set<String> effectiveValueDeniedAttributeIds,
            List<MaskDirective> effectiveMaskDirectives
    ) {
        Set<String> combined = new LinkedHashSet<>(nonExportableFieldNames);
        if (effectiveValueDeniedAttributeIds != null) {
            combined.addAll(effectiveValueDeniedAttributeIds);
        }
        if (effectiveMaskDirectives != null) {
            for (MaskDirective mask : effectiveMaskDirectives) {
                if (mask != null && "OMIT_FIELD".equals(mask.strategyId()) && mask.attributeId() != null) {
                    combined.add(mask.attributeId());
                }
            }
        }
        for (DtoFieldSchemaMetadata schema : fieldSchemas) {
            if (combined.contains(schema.wireFieldName()) || combined.contains(schema.attributeId())) {
                combined.add(schema.wireFieldName());
                combined.add(schema.attributeId());
            }
        }
        return Set.copyOf(combined);
    }

    private List<CollectionExportField> filterExportableFields(
            List<CollectionExportField> fields,
            Set<String> effectiveForbiddenFieldNames
    ) {
        if (fields == null || fields.isEmpty()) {
            return List.of();
        }
        return fields.stream()
                .filter(Objects::nonNull)
                .filter(f -> f.exportable() != Boolean.FALSE)
                .filter(f -> !isFieldNonExportable(f, effectiveForbiddenFieldNames))
                .toList();
    }

    private boolean isFieldNonExportable(
            CollectionExportField field,
            Set<String> effectiveForbiddenFieldNames
    ) {
        if (field == null) {
            return true;
        }
        if (field.key() != null && effectiveForbiddenFieldNames.contains(field.key())) {
            return true;
        }
        if (field.valuePath() != null
                && !field.valuePath().isBlank()
                && effectiveForbiddenFieldNames.contains(field.valuePath())) {
            return true;
        }
        return false;
    }
}
