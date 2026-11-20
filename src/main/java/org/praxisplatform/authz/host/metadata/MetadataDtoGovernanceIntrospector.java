package org.praxisplatform.authz.host.metadata;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.beans.Introspector;
import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.RecordComponent;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.praxisplatform.authz.catalog.FieldLineageCatalogEntry;
import org.praxisplatform.authz.contracts.annotation.AuthzCustodyPartition;
import org.praxisplatform.authz.contracts.annotation.AuthzMask;
import org.praxisplatform.authz.contracts.annotation.AuthzMaskStrategy;
import org.praxisplatform.authz.contracts.annotation.AuthzMasks;
import org.praxisplatform.authz.contracts.annotation.AuthzScopeAnchor;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.policy.MaskContributionSpec;
import org.praxisplatform.authz.contracts.policy.PolicyFieldSelector;
import org.praxisplatform.authz.enforcement.jpa.QueryAdapterFieldBinding;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.uischema.annotation.AiVisibilityMode;
import org.praxisplatform.uischema.annotation.DomainGovernance;
import org.praxisplatform.uischema.annotation.DomainLineage;
import org.praxisplatform.uischema.annotation.DomainLineageTransformation;
import org.praxisplatform.uischema.exporting.CollectionExportRequest;
import org.praxisplatform.uischema.extension.ResolverUtils;
import org.praxisplatform.uischema.filter.annotation.Filterable;
import org.praxisplatform.uischema.schema.DomainLineageResolver;
import org.praxisplatform.uischema.schema.DomainSchemaGovernance;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.data.domain.Sort;
import org.springframework.util.ClassUtils;

/**
 * Introspects Praxis DTO classes ({@code ResponseDTO}, {@code CreateDTO}, {@code UpdateDTO},
 * {@code FilterDTO}) annotated with {@link DomainLineage}, {@link DomainGovernance},
 * {@link AuthzMask}, and {@link Schema} to automatically derive authorization, masking, and
 * governance contracts without manual boilerplate ({@code CC07}, {@code CC09}, {@code P11},
 * {@code P12}, {@code P16}, {@code P44..P50}).
 */
public final class MetadataDtoGovernanceIntrospector {

    /**
     * Declarative mask binding extracted from {@link AuthzMask} including mode and surface scope.
     *
     * @param contribution compiled {@link MaskContributionSpec}
     * @param modes evaluation modes in which this mask applies
     * @param surfaces optional target {@code @UiSurface} identifiers (empty = all surfaces)
     * @param reason optional human-readable rationale
     */
    public record DeclaredMaskSpec(
            MaskContributionSpec contribution,
            Set<EvaluationMode> modes,
            Set<String> surfaces,
            String reason
    ) {
        public DeclaredMaskSpec {
            Objects.requireNonNull(contribution, "contribution is required");
            modes = modes == null || modes.isEmpty()
                    ? Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET)
                    : Set.copyOf(modes);
            surfaces = surfaces == null ? Set.of() : Set.copyOf(surfaces);
        }
    }

    /**
     * Immutable governance and schema contract derived from a DTO class.
     *
     * @param resourceKey canonical resource key owning the DTO
     * @param dtoType introspected DTO class
     * @param fieldSchemas ordered list of {@link DtoFieldSchemaMetadata} for detached masking
     * @param nonExportableFieldNames wire field names and attribute IDs with {@code exportable = false}
     * @param aiContextDeniedAttributeIds attribute IDs with {@link AiVisibilityMode#DENY}
     * @param baselineFieldUseDirectives baseline {@link FieldUseEffectDirective}s derived from {@link DomainGovernance}
     * @param wirePointerToAttributeIdMap JSON Pointer ({@code "/fieldName"}) to canonical {@code attributeId} map for {@code WriteIntent} extraction
     * @param derivedMasks masks automatically derived from sensitive/PII/financial {@link DomainGovernance} annotations
     * @param declaredMasks explicit masks declared via {@link AuthzMask}
     */
    public record IntrospectedDtoGovernanceContract(
            String resourceKey,
            Class<?> dtoType,
            List<DtoFieldSchemaMetadata> fieldSchemas,
            Set<String> nonExportableFieldNames,
            Set<String> aiContextDeniedAttributeIds,
            List<FieldUseEffectDirective> baselineFieldUseDirectives,
            Map<String, String> wirePointerToAttributeIdMap,
            List<MaskContributionSpec> derivedMasks,
            List<DeclaredMaskSpec> declaredMasks
    ) {
        /** Validates non-null components and wraps collections immutably. */
        public IntrospectedDtoGovernanceContract {
            Objects.requireNonNull(resourceKey, "resourceKey is required");
            Objects.requireNonNull(dtoType, "dtoType is required");
            fieldSchemas = List.copyOf(Objects.requireNonNull(fieldSchemas, "fieldSchemas is required"));
            nonExportableFieldNames = Set.copyOf(Objects.requireNonNull(nonExportableFieldNames, "nonExportableFieldNames is required"));
            aiContextDeniedAttributeIds = Set.copyOf(Objects.requireNonNull(aiContextDeniedAttributeIds, "aiContextDeniedAttributeIds is required"));
            baselineFieldUseDirectives = List.copyOf(Objects.requireNonNull(baselineFieldUseDirectives, "baselineFieldUseDirectives is required"));
            wirePointerToAttributeIdMap = Map.copyOf(Objects.requireNonNull(wirePointerToAttributeIdMap, "wirePointerToAttributeIdMap is required"));
            derivedMasks = derivedMasks == null ? List.of() : List.copyOf(derivedMasks);
            declaredMasks = declaredMasks == null ? List.of() : List.copyOf(declaredMasks);
        }

        /** Backward-compatible 7-argument constructor without explicit or derived mask metadata. */
        public IntrospectedDtoGovernanceContract(
                String resourceKey,
                Class<?> dtoType,
                List<DtoFieldSchemaMetadata> fieldSchemas,
                Set<String> nonExportableFieldNames,
                Set<String> aiContextDeniedAttributeIds,
                List<FieldUseEffectDirective> baselineFieldUseDirectives,
                Map<String, String> wirePointerToAttributeIdMap
        ) {
            this(
                    resourceKey,
                    dtoType,
                    fieldSchemas,
                    nonExportableFieldNames,
                    aiContextDeniedAttributeIds,
                    baselineFieldUseDirectives,
                    wirePointerToAttributeIdMap,
                    List.of(),
                    List.of()
            );
        }

        /**
         * Returns the effective mask contributions combining explicit {@link AuthzMask}
         * declarations (which take precedence per {@code attributeId}) and auto-derived
         * {@link DomainGovernance} masks.
         */
        public List<MaskContributionSpec> effectiveMaskDirectives() {
            if (declaredMasks.isEmpty() && derivedMasks.isEmpty()) {
                return List.of();
            }
            Set<String> overriddenAttrIds = new LinkedHashSet<>();
            List<MaskContributionSpec> result = new ArrayList<>();
            for (DeclaredMaskSpec declared : declaredMasks) {
                MaskContributionSpec contrib = declared.contribution();
                result.add(contrib);
                if (contrib.fieldSelector() != null && contrib.fieldSelector().attributeIds() != null) {
                    overriddenAttrIds.addAll(contrib.fieldSelector().attributeIds());
                }
            }
            for (MaskContributionSpec derived : derivedMasks) {
                Set<String> attrs = derived.fieldSelector() != null
                        ? derived.fieldSelector().attributeIds()
                        : Set.of();
                boolean overridden = !attrs.isEmpty() && attrs.stream().allMatch(overriddenAttrIds::contains);
                if (!overridden) {
                    result.add(derived);
                }
            }
            return List.copyOf(result);
        }
    }

    private record CacheKey(Class<?> dtoType, Class<?> fallbackResponseType, String resourceKey) {}

    private final Map<CacheKey, IntrospectedDtoGovernanceContract> cache = new ConcurrentHashMap<>();

    /** Creates a new {@link MetadataDtoGovernanceIntrospector}. */
    public MetadataDtoGovernanceIntrospector() {
    }

    /**
     * Introspects a DTO class (record or POJO) and returns its cached {@link IntrospectedDtoGovernanceContract}.
     *
     * @param dtoType DTO class to introspect
     * @param defaultResourceKey canonical resource prefix used when {@link DomainLineage#attributeId()} is omitted
     * @return derived {@link IntrospectedDtoGovernanceContract}
     */
    public IntrospectedDtoGovernanceContract introspect(Class<?> dtoType, String defaultResourceKey) {
        Objects.requireNonNull(dtoType, "dtoType is required");
        Objects.requireNonNull(defaultResourceKey, "defaultResourceKey is required");
        String cleanResourceKey = defaultResourceKey.trim();
        if (cleanResourceKey.isEmpty()) {
            throw new IllegalArgumentException("defaultResourceKey must not be blank");
        }
        return cache.computeIfAbsent(
                new CacheKey(dtoType, null, cleanResourceKey),
                key -> computeContract(key.dtoType(), null, key.resourceKey())
        );
    }

    /**
     * Introspects a write DTO class ({@code CreateDTO} or {@code UpdateDTO}) with automatic
     * lineage inheritance from {@code fallbackResponseDtoType} ({@code P10.8-R01}).
     *
     * <p>Properties on {@code writeDtoType} that omit an explicit {@link DomainLineage} annotation
     * automatically inherit the canonical {@code attributeId} declared on {@code fallbackResponseDtoType}
     * when a matching property name exists, while write-only properties or explicit
     * {@link DomainLineage} annotations on {@code writeDtoType} are resolved directly.</p>
     *
     * @param writeDtoType write DTO class ({@code CreateDTO} or {@code UpdateDTO})
     * @param fallbackResponseDtoType optional response DTO class providing baseline lineage
     * @param defaultResourceKey canonical resource key
     * @return derived {@link IntrospectedDtoGovernanceContract}
     */
    public IntrospectedDtoGovernanceContract introspectWriteDto(
            Class<?> writeDtoType,
            Class<?> fallbackResponseDtoType,
            String defaultResourceKey
    ) {
        Objects.requireNonNull(writeDtoType, "writeDtoType is required");
        Objects.requireNonNull(defaultResourceKey, "defaultResourceKey is required");
        if (fallbackResponseDtoType == null || writeDtoType.equals(fallbackResponseDtoType)) {
            return introspect(writeDtoType, defaultResourceKey);
        }
        String cleanResourceKey = defaultResourceKey.trim();
        if (cleanResourceKey.isEmpty()) {
            throw new IllegalArgumentException("defaultResourceKey must not be blank");
        }
        IntrospectedDtoGovernanceContract fallbackContract = introspect(fallbackResponseDtoType, cleanResourceKey);
        return cache.computeIfAbsent(
                new CacheKey(writeDtoType, fallbackResponseDtoType, cleanResourceKey),
                key -> computeContract(key.dtoType(), fallbackContract, key.resourceKey())
        );
    }

    private record PropertyDescriptor(String name, Class<?> type, List<AnnotatedElement> elements) {}

    private IntrospectedDtoGovernanceContract computeContract(
            Class<?> dtoType,
            IntrospectedDtoGovernanceContract fallbackContract,
            String resourceKey
    ) {
        List<DtoFieldSchemaMetadata> fieldSchemas = new ArrayList<>();
        Set<String> nonExportable = new LinkedHashSet<>();
        Set<String> aiContextDenied = new LinkedHashSet<>();
        List<FieldUseEffectDirective> baselineDirectives = new ArrayList<>();
        Map<String, String> wirePointers = new LinkedHashMap<>();
        List<MaskContributionSpec> derivedMasks = new ArrayList<>();
        List<DeclaredMaskSpec> declaredMasks = new ArrayList<>();
        if (fallbackContract != null) {
            wirePointers.putAll(fallbackContract.wirePointerToAttributeIdMap());
        }

        ObjectNode ownerTypeGovernance = DomainLineageResolver.resolveTypeGovernance(dtoType);
        collectTypeLevelAuthzMasks(dtoType, declaredMasks);

        for (PropertyDescriptor prop : collectProperties(dtoType)) {
            processProperty(
                    prop.name(),
                    prop.type(),
                    prop.elements(),
                    ownerTypeGovernance,
                    fallbackContract,
                    resourceKey,
                    fieldSchemas,
                    nonExportable,
                    aiContextDenied,
                    baselineDirectives,
                    wirePointers,
                    derivedMasks,
                    declaredMasks
            );
        }

        return new IntrospectedDtoGovernanceContract(
                resourceKey,
                dtoType,
                fieldSchemas,
                nonExportable,
                aiContextDenied,
                baselineDirectives,
                wirePointers,
                derivedMasks,
                declaredMasks
        );
    }

    private static List<PropertyDescriptor> collectProperties(Class<?> dtoType) {
        Map<String, Class<?>> types = new LinkedHashMap<>();
        Map<String, List<AnnotatedElement>> elements = new LinkedHashMap<>();

        if (dtoType.isRecord()) {
            for (RecordComponent rc : dtoType.getRecordComponents()) {
                types.put(rc.getName(), rc.getType());
                List<AnnotatedElement> propElements = elements.computeIfAbsent(rc.getName(), k -> new ArrayList<>());
                propElements.add(rc);
                Field backingField = findDeclaredFieldSilently(dtoType, rc.getName());
                if (backingField != null) {
                    propElements.add(backingField);
                }
                if (rc.getAccessor() != null) {
                    propElements.add(rc.getAccessor());
                }
            }
        } else {
            List<Class<?>> hierarchy = new ArrayList<>();
            for (Class<?> curr = dtoType; curr != null && curr != Object.class; curr = curr.getSuperclass()) {
                hierarchy.add(curr);
            }
            // Collect property names in superclass-first declaration order, but prioritize subclass elements
            List<Class<?>> superFirst = new ArrayList<>(hierarchy);
            Collections.reverse(superFirst);
            for (Class<?> curr : superFirst) {
                for (Field f : curr.getDeclaredFields()) {
                    if (Modifier.isStatic(f.getModifiers()) || f.isSynthetic()) {
                        continue;
                    }
                    types.putIfAbsent(f.getName(), f.getType());
                }
            }
            for (Class<?> curr : hierarchy) {
                for (Field f : curr.getDeclaredFields()) {
                    if (Modifier.isStatic(f.getModifiers()) || f.isSynthetic()) {
                        continue;
                    }
                    types.putIfAbsent(f.getName(), f.getType());
                    elements.computeIfAbsent(f.getName(), k -> new ArrayList<>()).add(f);
                }
                for (Method m : curr.getDeclaredMethods()) {
                    if (m.getParameterCount() != 0 || Modifier.isStatic(m.getModifiers())
                            || m.isSynthetic() || m.getReturnType() == void.class) {
                        continue;
                    }
                    String propName = extractPropertyNameFromMethod(m);
                    if (propName == null) {
                        continue;
                    }
                    boolean hasGovOrSchema = ResolverUtils.getAnnotation(DomainLineage.class, m.getAnnotations()) != null
                            || ResolverUtils.getAnnotation(DomainGovernance.class, m.getAnnotations()) != null
                            || ResolverUtils.getAnnotation(Schema.class, m.getAnnotations()) != null
                            || ResolverUtils.getAnnotation(AuthzMask.class, m.getAnnotations()) != null
                            || ResolverUtils.getAnnotation(AuthzMasks.class, m.getAnnotations()) != null
                            || ResolverUtils.getAnnotation(AuthzScopeAnchor.class, m.getAnnotations()) != null
                            || ResolverUtils.getAnnotation(AuthzCustodyPartition.class, m.getAnnotations()) != null
                            || ResolverUtils.getAnnotation(NotNull.class, m.getAnnotations()) != null
                            || ResolverUtils.getAnnotation(NotBlank.class, m.getAnnotations()) != null
                            || ResolverUtils.getAnnotation(NotEmpty.class, m.getAnnotations()) != null;
                    if (!types.containsKey(propName) && !hasGovOrSchema) {
                        continue;
                    }
                    types.putIfAbsent(propName, m.getReturnType());
                    elements.computeIfAbsent(propName, k -> new ArrayList<>()).add(m);
                }
            }
        }

        for (Class<?> contract : ClassUtils.getAllInterfacesForClass(dtoType)) {
            for (Method m : contract.getDeclaredMethods()) {
                if (!m.getDeclaringClass().isInterface() || m.getParameterCount() != 0
                        || Modifier.isStatic(m.getModifiers()) || m.getReturnType() == void.class) {
                    continue;
                }
                String propName = extractPropertyNameFromMethod(m);
                if (propName == null) {
                    continue;
                }
                boolean hasGovOrSchema = ResolverUtils.getAnnotation(DomainLineage.class, m.getAnnotations()) != null
                        || ResolverUtils.getAnnotation(DomainGovernance.class, m.getAnnotations()) != null
                        || ResolverUtils.getAnnotation(Schema.class, m.getAnnotations()) != null
                        || ResolverUtils.getAnnotation(AuthzMask.class, m.getAnnotations()) != null
                        || ResolverUtils.getAnnotation(AuthzMasks.class, m.getAnnotations()) != null
                        || ResolverUtils.getAnnotation(AuthzScopeAnchor.class, m.getAnnotations()) != null
                        || ResolverUtils.getAnnotation(AuthzCustodyPartition.class, m.getAnnotations()) != null
                        || ResolverUtils.getAnnotation(NotNull.class, m.getAnnotations()) != null
                        || ResolverUtils.getAnnotation(NotBlank.class, m.getAnnotations()) != null
                        || ResolverUtils.getAnnotation(NotEmpty.class, m.getAnnotations()) != null;
                if (!types.containsKey(propName) && !hasGovOrSchema) {
                    continue;
                }
                types.putIfAbsent(propName, m.getReturnType());
                elements.computeIfAbsent(propName, k -> new ArrayList<>()).add(m);
            }
        }

        List<PropertyDescriptor> result = new ArrayList<>(types.size());
        for (Map.Entry<String, Class<?>> entry : types.entrySet()) {
            List<AnnotatedElement> propElements = elements.getOrDefault(entry.getKey(), List.of());
            result.add(new PropertyDescriptor(entry.getKey(), entry.getValue(), List.copyOf(propElements)));
        }
        return result;
    }

    private static String extractPropertyNameFromMethod(Method m) {
        String name = m.getName();
        if ("getClass".equals(name)) {
            return null;
        }
        if (name.startsWith("get") && name.length() > 3 && Character.isUpperCase(name.charAt(3))) {
            return Introspector.decapitalize(name.substring(3));
        }
        if (name.startsWith("is") && name.length() > 2 && Character.isUpperCase(name.charAt(2))
                && (m.getReturnType() == boolean.class || m.getReturnType() == Boolean.class)) {
            return Introspector.decapitalize(name.substring(2));
        }
        return name;
    }

    private static void processProperty(
            String wireFieldName,
            Class<?> javaType,
            List<AnnotatedElement> elements,
            ObjectNode ownerTypeGovernance,
            IntrospectedDtoGovernanceContract fallbackContract,
            String resourceKey,
            List<DtoFieldSchemaMetadata> fieldSchemas,
            Set<String> nonExportable,
            Set<String> aiContextDenied,
            List<FieldUseEffectDirective> baselineDirectives,
            Map<String, String> wirePointers,
            List<MaskContributionSpec> derivedMasks,
            List<DeclaredMaskSpec> declaredMasks
    ) {
        DomainLineage lineage = findAnnotation(elements, DomainLineage.class);
        DomainGovernance governance = findAnnotation(elements, DomainGovernance.class);
        Schema schema = findAnnotation(elements, Schema.class);

        ObjectNode effectiveGovNode = null;
        String resolvedLineageAttrId = null;

        boolean hasOriginSourceClass = lineage != null
                && lineage.sourceClass() != null
                && lineage.sourceClass() != Void.class;

        if (lineage != null && (hasOriginSourceClass || governance != null || ownerTypeGovernance != null)) {
            DomainLineageResolver.ResolvedLineage resolved =
                    DomainLineageResolver.resolve(lineage, governance, ownerTypeGovernance);
            if (resolved.weakeningAttempted()) {
                throw new IllegalArgumentException(resolved.weakeningReason());
            }
            effectiveGovNode = resolved.effectiveGovernance();
            resolvedLineageAttrId = resolved.attributeId();
        } else if (governance != null || ownerTypeGovernance != null) {
            effectiveGovNode = DomainSchemaGovernance.mergeOrCopy(
                    ownerTypeGovernance,
                    DomainLineageResolver.toGovernanceNode(governance)
            );
        }

        String attributeId;
        if (lineage == null
                && fallbackContract != null
                && fallbackContract.wirePointerToAttributeIdMap().containsKey("/" + wireFieldName)) {
            attributeId = fallbackContract.wirePointerToAttributeIdMap().get("/" + wireFieldName);
        } else {
            attributeId = resolveAttributeId(wireFieldName, lineage, resolvedLineageAttrId, resourceKey);
        }
        FactValueType valueType = mapFactValueType(javaType);
        boolean nullable = resolveNullable(javaType, schema, elements);

        fieldSchemas.add(new DtoFieldSchemaMetadata(wireFieldName, attributeId, valueType, nullable));
        wirePointers.put("/" + wireFieldName, attributeId);

        boolean hasExplicitMemberMask = collectMemberAuthzMasks(elements, attributeId, declaredMasks);

        if (effectiveGovNode != null) {
            boolean exportable = effectiveGovNode.path("exportable").asBoolean(true);
            if (!exportable) {
                nonExportable.add(wireFieldName);
                nonExportable.add(attributeId);
            }

            String effectiveClassification = effectiveGovNode.path("classification").asText("");
            String effectiveCategory = effectiveGovNode.path("dataCategory").asText("");
            String effectiveAiVisibility = effectiveGovNode.path("aiUsage").path("visibility").asText("");

            boolean isSecretOrCredential = "credential".equals(effectiveCategory)
                    || "secret".equals(effectiveClassification);
            if (isSecretOrCredential) {
                baselineDirectives.add(new FieldUseEffectDirective(
                        attributeId, FieldUseCategory.VALUE, RuleEffect.DENY));
            }
            if ("restricted".equals(effectiveClassification)
                    || "secret".equals(effectiveClassification)
                    || "sensitive_personal".equals(effectiveCategory)
                    || "credential".equals(effectiveCategory)) {
                baselineDirectives.add(new FieldUseEffectDirective(
                        attributeId, FieldUseCategory.FILTER, RuleEffect.DENY));
                baselineDirectives.add(new FieldUseEffectDirective(
                        attributeId, FieldUseCategory.SORT, RuleEffect.DENY));
                baselineDirectives.add(new FieldUseEffectDirective(
                        attributeId, FieldUseCategory.GROUP, RuleEffect.DENY));
                baselineDirectives.add(new FieldUseEffectDirective(
                        attributeId, FieldUseCategory.AGGREGATE, RuleEffect.DENY));
                baselineDirectives.add(new FieldUseEffectDirective(
                        attributeId, FieldUseCategory.JOIN, RuleEffect.DENY));
            }

            if (!hasExplicitMemberMask && !isSecretOrCredential && ("sensitive_personal".equals(effectiveCategory)
                    || "restricted".equals(effectiveClassification)
                    || "confidential".equals(effectiveClassification))) {
                MaskContributionSpec derivedMask = deriveDefaultMaskForGovernance(
                        attributeId, javaType, nullable);
                if (derivedMask != null) {
                    derivedMasks.add(derivedMask);
                } else {
                    baselineDirectives.add(new FieldUseEffectDirective(
                            attributeId, FieldUseCategory.VALUE, RuleEffect.DENY));
                }
            }

            if ("deny".equals(effectiveAiVisibility)) {
                aiContextDenied.add(wireFieldName);
                aiContextDenied.add(attributeId);
            }
        }

        // Fase P10.13: Inherit baseline attribute-level governance from fallback ResponseDTO
        // when write DTO property omits explicit property-level @DomainGovernance / sourceClass
        if (governance == null && !hasOriginSourceClass && fallbackContract != null) {
            if (fallbackContract.nonExportableFieldNames().contains(attributeId)) {
                nonExportable.add(wireFieldName);
                nonExportable.add(attributeId);
            }
            if (fallbackContract.aiContextDeniedAttributeIds().contains(attributeId)) {
                aiContextDenied.add(wireFieldName);
                aiContextDenied.add(attributeId);
            }
            Set<FieldUseCategory> existingDeniedCategories = new LinkedHashSet<>();
            for (FieldUseEffectDirective dir : baselineDirectives) {
                if (attributeId.equals(dir.attributeId()) && dir.effect() == RuleEffect.DENY) {
                    existingDeniedCategories.add(dir.category());
                }
            }
            for (FieldUseEffectDirective fallbackDir : fallbackContract.baselineFieldUseDirectives()) {
                if (attributeId.equals(fallbackDir.attributeId())
                        && fallbackDir.effect() == RuleEffect.DENY
                        && !existingDeniedCategories.contains(fallbackDir.category())) {
                    baselineDirectives.add(fallbackDir);
                }
            }
        }
    }

    /**
     * Derives the canonical {@link FieldLineageCatalogEntry} list across {@code ResponseDTO}
     * ({@code READ_PROJECTION}), {@code CreateDTO} ({@code CREATE_INPUT}), and {@code UpdateDTO}
     * ({@code UPDATE_INPUT}) for the PAP semantic catalog ({@code Fase P10.13}, {@code P36},
     * {@code P44..P50}, {@code P57}, {@code P58}, {@code P62}, {@code P64}).
     *
     * <p>Write DTO properties that map to a canonical {@code attributeId} on {@code responseDtoType}
     * and omit redundant property-level {@link DomainGovernance} automatically inherit the canonical
     * sensitivity classification, concept ID, AI usage mode, and exportability from {@code responseDtoType},
     * while explicit contradictory {@link DomainGovernance} declarations on write DTOs are preserved
     * so catalog and readiness validators reject them fail-closed.</p>
     *
     * @param defaultResourceKey canonical resource key
     * @param responseDtoType response DTO class ({@code READ_PROJECTION})
     * @param createDtoType optional create DTO class ({@code CREATE_INPUT})
     * @param updateDtoType optional update DTO class ({@code UPDATE_INPUT})
     * @return immutable list of {@link FieldLineageCatalogEntry} across all provided DTO roles
     */
    public List<FieldLineageCatalogEntry> deriveFieldLineageCatalogEntries(
            String defaultResourceKey,
            Class<?> responseDtoType,
            Class<?> createDtoType,
            Class<?> updateDtoType
    ) {
        Objects.requireNonNull(defaultResourceKey, "defaultResourceKey is required");
        String cleanResourceKey = defaultResourceKey.trim();
        if (cleanResourceKey.isEmpty()) {
            throw new IllegalArgumentException("defaultResourceKey must not be blank");
        }
        List<FieldLineageCatalogEntry> entries = new ArrayList<>();
        if (responseDtoType != null && responseDtoType != Object.class && !Map.class.isAssignableFrom(responseDtoType)) {
            entries.addAll(deriveDtoFieldLineageCatalogEntries(cleanResourceKey, responseDtoType, "READ_PROJECTION", null));
        }
        if (createDtoType != null && createDtoType != Object.class && !Map.class.isAssignableFrom(createDtoType)) {
            entries.addAll(deriveDtoFieldLineageCatalogEntries(cleanResourceKey, createDtoType, "CREATE_INPUT", responseDtoType));
        }
        if (updateDtoType != null && updateDtoType != Object.class && !Map.class.isAssignableFrom(updateDtoType)) {
            entries.addAll(deriveDtoFieldLineageCatalogEntries(cleanResourceKey, updateDtoType, "UPDATE_INPUT", responseDtoType));
        }
        return List.copyOf(entries);
    }

    /**
     * Derives the canonical {@link FieldLineageCatalogEntry} list for a single DTO class and
     * operation role ({@code READ_PROJECTION}, {@code CREATE_INPUT}, {@code UPDATE_INPUT}, or
     * {@code FILTER_PREDICATE}).
     *
     * @param defaultResourceKey canonical resource key
     * @param dtoType DTO class to introspect
     * @param operationRole canonical operation role
     * @param fallbackResponseDtoType optional response DTO class for lineage and governance inheritance
     * @return immutable list of {@link FieldLineageCatalogEntry}
     */
    public List<FieldLineageCatalogEntry> deriveDtoFieldLineageCatalogEntries(
            String defaultResourceKey,
            Class<?> dtoType,
            String operationRole,
            Class<?> fallbackResponseDtoType
    ) {
        Objects.requireNonNull(defaultResourceKey, "defaultResourceKey is required");
        Objects.requireNonNull(dtoType, "dtoType is required");
        Objects.requireNonNull(operationRole, "operationRole is required");
        String cleanResourceKey = defaultResourceKey.trim();
        if (cleanResourceKey.isEmpty()) {
            throw new IllegalArgumentException("defaultResourceKey must not be blank");
        }

        IntrospectedDtoGovernanceContract fallbackContract = null;
        Map<String, FieldLineageCatalogEntry> fallbackEntriesByAttrId = new LinkedHashMap<>();
        if (fallbackResponseDtoType != null
                && fallbackResponseDtoType != Object.class
                && !Map.class.isAssignableFrom(fallbackResponseDtoType)
                && !dtoType.equals(fallbackResponseDtoType)) {
            fallbackContract = introspect(fallbackResponseDtoType, cleanResourceKey);
            for (FieldLineageCatalogEntry fbEntry : deriveDtoFieldLineageCatalogEntries(
                    cleanResourceKey, fallbackResponseDtoType, "READ_PROJECTION", null)) {
                fallbackEntriesByAttrId.putIfAbsent(fbEntry.attributeId(), fbEntry);
            }
        }

        IntrospectedDtoGovernanceContract contract = fallbackContract != null
                ? introspectWriteDto(dtoType, fallbackResponseDtoType, cleanResourceKey)
                : introspect(dtoType, cleanResourceKey);

        ObjectNode ownerTypeGovernance = DomainLineageResolver.resolveTypeGovernance(dtoType);
        String schemaRef = "schema://" + cleanResourceKey + "/" + dtoType.getSimpleName();
        List<PropertyDescriptor> dtoProps = collectProperties(dtoType);
        Map<String, String> directSourcePathToAttributeId = new LinkedHashMap<>();
        if (fallbackResponseDtoType != null
                && fallbackResponseDtoType != Object.class
                && !Map.class.isAssignableFrom(fallbackResponseDtoType)
                && fallbackContract != null) {
            for (PropertyDescriptor fbProp : collectProperties(fallbackResponseDtoType)) {
                DomainLineage fbLineage = findAnnotation(fbProp.elements(), DomainLineage.class);
                String fbAttrId = fallbackContract.wirePointerToAttributeIdMap().get("/" + fbProp.name());
                if (fbLineage != null
                        && (fbLineage.transformation() == null || fbLineage.transformation() == DomainLineageTransformation.DIRECT)
                        && fbLineage.sourcePaths() != null
                        && fbLineage.sourcePaths().length == 1
                        && fbAttrId != null) {
                    String sp = fbLineage.sourcePaths()[0];
                    if (sp != null && !sp.isBlank()) {
                        directSourcePathToAttributeId.putIfAbsent(sp.trim(), fbAttrId);
                    }
                }
            }
        }
        for (PropertyDescriptor p : dtoProps) {
            DomainLineage pLineage = findAnnotation(p.elements(), DomainLineage.class);
            String pAttrId = contract.wirePointerToAttributeIdMap().get("/" + p.name());
            if (pLineage != null
                    && (pLineage.transformation() == null || pLineage.transformation() == DomainLineageTransformation.DIRECT)
                    && pLineage.sourcePaths() != null
                    && pLineage.sourcePaths().length == 1
                    && pAttrId != null) {
                String sp = pLineage.sourcePaths()[0];
                if (sp != null && !sp.isBlank()) {
                    directSourcePathToAttributeId.put(sp.trim(), pAttrId);
                }
            }
        }
        List<FieldLineageCatalogEntry> result = new ArrayList<>();

        for (PropertyDescriptor prop : dtoProps) {
            String wireFieldName = prop.name();
            List<AnnotatedElement> elements = prop.elements();
            DomainLineage lineage = findAnnotation(elements, DomainLineage.class);
            DomainGovernance governance = findAnnotation(elements, DomainGovernance.class);
            boolean hasOriginSourceClass = lineage != null
                    && lineage.sourceClass() != null
                    && lineage.sourceClass() != Void.class;

            ObjectNode effectiveGovNode = null;
            String resolvedLineageAttrId = null;
            if (lineage != null && (hasOriginSourceClass || governance != null || ownerTypeGovernance != null)) {
                DomainLineageResolver.ResolvedLineage resolved =
                        DomainLineageResolver.resolve(lineage, governance, ownerTypeGovernance);
                if (resolved.weakeningAttempted()) {
                    throw new IllegalArgumentException(resolved.weakeningReason());
                }
                effectiveGovNode = resolved.effectiveGovernance();
                resolvedLineageAttrId = resolved.attributeId();
            } else if (governance != null || ownerTypeGovernance != null) {
                effectiveGovNode = DomainSchemaGovernance.mergeOrCopy(
                        ownerTypeGovernance,
                        DomainLineageResolver.toGovernanceNode(governance)
                );
            }

            String attributeId;
            if (lineage == null
                    && fallbackContract != null
                    && fallbackContract.wirePointerToAttributeIdMap().containsKey("/" + wireFieldName)) {
                attributeId = fallbackContract.wirePointerToAttributeIdMap().get("/" + wireFieldName);
            } else {
                attributeId = resolveAttributeId(wireFieldName, lineage, resolvedLineageAttrId, cleanResourceKey);
            }

            List<String> upstreamRefs = new ArrayList<>();
            if (lineage != null
                    && lineage.transformation() != null
                    && lineage.transformation() != DomainLineageTransformation.DIRECT
                    && lineage.sourcePaths() != null) {
                for (String sp : lineage.sourcePaths()) {
                    if (sp == null || sp.isBlank()) {
                        continue;
                    }
                    String trimmed = sp.trim();
                    String pointer = trimmed.startsWith("/") ? trimmed : "/" + trimmed;
                    String upstreamAttr = contract.wirePointerToAttributeIdMap().get(pointer);
                    if (upstreamAttr == null && fallbackContract != null) {
                        upstreamAttr = fallbackContract.wirePointerToAttributeIdMap().get(pointer);
                    }
                    if (upstreamAttr == null) {
                        upstreamAttr = directSourcePathToAttributeId.get(trimmed.startsWith("/") ? trimmed.substring(1) : trimmed);
                    }
                    if (upstreamAttr == null && !trimmed.startsWith("/") && trimmed.contains(".")) {
                        upstreamAttr = trimmed;
                    }
                    if (upstreamAttr != null && !upstreamAttr.equals(attributeId) && !upstreamRefs.contains(upstreamAttr)) {
                        upstreamRefs.add(upstreamAttr);
                    }
                }
            }

            FieldLineageCatalogEntry fallbackEntry = fallbackEntriesByAttrId.get(attributeId);
            if (governance == null && !hasOriginSourceClass && fallbackEntry != null) {
                result.add(new FieldLineageCatalogEntry(
                        attributeId,
                        fallbackEntry.conceptId(),
                        schemaRef,
                        wireFieldName,
                        operationRole,
                        fallbackEntry.sensitivityClassification(),
                        fallbackEntry.aiUsageMode(),
                        fallbackEntry.exportable(),
                        fallbackEntry.allowedUseCategories(),
                        upstreamRefs.isEmpty() ? fallbackEntry.upstreamAttributeRefs() : List.copyOf(upstreamRefs),
                        fallbackEntry.explicitGovernanceDeclared()
                ));
                continue;
            }

            boolean explicitGovernanceDeclared = effectiveGovNode != null;
            String sensitivityClassification = mapSensitivityClassification(effectiveGovNode);
            String aiUsageMode = mapAiUsageMode(effectiveGovNode);
            boolean exportable = effectiveGovNode == null || effectiveGovNode.path("exportable").asBoolean(true);
            Set<FieldUseCategory> allowedCategories = resolveAllowedUseCategories(attributeId, contract);

            result.add(new FieldLineageCatalogEntry(
                    attributeId,
                    "concept:" + attributeId,
                    schemaRef,
                    wireFieldName,
                    operationRole,
                    sensitivityClassification,
                    aiUsageMode,
                    exportable,
                    allowedCategories,
                    List.copyOf(upstreamRefs),
                    explicitGovernanceDeclared
            ));
        }

        return List.copyOf(result);
    }

    private static String mapSensitivityClassification(ObjectNode effectiveGovNode) {
        if (effectiveGovNode == null) {
            return "OPERATIONAL_INTERNAL";
        }
        String classification = effectiveGovNode.path("classification").asText("").toLowerCase(Locale.ROOT);
        String category = effectiveGovNode.path("dataCategory").asText("").toLowerCase(Locale.ROOT);
        if ("credential".equals(category)) {
            return "SECRET";
        }
        if ("sensitive_personal".equals(category)) {
            return "SENSITIVE_PERSONAL";
        }
        if ("restricted".equals(classification) || "confidential".equals(classification)) {
            if ("personal".equals(category)) {
                return "PII_RESTRICTED";
            }
            if ("financial".equals(category)) {
                return "FINANCIAL_RESTRICTED";
            }
            return "RESTRICTED";
        }
        if ("public".equals(classification)) {
            return "PUBLIC_OPERATIONAL";
        }
        return "OPERATIONAL_INTERNAL";
    }

    private static String mapAiUsageMode(ObjectNode effectiveGovNode) {
        if (effectiveGovNode == null) {
            return "SCHEMA_METADATA_ONLY";
        }
        String visibility = effectiveGovNode.path("aiUsage").path("visibility").asText("")
                .trim()
                .toLowerCase(Locale.ROOT);
        if ("deny".equals(visibility) || "denied".equals(visibility)) {
            return "DENIED";
        }
        if ("mask".equals(visibility) || "masked".equals(visibility) || "summarize_only".equals(visibility)) {
            return "MASKED_ONLY";
        }
        if ("allow".equals(visibility) || "allowed".equals(visibility)) {
            return "ALLOWED";
        }
        String sensitivity = mapSensitivityClassification(effectiveGovNode);
        if ("SECRET".equals(sensitivity) || "SENSITIVE_PERSONAL".equals(sensitivity)) {
            return "DENIED";
        }
        if ("PII_RESTRICTED".equals(sensitivity)
                || "FINANCIAL_RESTRICTED".equals(sensitivity)
                || "RESTRICTED".equals(sensitivity)) {
            return "MASKED_ONLY";
        }
        return "SCHEMA_METADATA_ONLY";
    }

    private static Set<FieldUseCategory> resolveAllowedUseCategories(
            String attributeId,
            IntrospectedDtoGovernanceContract contract
    ) {
        Set<FieldUseCategory> allowed = new LinkedHashSet<>(List.of(
                FieldUseCategory.VALUE,
                FieldUseCategory.FILTER,
                FieldUseCategory.SORT,
                FieldUseCategory.GROUP,
                FieldUseCategory.AGGREGATE,
                FieldUseCategory.JOIN
        ));
        for (FieldUseEffectDirective dir : contract.baselineFieldUseDirectives()) {
            if (attributeId.equals(dir.attributeId()) && dir.effect() == RuleEffect.DENY) {
                allowed.remove(dir.category());
            }
        }
        return Set.copyOf(allowed);
    }

    private static MaskContributionSpec deriveDefaultMaskForGovernance(
            String attributeId,
            Class<?> javaType,
            boolean nullable
    ) {
        // Complex DTO fields can share the STRING fact-type fallback without accepting string values.
        if (javaType == String.class) {
            return new MaskContributionSpec(
                    PolicyFieldSelector.exact(Set.of(attributeId)),
                    "REDACT_CONSTANT",
                    Map.of("replacement", "***")
            );
        }
        if (nullable) {
            return new MaskContributionSpec(
                    PolicyFieldSelector.exact(Set.of(attributeId)),
                    "NULLIFY",
                    Map.of()
            );
        }
        // Primitive and non-nullable non-String fields cannot satisfy MaskStrategy.requiresNullableTargetField;
        // fail closed via FieldUseCategory.VALUE + RuleEffect.DENY (OMIT_BY_FIELD_USE_DENY).
        return null;
    }

    private static void collectTypeLevelAuthzMasks(
            Class<?> dtoType,
            List<DeclaredMaskSpec> target
    ) {
        for (AuthzMask mask : AnnotatedElementUtils.findMergedRepeatableAnnotations(dtoType, AuthzMask.class)) {
            if (mask.attributeId() != null && !mask.attributeId().isBlank()) {
                target.add(toDeclaredMaskSpec(mask, mask.attributeId().trim()));
            }
        }
    }

    private static boolean collectMemberAuthzMasks(
            List<AnnotatedElement> elements,
            String resolvedAttributeId,
            List<DeclaredMaskSpec> target
    ) {
        if (elements == null) {
            return false;
        }
        boolean found = false;
        Set<String> seenKeys = new LinkedHashSet<>();
        for (AnnotatedElement el : elements) {
            if (el == null) {
                continue;
            }
            for (AuthzMask mask : AnnotatedElementUtils.findMergedRepeatableAnnotations(el, AuthzMask.class)) {
                String attrId = (mask.attributeId() != null && !mask.attributeId().isBlank())
                        ? mask.attributeId().trim()
                        : resolvedAttributeId;
                DeclaredMaskSpec spec = toDeclaredMaskSpec(mask, attrId);
                String dedupKey = attrId + "|" + spec.contribution().strategyId() + "|" + spec.surfaces() + "|" + spec.modes();
                if (seenKeys.add(dedupKey)) {
                    target.add(spec);
                    found = true;
                }
            }
        }
        return found;
    }

    /** Translates an {@link AuthzMask} annotation into a {@link DeclaredMaskSpec}. */
    public static DeclaredMaskSpec toDeclaredMaskSpec(AuthzMask mask, String attributeId) {
        Objects.requireNonNull(mask, "mask is required");
        String targetAttr = Objects.requireNonNull(attributeId, "attributeId is required").trim();
        if (targetAttr.isEmpty()) {
            throw new IllegalArgumentException("attributeId is required for @AuthzMask");
        }
        String strategyId = mask.strategy() == AuthzMaskStrategy.CUSTOM
                ? mask.customStrategyId().trim()
                : mask.strategy().strategyId();
        if (strategyId.isEmpty()) {
            throw new IllegalArgumentException("@AuthzMask with CUSTOM strategy requires non-blank customStrategyId");
        }
        Map<String, Object> params = new LinkedHashMap<>();
        switch (mask.strategy()) {
            case REDACT_CONSTANT -> params.put("replacement", mask.replacement() != null ? mask.replacement() : "***");
            case PARTIAL_MASK -> {
                params.put("visiblePrefix", mask.visiblePrefix());
                params.put("visibleSuffix", mask.visibleSuffix());
                params.put("maskChar", mask.maskChar() != null && !mask.maskChar().isEmpty() ? mask.maskChar() : "*");
            }
            case HASH_TOKEN_KEYED -> {
                if (mask.keyAlias() != null && !mask.keyAlias().isBlank()) {
                    params.put("keyAlias", mask.keyAlias().trim());
                }
                params.put("truncateChars", mask.truncateChars());
            }
            case SUMMARY_ONLY -> {
                if (mask.summaryFormat() != null && !mask.summaryFormat().isBlank()) {
                    params.put("summaryFormat", mask.summaryFormat());
                }
            }
            default -> {
                // OMIT, NULLIFY, CPF_CNPJ_PARTIAL, CUSTOM need no default parameters
            }
        }
        Set<EvaluationMode> modes = mask.modes() == null || mask.modes().length == 0
                ? Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET)
                : Set.of(mask.modes());
        Set<String> surfaces = new LinkedHashSet<>();
        if (mask.surfaces() != null) {
            for (String s : mask.surfaces()) {
                if (s != null && !s.isBlank()) {
                    surfaces.add(s.trim());
                }
            }
        }
        return new DeclaredMaskSpec(
                new MaskContributionSpec(
                        PolicyFieldSelector.exact(Set.of(targetAttr)),
                        strategyId,
                        Map.copyOf(params)
                ),
                modes,
                surfaces,
                mask.reason() != null ? mask.reason().trim() : ""
        );
    }

    private static <A extends Annotation> A findAnnotation(
            List<AnnotatedElement> elements,
            Class<A> annotationType
    ) {
        if (elements == null) {
            return null;
        }
        for (AnnotatedElement el : elements) {
            if (el == null) {
                continue;
            }
            A found = ResolverUtils.getAnnotation(annotationType, el.getAnnotations());
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    private static Field findDeclaredFieldSilently(Class<?> type, String name) {
        try {
            return type.getDeclaredField(name);
        } catch (NoSuchFieldException ex) {
            return null;
        }
    }

    private static String resolveAttributeId(
            String wireFieldName,
            DomainLineage lineage,
            String resolvedLineageAttrId,
            String resourceKey
    ) {
        if (lineage != null && lineage.attributeId() != null && !lineage.attributeId().isBlank()) {
            return lineage.attributeId().trim();
        }
        if (resolvedLineageAttrId != null && !resolvedLineageAttrId.isBlank()) {
            return resolvedLineageAttrId.trim();
        }
        String normalizedResource = resourceKey.replace('-', '_');
        return normalizedResource + "." + camelToSnake(wireFieldName);
    }

    private static boolean resolveNullable(Class<?> javaType, Schema schema, List<AnnotatedElement> elements) {
        if (javaType.isPrimitive()) {
            return false;
        }
        if (findAnnotation(elements, NotNull.class) != null
                || findAnnotation(elements, NotBlank.class) != null
                || findAnnotation(elements, NotEmpty.class) != null) {
            return false;
        }
        if (schema != null) {
            if (schema.requiredMode() == Schema.RequiredMode.REQUIRED) {
                return false;
            }
            return schema.nullable();
        }
        return true;
    }

    private static FactValueType mapFactValueType(Class<?> javaType) {
        if (javaType == boolean.class || javaType == Boolean.class) {
            return FactValueType.BOOLEAN;
        }
        if (javaType == int.class || javaType == Integer.class
                || javaType == long.class || javaType == Long.class
                || javaType == short.class || javaType == Short.class
                || javaType == byte.class || javaType == Byte.class
                || javaType == BigInteger.class) {
            return FactValueType.INT64;
        }
        if (javaType == double.class || javaType == Double.class
                || javaType == float.class || javaType == Float.class
                || javaType == BigDecimal.class) {
            return FactValueType.DECIMAL;
        }
        if (javaType == LocalDate.class) {
            return FactValueType.LOCAL_DATE;
        }
        if (javaType == Instant.class || javaType == LocalDateTime.class
                || javaType == OffsetDateTime.class || javaType == ZonedDateTime.class) {
            return FactValueType.INSTANT;
        }
        if (javaType.isEnum()) {
            return FactValueType.ENUM;
        }
        return FactValueType.STRING;
    }

    private static String camelToSnake(String input) {
        StringBuilder sb = new StringBuilder(input.length() + 4);
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (Character.isUpperCase(c)) {
                if (i > 0) {
                    sb.append('_');
                }
                sb.append(Character.toLowerCase(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString().toLowerCase(Locale.ROOT);
    }

    /**
     * Automatically extracts {@link FieldUseCategory#FILTER} and {@link FieldUseCategory#SORT}
     * attribute uses from a runtime {@code filterDto} instance and {@link Sort} specification
     * ({@code Fase P10.15-A}, {@code P08}, {@code P10}, {@code P46}).
     *
     * <p>Resolves populated {@code FilterDTO} properties (via {@link DomainLineage},
     * {@link Filterable#relation()}, {@link Filterable#relations()}, and {@code responseContract}
     * wire/entity mappings) into canonical {@code attributeId}s so {@code FieldUseQueryGuard}
     * automatically blocks oracle/side-channel filtering or sorting on restricted attributes
     * without requiring manual {@code AuthzCallerContext.withRequestedQueryFieldUses(...)} wiring.</p>
     *
     * @param filterDto optional {@code FilterDTO} instance or {@code Map}
     * @param sort optional Spring Data {@link Sort}
     * @param responseContract introspected {@code ResponseDTO} governance contract
     * @param governanceSpec optional resource governance specification
     * @return immutable map of extracted {@link FieldUseCategory} to canonical {@code attributeId} sets
     */
    public Map<FieldUseCategory, Set<String>> extractQueryFieldUses(
            Object filterDto,
            Sort sort,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> governanceSpec
    ) {
        Set<String> filterAttrs = new LinkedHashSet<>();
        Set<String> sortAttrs = new LinkedHashSet<>();
        extractFilterDtoAttributeUses(filterDto, responseContract, governanceSpec, filterAttrs);
        extractSortAttributeUses(sort, responseContract, governanceSpec, sortAttrs);

        Map<FieldUseCategory, Set<String>> result = new LinkedHashMap<>();
        if (!filterAttrs.isEmpty()) {
            result.put(FieldUseCategory.FILTER, Set.copyOf(filterAttrs));
        }
        if (!sortAttrs.isEmpty()) {
            result.put(FieldUseCategory.SORT, Set.copyOf(sortAttrs));
        }
        return result.isEmpty() ? Map.of() : Map.copyOf(result);
    }

    /**
     * Automatically extracts {@link FieldUseCategory#FILTER} and {@link FieldUseCategory#SORT}
     * attribute uses from a {@link CollectionExportRequest} ({@code Fase P10.15-A}).
     */
    public Map<FieldUseCategory, Set<String>> extractExportQueryFieldUses(
            CollectionExportRequest<?> request,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> governanceSpec
    ) {
        if (request == null) {
            return Map.of();
        }
        Set<String> filterAttrs = new LinkedHashSet<>();
        Set<String> sortAttrs = new LinkedHashSet<>();
        extractFilterDtoAttributeUses(request.filters(), responseContract, governanceSpec, filterAttrs);
        Object sortSpec = request.sort();
        if (sortSpec instanceof Iterable<?> iterable) {
            for (Object sortItem : iterable) {
                extractSingleSortSpecAttributeUses(sortItem, responseContract, governanceSpec, sortAttrs);
            }
        } else if (sortSpec != null) {
            extractSingleSortSpecAttributeUses(sortSpec, responseContract, governanceSpec, sortAttrs);
        }
        Map<FieldUseCategory, Set<String>> result = new LinkedHashMap<>();
        if (!filterAttrs.isEmpty()) {
            result.put(FieldUseCategory.FILTER, Set.copyOf(filterAttrs));
        }
        if (!sortAttrs.isEmpty()) {
            result.put(FieldUseCategory.SORT, Set.copyOf(sortAttrs));
        }
        return result.isEmpty() ? Map.of() : Map.copyOf(result);
    }

    private void extractFilterDtoAttributeUses(
            Object filterDto,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> governanceSpec,
            Set<String> filterAttrs
    ) {
        if (filterDto == null) {
            return;
        }
        if (filterDto instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() != null && isNonEmptyFilterValue(entry.getValue())) {
                    resolvePathToAttributeIds(
                            String.valueOf(entry.getKey()),
                            responseContract,
                            governanceSpec,
                            filterAttrs
                    );
                }
            }
            return;
        }
        Class<?> dtoClass = filterDto.getClass();
        Map<String, List<AnnotatedElement>> propElements = new LinkedHashMap<>();
        Map<String, Object> populatedValues = new LinkedHashMap<>();

        if (dtoClass.isRecord() && dtoClass.getRecordComponents() != null) {
            for (RecordComponent rc : dtoClass.getRecordComponents()) {
                String name = rc.getName();
                List<AnnotatedElement> els = propElements.computeIfAbsent(name, k -> new ArrayList<>());
                els.add(rc);
                if (rc.getAccessor() != null) {
                    els.add(rc.getAccessor());
                }
                Field f = findDeclaredFieldSilently(dtoClass, name);
                if (f != null) {
                    els.add(f);
                }
                Object val = invokeZeroArgSilently(rc.getAccessor(), filterDto);
                if (isNonEmptyFilterValue(val)) {
                    populatedValues.put(name, val);
                }
            }
        } else {
            for (Class<?> curr = dtoClass; curr != null && curr != Object.class; curr = curr.getSuperclass()) {
                for (Field f : curr.getDeclaredFields()) {
                    if (Modifier.isStatic(f.getModifiers()) || f.isSynthetic()) {
                        continue;
                    }
                    String name = f.getName();
                    propElements.computeIfAbsent(name, k -> new ArrayList<>()).add(f);
                    if (!populatedValues.containsKey(name)) {
                        Object val = readFieldSilently(f, filterDto);
                        if (isNonEmptyFilterValue(val)) {
                            populatedValues.put(name, val);
                        }
                    }
                }
                for (Method m : curr.getDeclaredMethods()) {
                    if (m.getParameterCount() != 0 || Modifier.isStatic(m.getModifiers()) || m.getReturnType() == void.class) {
                        continue;
                    }
                    String name = extractPropertyNameFromMethod(m);
                    if (name == null) {
                        continue;
                    }
                    if (!propElements.containsKey(name) && !hasFilterOrLineageAnnotation(m)) {
                        continue;
                    }
                    propElements.computeIfAbsent(name, k -> new ArrayList<>()).add(m);
                    if (!populatedValues.containsKey(name)) {
                        Object val = invokeZeroArgSilently(m, filterDto);
                        if (isNonEmptyFilterValue(val)) {
                            populatedValues.put(name, val);
                        }
                    }
                }
            }
        }

        for (String propName : populatedValues.keySet()) {
            List<AnnotatedElement> els = propElements.getOrDefault(propName, List.of());
            resolveFilterPropertyToAttributeIds(propName, els, responseContract, governanceSpec, filterAttrs);
        }
    }

    private void extractSortAttributeUses(
            Sort sort,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> governanceSpec,
            Set<String> sortAttrs
    ) {
        if (sort == null || sort.isUnsorted()) {
            return;
        }
        for (Sort.Order order : sort) {
            if (order != null && order.getProperty() != null && !order.getProperty().isBlank()) {
                resolvePathToAttributeIds(
                        order.getProperty().trim(),
                        responseContract,
                        governanceSpec,
                        sortAttrs
                );
            }
        }
    }

    private void extractSingleSortSpecAttributeUses(
            Object sortItem,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> governanceSpec,
            Set<String> sortAttrs
    ) {
        if (sortItem == null) {
            return;
        }
        if (sortItem instanceof Sort.Order order) {
            if (order.getProperty() != null && !order.getProperty().isBlank()) {
                resolvePathToAttributeIds(order.getProperty().trim(), responseContract, governanceSpec, sortAttrs);
            }
            return;
        }
        if (sortItem instanceof CharSequence cs) {
            String raw = cs.toString().trim();
            if (!raw.isEmpty()) {
                String clean = cleanSortToken(raw);
                if (!clean.isEmpty()) {
                    resolvePathToAttributeIds(clean, responseContract, governanceSpec, sortAttrs);
                }
            }
            return;
        }
        for (String accessorName : List.of("field", "property", "getField", "getProperty", "column")) {
            try {
                Method m = sortItem.getClass().getMethod(accessorName);
                Object val = m.invoke(sortItem);
                if (val instanceof String s && !s.isBlank()) {
                    resolvePathToAttributeIds(s.trim(), responseContract, governanceSpec, sortAttrs);
                    return;
                }
            } catch (ReflectiveOperationException ignored) {
                // try next accessor
            }
        }
    }

    private static String cleanSortToken(String raw) {
        String s = raw.trim();
        if (s.startsWith("+") || s.startsWith("-")) {
            s = s.substring(1).trim();
        }
        int colonIdx = s.indexOf(':');
        if (colonIdx > 0) {
            s = s.substring(0, colonIdx).trim();
        }
        int commaIdx = s.indexOf(',');
        if (commaIdx > 0) {
            s = s.substring(0, commaIdx).trim();
        }
        return s;
    }

    private static void resolveFilterPropertyToAttributeIds(
            String propName,
            List<AnnotatedElement> elements,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> governanceSpec,
            Set<String> targetSet
    ) {
        DomainLineage lineage = findAnnotation(elements, DomainLineage.class);
        if (lineage != null && lineage.attributeId() != null && !lineage.attributeId().isBlank()) {
            targetSet.add(lineage.attributeId().trim());
        }
        Filterable filterable = findAnnotation(elements, Filterable.class);
        boolean resolvedViaFilterable = false;
        if (filterable != null) {
            if (filterable.relations() != null && filterable.relations().length > 0) {
                for (String rel : filterable.relations()) {
                    if (rel != null && !rel.isBlank()) {
                        resolvePathToAttributeIds(rel.trim(), responseContract, governanceSpec, targetSet);
                        resolvedViaFilterable = true;
                    }
                }
            } else if (filterable.relation() != null && !filterable.relation().isBlank()) {
                resolvePathToAttributeIds(filterable.relation().trim(), responseContract, governanceSpec, targetSet);
                resolvedViaFilterable = true;
            }
        }
        if (!resolvedViaFilterable) {
            resolvePathToAttributeIds(propName, responseContract, governanceSpec, targetSet);
        }
    }

    private static void resolvePathToAttributeIds(
            String rawPath,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> governanceSpec,
            Set<String> targetSet
    ) {
        if (rawPath == null || rawPath.isBlank()) {
            return;
        }
        String clean = rawPath.trim();
        if (clean.startsWith("/")) {
            clean = clean.substring(1);
        }
        boolean matched = false;
        if (responseContract != null) {
            String direct = responseContract.wirePointerToAttributeIdMap().get("/" + clean);
            if (direct != null) {
                targetSet.add(direct);
                matched = true;
            }
            if (clean.contains(".")) {
                String leaf = clean.substring(clean.lastIndexOf('.') + 1);
                String leafMapped = responseContract.wirePointerToAttributeIdMap().get("/" + leaf);
                if (leafMapped != null) {
                    targetSet.add(leafMapped);
                    matched = true;
                }
            }
            if (!matched && responseContract.dtoType() != null) {
                for (PropertyDescriptor pd : collectProperties(responseContract.dtoType())) {
                    DomainLineage dl = findAnnotation(pd.elements(), DomainLineage.class);
                    if (dl != null && dl.sourcePaths() != null) {
                        for (String sp : dl.sourcePaths()) {
                            if (clean.equals(sp)) {
                                String attrId = responseContract.wirePointerToAttributeIdMap().get("/" + pd.name());
                                if (attrId != null) {
                                    targetSet.add(attrId);
                                    matched = true;
                                }
                            }
                        }
                    }
                }
            }
            if (!matched && responseContract.wirePointerToAttributeIdMap().containsValue(clean)) {
                targetSet.add(clean);
                matched = true;
            }
        }
        if (governanceSpec != null) {
            for (QueryAdapterFieldBinding binding : governanceSpec.fieldBindings()) {
                if (clean.equals(binding.nativeJpaPath())
                        || clean.equals(binding.fieldPath())
                        || ("resource." + clean).equals(binding.fieldPath())
                        || clean.equals(binding.attributeId())) {
                    targetSet.add(binding.attributeId());
                    matched = true;
                }
            }
        }
        if (!matched) {
            targetSet.add(clean);
        }
    }

    private static boolean hasFilterOrLineageAnnotation(Method method) {
        return ResolverUtils.getAnnotation(Filterable.class, method.getAnnotations()) != null
                || ResolverUtils.getAnnotation(DomainLineage.class, method.getAnnotations()) != null
                || ResolverUtils.getAnnotation(DomainGovernance.class, method.getAnnotations()) != null;
    }

    private static boolean isNonEmptyFilterValue(Object val) {
        if (val == null) {
            return false;
        }
        if (val instanceof CharSequence cs) {
            return !cs.toString().isBlank();
        }
        if (val instanceof Collection<?> col) {
            return !col.isEmpty();
        }
        if (val instanceof Map<?, ?> map) {
            return !map.isEmpty();
        }
        if (val.getClass().isArray()) {
            return Array.getLength(val) > 0;
        }
        return true;
    }

    private static Object readFieldSilently(Field f, Object target) {
        try {
            f.setAccessible(true);
            return f.get(target);
        } catch (ReflectiveOperationException | RuntimeException ex) {
            return null;
        }
    }

    private static Object invokeZeroArgSilently(Method m, Object target) {
        if (m == null) {
            return null;
        }
        try {
            m.setAccessible(true);
            return m.invoke(target);
        } catch (ReflectiveOperationException | RuntimeException ex) {
            return null;
        }
    }
}
