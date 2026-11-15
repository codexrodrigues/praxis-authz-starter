package org.praxisplatform.authz.host.metadata;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseViolationException;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.AuthorizedQueryScopeContext;
import org.praxisplatform.uischema.dto.OptionDTO;
import org.praxisplatform.uischema.options.EntityLookupDescriptor;
import org.praxisplatform.uischema.options.LookupFilterRequest;
import org.praxisplatform.uischema.options.LookupSelectionPolicy;
import org.praxisplatform.uischema.options.OptionSourceDescriptor;
import org.praxisplatform.uischema.options.service.OptionSourceExecutionContext;
import org.praxisplatform.uischema.options.service.OptionSourceExecutionRequest;
import org.praxisplatform.uischema.options.service.OptionSourceOperation;
import org.praxisplatform.uischema.options.service.OptionSourceProvider;
import org.praxisplatform.uischema.options.service.OptionSourceQueryExecutor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;

/**
 * Governed decorator for {@code praxis-metadata-starter}'s {@link OptionSourceQueryExecutor}
 * and {@link OptionSourceProvider}, bridging {@code AbstractBaseQueryResourceService.filterOptionSourceOptions}
 * and {@code byIdsOptionSourceOptions} to the authorization pipeline
 * ({@code Fase P10.5}, {@code P05}, {@code P06}, {@code P07}, {@code P09}, {@code P12}, {@code P13}, {@code P14}, {@code P50}).
 *
 * <p>Guarantees:</p>
 * <ul>
 *   <li><b>Unified Query Scope &amp; Zero Out-of-Scope Hydration ({@code P05}, {@code P06}, {@code P07}):</b>
 *       {@code filter}, {@code includeIds}, and {@code byIds} execute under the composed
 *       {@code ResourceFilterAccessScope} ({@code hardScope} AND OPA {@code DataScopePlan});
 *       out-of-scope or cross-tenant IDs are omitted without leaking existence;</li>
 *   <li><b>Detached Masking &amp; Redaction of {@code OptionDTO.extra} ({@code P09}, {@code P12}, {@code P50}):</b>
 *       any attribute in {@code OptionDTO.extra()} (or nested {@code displayFields}) that is denied
 *       by {@code FieldUseCategory.VALUE} or governed by an active {@link MaskDirective} is masked
 *       or redacted without mutating JPA entities;</li>
 *   <li><b>Historical Display-Only vs. Active Selection Eligibility ({@code P06}, {@code P07}, {@code P14}):</b>
 *       enforces {@link LookupSelectionPolicy} on {@code RESOURCE_ENTITY} lookups, stamping
 *       {@code selectable = false} and {@code historicalDisplayOnly = true} when an in-scope
 *       historical option is reloaded via {@code byIds} or {@code includeIds} with
 *       {@code allowRetainInvalidExistingValue = true};</li>
 *   <li><b>Deterministic ThreadLocal Hygiene:</b> clears transient query authorization contexts in a
 *       {@code finally} block after {@code filterOptionSourceOptions} and {@code byIdsOptionSourceOptions}.</li>
 * </ul>
 */
public final class AuthzGovernedOptionSourceProvider
        implements OptionSourceQueryExecutor, OptionSourceProvider {

    private final OptionSourceQueryExecutor executorDelegate;
    private final OptionSourceProvider providerDelegate;
    private final AuthzGovernedResourceServiceSupport serviceSupport;
    private final DetachedDtoMaskingProcessor maskingProcessor;
    private final IntrospectedDtoGovernanceContract governanceContract;
    private final AuthzResourceGovernanceSpec<?> governanceSpec;
    private final FieldUseQueryGuard fieldUseQueryGuard;

    /**
     * Wraps an {@link OptionSourceQueryExecutor} (such as {@code CompositeOptionSourceQueryExecutor}
     * or {@code JpaOptionSourceQueryExecutor}).
     *
     * @param executorDelegate underlying option-source query executor
     * @param serviceSupport governed resource service support bridge
     * @param maskingProcessor detached DTO masking processor
     * @param governanceContract introspected DTO governance contract for the option-source entity/DTO
     */
    public AuthzGovernedOptionSourceProvider(
            OptionSourceQueryExecutor executorDelegate,
            AuthzGovernedResourceServiceSupport serviceSupport,
            DetachedDtoMaskingProcessor maskingProcessor,
            IntrospectedDtoGovernanceContract governanceContract
    ) {
        this(executorDelegate, serviceSupport, maskingProcessor, governanceContract, null);
    }

    /**
     * Wraps an {@link OptionSourceQueryExecutor} with an optional {@link AuthzResourceGovernanceSpec}
     * for {@code QueryAdapterFieldBinding} lineage resolution ({@code Fase P10.25-A}).
     */
    public AuthzGovernedOptionSourceProvider(
            OptionSourceQueryExecutor executorDelegate,
            AuthzGovernedResourceServiceSupport serviceSupport,
            DetachedDtoMaskingProcessor maskingProcessor,
            IntrospectedDtoGovernanceContract governanceContract,
            AuthzResourceGovernanceSpec<?> governanceSpec
    ) {
        this.executorDelegate = Objects.requireNonNull(executorDelegate, "executorDelegate is required");
        this.providerDelegate = null;
        this.serviceSupport = Objects.requireNonNull(serviceSupport, "serviceSupport is required");
        this.maskingProcessor = Objects.requireNonNull(maskingProcessor, "maskingProcessor is required");
        this.governanceContract = Objects.requireNonNull(governanceContract, "governanceContract is required");
        this.governanceSpec = governanceSpec;
        this.fieldUseQueryGuard = new FieldUseQueryGuard();
    }

    /**
     * Wraps an {@link OptionSourceProvider} (such as {@code JpaOptionSourceProvider} or a custom host provider).
     *
     * @param providerDelegate underlying option-source provider
     * @param serviceSupport governed resource service support bridge
     * @param maskingProcessor detached DTO masking processor
     * @param governanceContract introspected DTO governance contract for the option-source entity/DTO
     */
    public AuthzGovernedOptionSourceProvider(
            OptionSourceProvider providerDelegate,
            AuthzGovernedResourceServiceSupport serviceSupport,
            DetachedDtoMaskingProcessor maskingProcessor,
            IntrospectedDtoGovernanceContract governanceContract
    ) {
        this(providerDelegate, serviceSupport, maskingProcessor, governanceContract, null);
    }

    /**
     * Wraps an {@link OptionSourceProvider} with an optional {@link AuthzResourceGovernanceSpec}
     * for {@code QueryAdapterFieldBinding} lineage resolution ({@code Fase P10.25-A}).
     */
    public AuthzGovernedOptionSourceProvider(
            OptionSourceProvider providerDelegate,
            AuthzGovernedResourceServiceSupport serviceSupport,
            DetachedDtoMaskingProcessor maskingProcessor,
            IntrospectedDtoGovernanceContract governanceContract,
            AuthzResourceGovernanceSpec<?> governanceSpec
    ) {
        this.executorDelegate = null;
        this.providerDelegate = Objects.requireNonNull(providerDelegate, "providerDelegate is required");
        this.serviceSupport = Objects.requireNonNull(serviceSupport, "serviceSupport is required");
        this.maskingProcessor = Objects.requireNonNull(maskingProcessor, "maskingProcessor is required");
        this.governanceContract = Objects.requireNonNull(governanceContract, "governanceContract is required");
        this.governanceSpec = governanceSpec;
        this.fieldUseQueryGuard = new FieldUseQueryGuard();
    }

    @Override
    public boolean supports(
            OptionSourceDescriptor descriptor,
            OptionSourceExecutionContext context,
            OptionSourceOperation operation
    ) {
        if (providerDelegate != null) {
            return providerDelegate.supports(descriptor, context, operation);
        }
        return descriptor != null;
    }

    @Override
    public Page<OptionDTO<Object>> filter(OptionSourceExecutionRequest<?> request) {
        if (providerDelegate == null) {
            throw new IllegalStateException("AuthzGovernedOptionSourceProvider was not constructed with an OptionSourceProvider delegate");
        }
        try {
            if (request != null) {
                enforceOptionSourceFieldUses(
                        request.descriptor(),
                        request.search(),
                        request.filterPayload(),
                        request.filters(),
                        request.sortKey(),
                        request.pageable()
                );
            }
            Page<OptionDTO<Object>> rawPage = providerDelegate.filter(request);
            return sanitizeOptionPage(
                    rawPage,
                    request == null ? null : request.descriptor(),
                    OptionSourceOperation.FILTER,
                    request == null ? List.of() : request.includeIds()
            );
        } finally {
            serviceSupport.clearTransientRequestContexts();
        }
    }

    @Override
    public List<OptionDTO<Object>> byIds(OptionSourceExecutionRequest<?> request) {
        if (providerDelegate == null) {
            throw new IllegalStateException("AuthzGovernedOptionSourceProvider was not constructed with an OptionSourceProvider delegate");
        }
        try {
            if (request != null) {
                enforceOptionSourceFieldUses(
                        request.descriptor(),
                        null,
                        request.filterPayload(),
                        request.filters(),
                        null,
                        null
                );
            }
            List<OptionDTO<Object>> rawList = providerDelegate.byIds(request);
            return sanitizeOptionList(
                    rawList,
                    request == null ? null : request.descriptor(),
                    OptionSourceOperation.BY_IDS,
                    request == null ? List.of() : request.ids()
            );
        } finally {
            serviceSupport.clearTransientRequestContexts();
        }
    }

    @Override
    public <E> Page<OptionDTO<Object>> filterOptions(
            EntityManager entityManager,
            Class<E> entityClass,
            Specification<E> specification,
            Object filterPayload,
            OptionSourceDescriptor descriptor,
            String search,
            List<LookupFilterRequest> filters,
            String sortKey,
            Pageable pageable,
            Collection<Object> includeIds
    ) {
        return filterOptions(
                entityManager,
                entityClass,
                specification,
                filterPayload,
                descriptor,
                search,
                null,
                filters,
                sortKey,
                pageable,
                includeIds
        );
    }

    @Override
    public <E> Page<OptionDTO<Object>> filterOptions(
            EntityManager entityManager,
            Class<E> entityClass,
            Specification<E> specification,
            Object filterPayload,
            OptionSourceDescriptor descriptor,
            String search,
            String searchStrategy,
            List<LookupFilterRequest> filters,
            String sortKey,
            Pageable pageable,
            Collection<Object> includeIds
    ) {
        if (executorDelegate == null) {
            throw new IllegalStateException("AuthzGovernedOptionSourceProvider was not constructed with an OptionSourceQueryExecutor delegate");
        }
        try {
            enforceOptionSourceFieldUses(descriptor, search, filterPayload, filters, sortKey, pageable);
            Page<OptionDTO<Object>> rawPage = executorDelegate.filterOptions(
                    entityManager,
                    entityClass,
                    specification,
                    filterPayload,
                    descriptor,
                    search,
                    searchStrategy,
                    filters,
                    sortKey,
                    pageable,
                    includeIds
            );
            return sanitizeOptionPage(rawPage, descriptor, OptionSourceOperation.FILTER, includeIds);
        } finally {
            serviceSupport.clearTransientRequestContexts();
        }
    }

    @Override
    public <E> List<OptionDTO<Object>> byIdsOptions(
            EntityManager entityManager,
            Class<E> entityClass,
            OptionSourceDescriptor descriptor,
            Collection<Object> ids
    ) {
        return byIdsOptions(entityManager, entityClass, null, null, descriptor, List.of(), ids);
    }

    @Override
    public <E> List<OptionDTO<Object>> byIdsOptions(
            EntityManager entityManager,
            Class<E> entityClass,
            Specification<E> specification,
            Object filterPayload,
            OptionSourceDescriptor descriptor,
            List<LookupFilterRequest> filters,
            Collection<Object> ids
    ) {
        if (executorDelegate == null) {
            throw new IllegalStateException("AuthzGovernedOptionSourceProvider was not constructed with an OptionSourceQueryExecutor delegate");
        }
        try {
            enforceOptionSourceFieldUses(descriptor, null, filterPayload, filters, null, null);
            List<OptionDTO<Object>> rawList = executorDelegate.byIdsOptions(
                    entityManager,
                    entityClass,
                    specification,
                    filterPayload,
                    descriptor,
                    filters,
                    ids
            );
            return sanitizeOptionList(rawList, descriptor, OptionSourceOperation.BY_IDS, ids);
        } finally {
            serviceSupport.clearTransientRequestContexts();
        }
    }

    private Page<OptionDTO<Object>> sanitizeOptionPage(
            Page<OptionDTO<Object>> rawPage,
            OptionSourceDescriptor descriptor,
            OptionSourceOperation operation,
            Collection<Object> includeOrByIds
    ) {
        if (rawPage == null) {
            return Page.empty();
        }
        List<OptionDTO<Object>> sanitized = sanitizeOptionList(
                rawPage.getContent(),
                descriptor,
                operation,
                includeOrByIds
        );
        return new PageImpl<>(sanitized, rawPage.getPageable(), rawPage.getTotalElements());
    }

    private List<OptionDTO<Object>> sanitizeOptionList(
            List<OptionDTO<Object>> rawOptions,
            OptionSourceDescriptor descriptor,
            OptionSourceOperation operation,
            Collection<Object> includeOrByIds
    ) {
        if (rawOptions == null || rawOptions.isEmpty()) {
            return List.of();
        }
        AuthorizedQueryScopeContext queryCtx = serviceSupport.currentQueryScopeContext();
        Set<String> valueDeniedAttrs = queryCtx != null && queryCtx.valueDeniedAttributeIds() != null
                ? queryCtx.valueDeniedAttributeIds()
                : Set.of();
        List<MaskDirective> maskDirectives = queryCtx != null && queryCtx.maskDirectives() != null
                ? queryCtx.maskDirectives()
                : serviceSupport.currentExportMaskDirectives();
        return sanitizeOptionsWithDirectives(
                rawOptions,
                descriptor,
                operation,
                includeOrByIds,
                valueDeniedAttrs,
                maskDirectives
        );
    }

    /**
     * Sanitizes a list of {@link OptionDTO} items using explicit {@code valueDeniedAttrs} and
     * {@code maskDirectives} ({@code Fase P10.19-A}, {@code P06}, {@code P07}, {@code P09}, {@code P12}, {@code P50}).
     */
    public List<OptionDTO<Object>> sanitizeOptionsWithDirectives(
            List<OptionDTO<Object>> rawOptions,
            OptionSourceDescriptor descriptor,
            OptionSourceOperation operation,
            Collection<Object> includeOrByIds,
            Set<String> valueDeniedAttrs,
            List<MaskDirective> maskDirectives
    ) {
        if (rawOptions == null || rawOptions.isEmpty()) {
            return List.of();
        }
        Set<String> effectiveValueDenied = new LinkedHashSet<>();
        if (valueDeniedAttrs != null) {
            effectiveValueDenied.addAll(valueDeniedAttrs);
        }
        for (FieldUseEffectDirective dir : governanceContract.baselineFieldUseDirectives()) {
            if (dir.category() == FieldUseCategory.VALUE
                    && dir.effect() == org.praxisplatform.authz.contracts.envelope.RuleEffect.DENY) {
                effectiveValueDenied.add(dir.attributeId());
            }
        }
        List<MaskDirective> effectiveMasks = maskDirectives == null ? List.of() : maskDirectives;

        Set<String> hydratedIdStrings = new LinkedHashSet<>();
        if (includeOrByIds != null) {
            for (Object id : includeOrByIds) {
                if (id != null) {
                    hydratedIdStrings.add(String.valueOf(id));
                }
            }
        }

        LookupSelectionPolicy selectionPolicy = resolveSelectionPolicy(descriptor);
        List<OptionDTO<Object>> sanitized = new ArrayList<>(rawOptions.size());
        for (OptionDTO<Object> option : rawOptions) {
            if (option == null || option.id() == null) {
                continue;
            }
            Map<String, String> maskedValueReplacements = new LinkedHashMap<>();
            Set<String> redactedValues = new LinkedHashSet<>();
            Map<String, Object> sanitizedExtra = sanitizeExtraMap(
                    option.extra(),
                    descriptor,
                    effectiveValueDenied,
                    effectiveMasks,
                    maskedValueReplacements,
                    redactedValues
            );
            String sanitizedLabel = sanitizeOptionLabel(
                    option,
                    descriptor,
                    effectiveValueDenied,
                    effectiveMasks,
                    maskedValueReplacements,
                    redactedValues
            );
            applySelectionEligibilityPolicy(
                    option.id(),
                    sanitizedExtra,
                    selectionPolicy,
                    operation,
                    hydratedIdStrings.contains(String.valueOf(option.id()))
            );
            sanitized.add(new OptionDTO<>(
                    option.id(),
                    sanitizedLabel,
                    sanitizedExtra.isEmpty() ? null : Map.copyOf(sanitizedExtra)
            ));
        }
        return List.copyOf(sanitized);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> sanitizeExtraMap(
            Map<String, Object> rawExtra,
            OptionSourceDescriptor descriptor,
            Set<String> valueDeniedAttrs,
            List<MaskDirective> maskDirectives,
            Map<String, String> maskedDescriptionReplacements,
            Set<String> redactedDescriptionValues
    ) {
        Map<String, Object> working = new LinkedHashMap<>();
        if (rawExtra == null || rawExtra.isEmpty()) {
            return working;
        }
        DetachedDtoMaskingResult topLevelMasked = maskingProcessor.projectAndMask(
                rawExtra,
                governanceContract.fieldSchemas(),
                valueDeniedAttrs,
                maskDirectives
        );
        Map<String, Object> maskedProjection = topLevelMasked.detachedProjection();

        for (Map.Entry<String, Object> entry : rawExtra.entrySet()) {
            String key = entry.getKey();
            Object val = entry.getValue();
            if ("displayFields".equals(key) && val instanceof Map<?, ?> displayFieldsMap) {
                Map<String, Object> rawDisplayFields = new LinkedHashMap<>();
                displayFieldsMap.forEach((k, v) -> rawDisplayFields.put(String.valueOf(k), v));
                DetachedDtoMaskingResult nestedMasked = maskingProcessor.projectAndMask(
                        rawDisplayFields,
                        governanceContract.fieldSchemas(),
                        valueDeniedAttrs,
                        maskDirectives
                );
                Map<String, Object> mergedDisplayFields = new LinkedHashMap<>(rawDisplayFields);
                for (var schema : governanceContract.fieldSchemas()) {
                    String wireName = schema.wireFieldName();
                    if (rawDisplayFields.containsKey(wireName)) {
                        Object rawVal = rawDisplayFields.get(wireName);
                        if (nestedMasked.detachedProjection().containsKey(wireName)) {
                            Object maskedVal = nestedMasked.detachedProjection().get(wireName);
                            mergedDisplayFields.put(wireName, maskedVal);
                            if (rawVal != null && maskedVal != null && !Objects.equals(rawVal, maskedVal)) {
                                maskedDescriptionReplacements.put(String.valueOf(rawVal), String.valueOf(maskedVal));
                            }
                        } else {
                            mergedDisplayFields.remove(wireName);
                            if (rawVal != null) {
                                redactedDescriptionValues.add(String.valueOf(rawVal));
                            }
                        }
                    }
                }
                working.put("displayFields", Map.copyOf(mergedDisplayFields));
                continue;
            }
            if ("richFields".equals(key) && val instanceof List<?> richFieldsList) {
                Map<String, Object> rawRichValues = new LinkedHashMap<>();
                for (Object item : richFieldsList) {
                    if (item instanceof Map<?, ?> fieldMap) {
                        Object fKey = fieldMap.get("key");
                        Object fVal = fieldMap.get("value");
                        if (fKey != null) {
                            rawRichValues.put(String.valueOf(fKey), fVal);
                        }
                    }
                }
                DetachedDtoMaskingResult nestedMasked = maskingProcessor.projectAndMask(
                        rawRichValues,
                        governanceContract.fieldSchemas(),
                        valueDeniedAttrs,
                        maskDirectives
                );
                List<Map<String, Object>> sanitizedRichFields = new ArrayList<>(richFieldsList.size());
                Map<String, Object> synchronizedDisplayFields = new LinkedHashMap<>();
                for (Object item : richFieldsList) {
                    if (!(item instanceof Map<?, ?> fieldMap)) {
                        continue;
                    }
                    Object fKeyObj = fieldMap.get("key");
                    if (fKeyObj == null) {
                        continue;
                    }
                    String fKey = String.valueOf(fKeyObj);
                    Object rawVal = fieldMap.get("value");
                    boolean isGoverned = governanceContract.fieldSchemas().stream()
                            .anyMatch(s -> s.wireFieldName().equals(fKey) || s.attributeId().equals(fKey));
                    if (isGoverned) {
                        if (!nestedMasked.detachedProjection().containsKey(fKey)) {
                            if (rawVal != null) {
                                redactedDescriptionValues.add(String.valueOf(rawVal));
                            }
                            continue;
                        }
                        Object maskedVal = nestedMasked.detachedProjection().get(fKey);
                        if (rawVal != null && maskedVal != null && !Objects.equals(rawVal, maskedVal)) {
                            maskedDescriptionReplacements.put(String.valueOf(rawVal), String.valueOf(maskedVal));
                        }
                        Map<String, Object> copy = new LinkedHashMap<>();
                        fieldMap.forEach((k, v) -> copy.put(String.valueOf(k), v));
                        copy.put("value", maskedVal);
                        sanitizedRichFields.add(Map.copyOf(copy));
                        synchronizedDisplayFields.put(fKey, maskedVal);
                    } else {
                        Map<String, Object> copy = new LinkedHashMap<>();
                        fieldMap.forEach((k, v) -> copy.put(String.valueOf(k), v));
                        sanitizedRichFields.add(Map.copyOf(copy));
                        synchronizedDisplayFields.put(fKey, rawVal);
                    }
                }
                working.put("richFields", List.copyOf(sanitizedRichFields));
                working.putIfAbsent("displayFields", Map.copyOf(synchronizedDisplayFields));
                continue;
            }
            boolean isGovernedSchemaField = governanceContract.fieldSchemas().stream()
                    .anyMatch(s -> s.wireFieldName().equals(key) || s.attributeId().equals(key));
            if (isGovernedSchemaField) {
                if (maskedProjection.containsKey(key)) {
                    Object maskedVal = maskedProjection.get(key);
                    working.put(key, maskedVal);
                    if (val != null && maskedVal != null && !Objects.equals(val, maskedVal)) {
                        maskedDescriptionReplacements.put(String.valueOf(val), String.valueOf(maskedVal));
                    }
                } else if (val != null) {
                    redactedDescriptionValues.add(String.valueOf(val));
                }
            } else {
                working.put(key, val);
            }
        }
        // Sanitize 'code' if mapped to a governed codePropertyPath (P10.6-R03)
        if (descriptor != null
                && descriptor.entityLookup() != null
                && descriptor.entityLookup().codePropertyPath() != null
                && working.containsKey("code")) {
            String codeProp = descriptor.entityLookup().codePropertyPath();
            boolean isGovernedCode = governanceContract.fieldSchemas().stream()
                    .anyMatch(s -> s.wireFieldName().equals(codeProp) || s.attributeId().equals(codeProp));
            if (isGovernedCode) {
                Object rawCode = working.get("code");
                DetachedDtoMaskingResult codeMasked = maskingProcessor.projectAndMask(
                        Map.of(codeProp, rawCode),
                        governanceContract.fieldSchemas(),
                        valueDeniedAttrs,
                        maskDirectives
                );
                if (codeMasked.detachedProjection().containsKey(codeProp)) {
                    Object maskedCode = codeMasked.detachedProjection().get(codeProp);
                    working.put("code", maskedCode);
                    if (rawCode != null && maskedCode != null && !Objects.equals(rawCode, maskedCode)) {
                        maskedDescriptionReplacements.put(String.valueOf(rawCode), String.valueOf(maskedCode));
                    }
                } else {
                    working.remove("code");
                    if (rawCode != null) {
                        redactedDescriptionValues.add(String.valueOf(rawCode));
                    }
                }
            }
        }
        // Sanitize 'badges' list if any badge contains a masked or redacted value (P10.6-R03)
        if (working.get("badges") instanceof List<?> rawBadges
                && (!maskedDescriptionReplacements.isEmpty() || !redactedDescriptionValues.isEmpty())) {
            List<String> sanitizedBadges = new ArrayList<>(rawBadges.size());
            for (Object badgeObj : rawBadges) {
                if (badgeObj == null) {
                    continue;
                }
                String badgeStr = String.valueOf(badgeObj);
                if (redactedDescriptionValues.contains(badgeStr)) {
                    continue;
                }
                String replaced = maskedDescriptionReplacements.getOrDefault(badgeStr, badgeStr);
                sanitizedBadges.add(replaced);
            }
            working.put("badges", List.copyOf(sanitizedBadges));
        }
        if (working.get("description") instanceof String desc && (!maskedDescriptionReplacements.isEmpty() || !redactedDescriptionValues.isEmpty())) {
            String sanitizedDesc = desc;
            for (Map.Entry<String, String> rep : maskedDescriptionReplacements.entrySet()) {
                sanitizedDesc = sanitizedDesc.replace(rep.getKey(), rep.getValue());
            }
            for (String redactedVal : redactedDescriptionValues) {
                sanitizedDesc = sanitizedDesc.replace(" - " + redactedVal, "")
                        .replace(redactedVal + " - ", "")
                        .replace(redactedVal, "");
            }
            working.put("description", sanitizedDesc);
        }
        return working;
    }

    private String sanitizeOptionLabel(
            OptionDTO<Object> option,
            OptionSourceDescriptor descriptor,
            Set<String> valueDeniedAttrs,
            List<MaskDirective> maskDirectives,
            Map<String, String> maskedValueReplacements,
            Set<String> redactedValues
    ) {
        String rawLabel = option.label();
        if (rawLabel == null) {
            return null;
        }
        if (descriptor != null) {
            String labelProp = descriptor.labelPropertyPath() != null
                    ? descriptor.labelPropertyPath()
                    : descriptor.propertyPath();
            if (labelProp != null) {
                boolean isGovernedLabel = governanceContract.fieldSchemas().stream()
                        .anyMatch(s -> s.wireFieldName().equals(labelProp) || s.attributeId().equals(labelProp));
                if (isGovernedLabel) {
                    DetachedDtoMaskingResult labelMasked = maskingProcessor.projectAndMask(
                            Map.of(labelProp, rawLabel),
                            governanceContract.fieldSchemas(),
                            valueDeniedAttrs,
                            maskDirectives
                    );
                    if (labelMasked.detachedProjection().containsKey(labelProp)) {
                        return String.valueOf(labelMasked.detachedProjection().get(labelProp));
                    }
                    return String.valueOf(option.id());
                }
            }
        }
        String sanitized = rawLabel;
        for (Map.Entry<String, String> rep : maskedValueReplacements.entrySet()) {
            sanitized = sanitized.replace(rep.getKey(), rep.getValue());
        }
        for (String redacted : redactedValues) {
            if (sanitized.equals(redacted)) {
                return String.valueOf(option.id());
            }
            sanitized = sanitized.replace(" - " + redacted, "")
                    .replace(redacted + " - ", "")
                    .replace(redacted, "");
        }
        return sanitized;
    }

    private void enforceOptionSourceFieldUses(
            OptionSourceDescriptor descriptor,
            String search,
            Object filterPayload,
            List<LookupFilterRequest> filters,
            String sortKey,
            Pageable pageable
    ) {
        Set<String> filterAttributes = new LinkedHashSet<>();
        Set<String> sortAttributes = new LinkedHashSet<>();
        if (filterPayload != null || (pageable != null && pageable.getSort().isSorted())) {
            Map<FieldUseCategory, Set<String>> extracted = serviceSupport.dtoIntrospector().extractQueryFieldUses(
                    filterPayload,
                    pageable != null ? pageable.getSort() : null,
                    governanceContract,
                    governanceSpec
            );
            Set<String> extractedFilterUses = extracted.get(FieldUseCategory.FILTER);
            if (extractedFilterUses != null) {
                for (String attr : extractedFilterUses) {
                    filterAttributes.addAll(resolveFieldIdentifierToAttributeIds(attr));
                }
            }
            Set<String> extractedSortUses = extracted.get(FieldUseCategory.SORT);
            if (extractedSortUses != null) {
                for (String attr : extractedSortUses) {
                    sortAttributes.addAll(resolveFieldIdentifierToAttributeIds(attr));
                }
            }
            if (descriptor != null && pageable != null && pageable.getSort().isSorted()) {
                String labelPath = (descriptor.labelPropertyPath() != null && !descriptor.labelPropertyPath().isBlank())
                        ? descriptor.labelPropertyPath()
                        : descriptor.propertyPath();
                String valuePath = (descriptor.valuePropertyPath() != null && !descriptor.valuePropertyPath().isBlank())
                        ? descriptor.valuePropertyPath()
                        : descriptor.propertyPath();
                for (org.springframework.data.domain.Sort.Order order : pageable.getSort()) {
                    if ("label".equals(order.getProperty()) && labelPath != null && !labelPath.isBlank()) {
                        sortAttributes.addAll(resolveFieldIdentifierToAttributeIds(labelPath.trim()));
                    } else if ("id".equals(order.getProperty()) && valuePath != null && !valuePath.isBlank()) {
                        sortAttributes.addAll(resolveFieldIdentifierToAttributeIds(valuePath.trim()));
                    }
                }
            }
        }
        if (filters != null) {
            for (LookupFilterRequest filterReq : filters) {
                if (filterReq != null && filterReq.field() != null && !filterReq.field().isBlank()) {
                    filterAttributes.addAll(resolveFieldIdentifierToAttributeIds(filterReq.field().trim()));
                }
            }
        }
        if (search != null && !search.isBlank() && descriptor != null) {
            boolean searchAllowed = descriptor.policy() == null
                    || (descriptor.policy().allowSearch() && !"none".equalsIgnoreCase(descriptor.policy().searchMode()));
            if (searchAllowed) {
                boolean hasExplicitSearchPaths = false;
                if (descriptor.entityLookup() != null && descriptor.entityLookup().searchPropertyPaths() != null) {
                    for (String sp : descriptor.entityLookup().searchPropertyPaths()) {
                        if (sp != null && !sp.isBlank()) {
                            filterAttributes.addAll(resolveFieldIdentifierToAttributeIds(sp.trim()));
                            hasExplicitSearchPaths = true;
                        }
                    }
                }
                if (!hasExplicitSearchPaths) {
                    String fallbackLabelPath = (descriptor.labelPropertyPath() != null && !descriptor.labelPropertyPath().isBlank())
                            ? descriptor.labelPropertyPath()
                            : descriptor.propertyPath();
                    if (fallbackLabelPath != null && !fallbackLabelPath.isBlank()) {
                        filterAttributes.addAll(resolveFieldIdentifierToAttributeIds(fallbackLabelPath.trim()));
                    }
                }
                var effectiveFiltering = descriptor.effectiveFiltering();
                if (effectiveFiltering != null && effectiveFiltering.quickFilterFields() != null) {
                    for (String qf : effectiveFiltering.quickFilterFields()) {
                        if (qf != null && !qf.isBlank()) {
                            filterAttributes.addAll(resolveFieldIdentifierToAttributeIds(qf.trim()));
                        }
                    }
                }
            }
        }
        String effectiveSortKey = (sortKey != null && !sortKey.isBlank())
                ? sortKey
                : ((pageable == null || !pageable.getSort().isSorted())
                        && descriptor != null
                        && descriptor.effectiveFiltering() != null
                        ? descriptor.effectiveFiltering().defaultSort()
                        : null);
        if (effectiveSortKey != null && !effectiveSortKey.isBlank()) {
            String normalizedSort = effectiveSortKey.trim();
            int colonIdx = normalizedSort.indexOf(':');
            if (colonIdx > 0) {
                normalizedSort = normalizedSort.substring(0, colonIdx).trim();
            }
            if (!normalizedSort.isEmpty()) {
                boolean matchedSymbolicSortOption = false;
                if (descriptor != null && descriptor.effectiveFiltering() != null
                        && descriptor.effectiveFiltering().sortOptions() != null) {
                    for (var sortOpt : descriptor.effectiveFiltering().sortOptions()) {
                        if (sortOpt != null
                                && (normalizedSort.equals(sortOpt.key()) || effectiveSortKey.trim().equals(sortOpt.key()))
                                && sortOpt.field() != null
                                && !sortOpt.field().isBlank()) {
                            sortAttributes.addAll(resolveFieldIdentifierToAttributeIds(sortOpt.field().trim()));
                            matchedSymbolicSortOption = true;
                        }
                    }
                }
                if (!matchedSymbolicSortOption) {
                    sortAttributes.addAll(resolveFieldIdentifierToAttributeIds(normalizedSort));
                }
            }
        }
        Map<FieldUseCategory, Set<String>> requestedByCategory = new EnumMap<>(FieldUseCategory.class);
        if (!filterAttributes.isEmpty()) {
            requestedByCategory.put(FieldUseCategory.FILTER, filterAttributes);
        }
        if (!sortAttributes.isEmpty()) {
            requestedByCategory.put(FieldUseCategory.SORT, sortAttributes);
        }
        if (requestedByCategory.isEmpty()) {
            return;
        }
        List<FieldUseEffectDirective> effectiveDirectives = new ArrayList<>(governanceContract.baselineFieldUseDirectives());
        AuthorizedQueryScopeContext queryCtx = serviceSupport.currentQueryScopeContext();
        if (queryCtx != null && queryCtx.combinedFieldUseDirectives() != null) {
            effectiveDirectives.addAll(queryCtx.combinedFieldUseDirectives());
        }
        fieldUseQueryGuard.guardQueryFieldUses(requestedByCategory, effectiveDirectives);

        if (queryCtx != null && queryCtx.valueDeniedAttributeIds() != null && !queryCtx.valueDeniedAttributeIds().isEmpty()) {
            Set<String> denied = queryCtx.valueDeniedAttributeIds();
            for (Map.Entry<FieldUseCategory, Set<String>> entry : requestedByCategory.entrySet()) {
                for (String attr : entry.getValue()) {
                    if (denied.contains(attr)) {
                        throw new FieldUseViolationException(
                                entry.getKey(),
                                Set.of(attr),
                                "Field use category " + entry.getKey() + " is denied for attribute: " + attr
                        );
                    }
                }
            }
        }
    }

    private Set<String> resolveFieldIdentifierToAttributeIds(String fieldOrPath) {
        Set<String> resolved = new LinkedHashSet<>();
        String clean = fieldOrPath.startsWith("/") ? fieldOrPath.substring(1) : fieldOrPath;
        resolved.add(clean);
        if (governanceContract.wirePointerToAttributeIdMap() != null) {
            String mapped = governanceContract.wirePointerToAttributeIdMap().get("/" + clean);
            if (mapped != null) {
                resolved.add(mapped);
            }
        }
        if (governanceSpec != null && governanceSpec.fieldBindings() != null) {
            for (var binding : governanceSpec.fieldBindings()) {
                if (clean.equals(binding.nativeJpaPath())
                        || clean.equals(binding.fieldPath())
                        || ("resource." + clean).equals(binding.fieldPath())
                        || clean.equals(binding.attributeId())) {
                    resolved.add(binding.attributeId());
                    resolved.add(binding.fieldPath());
                }
            }
        }
        for (DtoFieldSchemaMetadata schema : governanceContract.fieldSchemas()) {
            if (resolved.contains(schema.wireFieldName()) || resolved.contains(schema.attributeId())) {
                resolved.add(schema.attributeId());
                resolved.add(schema.wireFieldName());
            }
        }
        return resolved;
    }

    private static void applySelectionEligibilityPolicy(
            Object optionId,
            Map<String, Object> extra,
            LookupSelectionPolicy selectionPolicy,
            OptionSourceOperation operation,
            boolean requestedAsExistingId
    ) {
        if (selectionPolicy == null || selectionPolicy.isEmpty()) {
            return;
        }
        Object rawStatus = extra.get("status");
        if (rawStatus == null && selectionPolicy.statusPropertyPath() != null) {
            rawStatus = extra.get(selectionPolicy.statusPropertyPath());
        }
        String statusStr = rawStatus == null ? null : String.valueOf(rawStatus);
        boolean statusBlocked = false;
        if (statusStr != null) {
            if (!selectionPolicy.blockedStatuses().isEmpty()
                    && selectionPolicy.blockedStatuses().contains(statusStr)) {
                statusBlocked = true;
            }
            if (!selectionPolicy.allowedStatuses().isEmpty()
                    && !selectionPolicy.allowedStatuses().contains(statusStr)) {
                statusBlocked = true;
            }
        }
        if (Boolean.FALSE.equals(extra.get("selectable")) || Boolean.TRUE.equals(extra.get("disabled"))) {
            statusBlocked = true;
        }
        if (!statusBlocked) {
            extra.putIfAbsent("selectable", Boolean.TRUE);
            return;
        }
        extra.put("selectable", Boolean.FALSE);
        extra.put("disabled", Boolean.TRUE);
        if (selectionPolicy.disabledReasonTemplate() != null && !extra.containsKey("disabledReason")) {
            extra.put(
                    "disabledReason",
                    selectionPolicy.disabledReasonTemplate()
                            .replace("{status}", statusStr == null ? "" : statusStr)
                            .replace("{id}", String.valueOf(optionId))
            );
        }
        if ((operation == OptionSourceOperation.BY_IDS || requestedAsExistingId)
                && selectionPolicy.allowRetainInvalidExistingValue()) {
            extra.put("historicalDisplayOnly", Boolean.TRUE);
        }
    }

    private static LookupSelectionPolicy resolveSelectionPolicy(OptionSourceDescriptor descriptor) {
        if (descriptor == null) {
            return null;
        }
        EntityLookupDescriptor entityLookup = descriptor.entityLookup();
        return entityLookup == null ? null : entityLookup.selectionPolicy();
    }
}
