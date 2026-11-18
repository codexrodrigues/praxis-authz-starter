package org.praxisplatform.authz.agent;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointKind;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.host.metadata.AuthzCallerContext;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.authz.host.metadata.ThreadLocalAuthzCallerContextProvider;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.OperationalAgentOpaProjection;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry.RegisteredDecisionPointContext;
import org.praxisplatform.config.ai.agent.bridge.DefaultMetadataGovernanceAgentAuthorizationBridge;
import org.praxisplatform.config.ai.agent.spi.AgentAuthorizationBridge;
import org.praxisplatform.config.ai.agent.spi.AgentExecutionContext;
import org.praxisplatform.config.ai.agent.spi.DualProjectedPayload;
import org.praxisplatform.uischema.capability.AvailabilityDecision;
import org.praxisplatform.uischema.capability.ResourceOperationAvailabilityContext;

/**
 * Implementacao de {@link AgentAuthorizationBridge} integrada ao {@code praxis-authz-starter}.
 *
 * <p>Combina governanca declarativa em DTOs ({@code @DomainGovernance}, {@code @AiUsagePolicy} e
 * {@code @UISchema}) com verificacoes ao vivo OPA ({@link GovernedExportAndAiToolAuthorizationSeam}
 * e {@link AuthzResourceOperationAvailabilityProvider}) sempre que pontos {@code TARGET}
 * estiverem registrados no {@link RuntimeDecisionPointRegistry}.
 */
public final class AuthzAgentAuthorizationBridge implements AgentAuthorizationBridge {

    private final DefaultMetadataGovernanceAgentAuthorizationBridge metadataGovernance;
    private final GovernedExportAndAiToolAuthorizationSeam aiToolSeam;
    private final RuntimeDecisionPointRegistry decisionPointRegistry;
    private final ThreadLocalAuthzCallerContextProvider callerContextProvider;
    private final MetadataDtoGovernanceIntrospector dtoIntrospector;
    private final AuthzResourceOperationAvailabilityProvider availabilityProvider;
    private final Map<String, String> resourcePathToTargetPointKey;

    public AuthzAgentAuthorizationBridge(
            DefaultMetadataGovernanceAgentAuthorizationBridge metadataGovernance,
            GovernedExportAndAiToolAuthorizationSeam aiToolSeam,
            RuntimeDecisionPointRegistry decisionPointRegistry,
            ThreadLocalAuthzCallerContextProvider callerContextProvider,
            MetadataDtoGovernanceIntrospector dtoIntrospector,
            AuthzResourceOperationAvailabilityProvider availabilityProvider,
            Map<String, String> resourcePathToTargetPointKey) {
        this.metadataGovernance = metadataGovernance != null
                ? metadataGovernance
                : new DefaultMetadataGovernanceAgentAuthorizationBridge();
        this.aiToolSeam = aiToolSeam;
        this.decisionPointRegistry = decisionPointRegistry;
        this.callerContextProvider = callerContextProvider;
        this.dtoIntrospector = dtoIntrospector;
        this.availabilityProvider = availabilityProvider;
        this.resourcePathToTargetPointKey = resourcePathToTargetPointKey == null
                ? Map.of()
                : Map.copyOf(resourcePathToTargetPointKey);
    }

    @Override
    public boolean canReadResource(AgentExecutionContext context, String resourcePath) {
        if (availabilityProvider != null) {
            Optional<DecisionPointDescriptor> targetPoint = resolveTargetDescriptor(resourcePath);
            if (targetPoint.isPresent()) {
                String resourceKey = targetPoint.get().identity().resourceKey();
                if (availabilityProvider.hasResourceBinding(resourceKey)) {
                    AvailabilityDecision decision = availabilityProvider.evaluate(
                            ResourceOperationAvailabilityContext.collection(resourceKey, resourcePath, "read"));
                    if (decision == null || !decision.allowed()) {
                        return false;
                    }
                }
            }
        }
        return metadataGovernance.canReadResource(context, resourcePath);
    }

    @Override
    public boolean canInvokeAction(
            AgentExecutionContext context,
            String resourcePath,
            String actionId,
            Object entityId) {
        if (availabilityProvider != null) {
            Optional<DecisionPointDescriptor> targetPoint = resolveTargetDescriptor(resourcePath);
            if (targetPoint.isPresent()) {
                String resourceKey = targetPoint.get().identity().resourceKey();
                if (availabilityProvider.hasResourceBinding(resourceKey)) {
                    AvailabilityDecision decision = entityId == null
                            ? availabilityProvider.evaluate(
                                    ResourceOperationAvailabilityContext.collection(resourceKey, resourcePath, actionId))
                            : availabilityProvider.evaluate(
                                    ResourceOperationAvailabilityContext.item(resourceKey, resourcePath, actionId, entityId));
                    if (decision == null || !decision.allowed()) {
                        return false;
                    }
                }
            }
        }
        return metadataGovernance.canInvokeAction(context, resourcePath, actionId, entityId);
    }

    @Override
    public boolean canModifyFields(
            AgentExecutionContext context,
            String resourcePath,
            Class<?> dtoType,
            Set<String> fieldNames) {
        return metadataGovernance.canModifyFields(context, resourcePath, dtoType, fieldNames);
    }

    @Override
    public DualProjectedPayload projectRecord(
            AgentExecutionContext context,
            String resourcePath,
            Class<?> dtoType,
            Map<String, Object> rawRecord) {
        DualProjectedPayload base = metadataGovernance.projectRecord(context, resourcePath, dtoType, rawRecord);
        if (rawRecord == null || rawRecord.isEmpty()) {
            return base;
        }

        Optional<DecisionPointDescriptor> targetPoint = resolveTargetDescriptor(resourcePath);
        String defaultResourceKey = targetPoint.map(dp -> dp.identity().resourceKey()).orElse(resourcePath);
        IntrospectedDtoGovernanceContract contract = dtoType != null && dtoIntrospector != null
                ? dtoIntrospector.introspect(dtoType, defaultResourceKey)
                : null;

        Map<String, Object> uiRecord = new LinkedHashMap<>(base.uiRecord());
        Map<String, Object> modelSafeRecord = new LinkedHashMap<>(base.modelSafeRecord());
        Set<String> hiddenFields = new LinkedHashSet<>(base.hiddenFields());
        Set<String> maskedForAiFields = new LinkedHashSet<>(base.maskedForAiFields());

        if (contract != null && !contract.aiContextDeniedAttributeIds().isEmpty()) {
            for (DtoFieldSchemaMetadata field : contract.fieldSchemas()) {
                if (contract.aiContextDeniedAttributeIds().contains(field.attributeId())
                        && modelSafeRecord.containsKey(field.wireFieldName())) {
                    modelSafeRecord.remove(field.wireFieldName());
                    maskedForAiFields.add(field.wireFieldName());
                }
            }
        }

        if (targetPoint.isPresent() && aiToolSeam != null) {
            String pointKey = targetPoint.get().identity().pointKey();
            List<DtoFieldSchemaMetadata> fieldSchemas = contract != null
                    ? contract.fieldSchemas()
                    : deriveAdHocSchemas(rawRecord);
            Map<String, String> attributeToWire = new LinkedHashMap<>();
            for (DtoFieldSchemaMetadata schema : fieldSchemas) {
                if (schema.attributeId() != null && schema.wireFieldName() != null) {
                    attributeToWire.putIfAbsent(schema.attributeId(), schema.wireFieldName());
                }
            }

            Map<String, Object> trustedFacts = new LinkedHashMap<>();
            Map<String, FactResolutionStatus> trustedStatuses = new LinkedHashMap<>();

            AuthzCallerContext caller = callerContextProvider != null
                    ? callerContextProvider.currentCallerContextOptional().orElse(null)
                    : null;
            if (caller != null) {
                trustedFacts.putAll(caller.subjectAndEnvironmentFacts());
                trustedStatuses.putAll(caller.factStatuses());
            } else if (context != null) {
                if (context.userId() != null) {
                    trustedFacts.put("subject.principalId", context.userId());
                    trustedStatuses.put("subject.principalId", FactResolutionStatus.PRESENT);
                    trustedFacts.put("subject.id", context.userId());
                    trustedStatuses.put("subject.id", FactResolutionStatus.PRESENT);
                }
                if (context.tenantId() != null) {
                    trustedFacts.put("subject.tenantId", context.tenantId());
                    trustedStatuses.put("subject.tenantId", FactResolutionStatus.PRESENT);
                    trustedFacts.put("tenant.id", context.tenantId());
                    trustedStatuses.put("tenant.id", FactResolutionStatus.PRESENT);
                }
                if (context.authorities() != null) {
                    trustedFacts.put("subject.roles", List.copyOf(context.authorities()));
                    trustedStatuses.put("subject.roles", FactResolutionStatus.PRESENT);
                }
            }

            Optional<RegisteredDecisionPointContext> registeredPoint = decisionPointRegistry != null
                    ? decisionPointRegistry.findRegisteredPoint(pointKey)
                    : Optional.empty();
            if (registeredPoint.isPresent() && registeredPoint.get().factContract() != null) {
                extractResourceTargetFacts(
                        rawRecord,
                        registeredPoint.get().factContract(),
                        attributeToWire,
                        trustedFacts,
                        trustedStatuses);
            }
            if (rawRecord.containsKey("id") && rawRecord.get("id") != null) {
                trustedFacts.putIfAbsent("resource.id", rawRecord.get("id"));
                trustedStatuses.putIfAbsent("resource.id", FactResolutionStatus.PRESENT);
            }

            String tenantId = caller != null ? caller.tenantId()
                    : (context != null && context.tenantId() != null ? context.tenantId() : "default");
            String env = context != null && context.environment() != null ? context.environment() : "prod";

            OperationalAgentOpaProjection opaProjected = aiToolSeam.projectOperationalAgentRecord(
                    pointKey,
                    tenantId,
                    env,
                    Collections.unmodifiableMap(new LinkedHashMap<>(uiRecord)),
                    Collections.unmodifiableMap(new LinkedHashMap<>(modelSafeRecord)),
                    fieldSchemas,
                    trustedFacts,
                    trustedStatuses);

            Set<String> wireFieldsHiddenByOpa = new LinkedHashSet<>();
            for (DtoFieldSchemaMetadata schema : fieldSchemas) {
                if (opaProjected.dynamicValueDeniedAttributeIds().contains(schema.attributeId())) {
                    wireFieldsHiddenByOpa.add(schema.wireFieldName());
                }
            }
            Set<String> maskedAttributeIds = new LinkedHashSet<>();
            for (MaskDirective dir : opaProjected.activeMaskDirectives()) {
                if (dir.attributeId() != null) {
                    maskedAttributeIds.add(dir.attributeId());
                }
            }
            Set<String> wireFieldsMaskedByOpa = new LinkedHashSet<>();
            for (DtoFieldSchemaMetadata schema : fieldSchemas) {
                if (maskedAttributeIds.contains(schema.attributeId())) {
                    wireFieldsMaskedByOpa.add(schema.wireFieldName());
                }
            }

            for (String key : new ArrayList<>(uiRecord.keySet())) {
                if (wireFieldsHiddenByOpa.contains(key)) {
                    uiRecord.remove(key);
                    hiddenFields.add(key);
                } else if (wireFieldsMaskedByOpa.contains(key)) {
                    if (!opaProjected.maskedUiPayload().containsKey(key)) {
                        uiRecord.remove(key);
                        hiddenFields.add(key);
                    } else {
                        Object opaUiValue = opaProjected.maskedUiPayload().get(key);
                        if (!Objects.equals(opaUiValue, uiRecord.get(key))) {
                            uiRecord.put(key, opaUiValue);
                        }
                    }
                }
            }

            for (String key : new ArrayList<>(modelSafeRecord.keySet())) {
                if (!opaProjected.maskedModelPayload().containsKey(key)) {
                    modelSafeRecord.remove(key);
                    maskedForAiFields.add(key);
                } else {
                    Object opaValue = opaProjected.maskedModelPayload().get(key);
                    Object existingValue = modelSafeRecord.get(key);
                    if (!Objects.equals(opaValue, existingValue)) {
                        modelSafeRecord.put(key, opaValue);
                        maskedForAiFields.add(key);
                    }
                }
            }
        }

        return new DualProjectedPayload(
                uiRecord,
                modelSafeRecord,
                List.copyOf(hiddenFields),
                List.copyOf(maskedForAiFields));
    }

    private Optional<DecisionPointDescriptor> resolveTargetDescriptor(String resourcePath) {
        if (decisionPointRegistry == null || resourcePath == null || resourcePath.isBlank()) {
            return Optional.empty();
        }
        String normalizedTarget = normalizePath(resourcePath);
        String mappedKey = resourcePathToTargetPointKey.get(resourcePath);
        if (mappedKey == null) {
            for (Map.Entry<String, String> entry : resourcePathToTargetPointKey.entrySet()) {
                if (entry.getKey() != null && normalizePath(entry.getKey()).equals(normalizedTarget)) {
                    mappedKey = entry.getValue();
                    break;
                }
            }
        }
        if (mappedKey != null) {
            return decisionPointRegistry.findRegisteredPoint(mappedKey)
                    .map(RegisteredDecisionPointContext::decisionPoint)
                    .filter(dp -> dp.evaluationModes().contains(EvaluationMode.TARGET));
        }

        List<DecisionPointDescriptor> candidates = new ArrayList<>();
        for (DecisionPointDescriptor descriptor : decisionPointRegistry.getDecisionPointsByKey().values()) {
            if (descriptor.evaluationModes().contains(EvaluationMode.TARGET)) {
                candidates.add(descriptor);
            }
        }

        DecisionPointDescriptor nonPrimaryExact = null;
        for (DecisionPointDescriptor descriptor : candidates) {
            if (normalizePath(descriptor.canonicalPath()).equals(normalizedTarget)
                    || normalizePath(descriptor.identity().resourceKey()).equals(normalizedTarget)) {
                if (isPrimaryResourceOperation(descriptor)) {
                    return Optional.of(descriptor);
                }
                if (nonPrimaryExact == null) {
                    nonPrimaryExact = descriptor;
                }
            }
        }
        if (nonPrimaryExact != null) {
            return Optional.of(nonPrimaryExact);
        }

        for (DecisionPointDescriptor descriptor : candidates) {
            if (!isPrimaryResourceOperation(descriptor)) {
                continue;
            }
            String basePath = stripTrailingFilter(normalizePath(descriptor.canonicalPath()));
            if (basePath.equals(normalizedTarget)) {
                return Optional.of(descriptor);
            }
        }

        String strippedTarget = stripLeadingApi(normalizedTarget);
        for (DecisionPointDescriptor descriptor : candidates) {
            if (!isPrimaryResourceOperation(descriptor)) {
                continue;
            }
            String strippedBase = stripLeadingApi(stripTrailingFilter(normalizePath(descriptor.canonicalPath())));
            if (!strippedTarget.isEmpty() && strippedBase.equals(strippedTarget)) {
                return Optional.of(descriptor);
            }
        }
        return Optional.empty();
    }

    private static boolean isPrimaryResourceOperation(DecisionPointDescriptor descriptor) {
        if (descriptor.identity().pointKind() != DecisionPointKind.RESOURCE_OPERATION) {
            return false;
        }
        String opKey = descriptor.identity().operationOrActionKey();
        return opKey == null || !opKey.startsWith("surface-");
    }

    private static String stripTrailingFilter(String normalizedPath) {
        if (normalizedPath.endsWith("/filter")) {
            return normalizedPath.substring(0, normalizedPath.length() - "/filter".length());
        }
        return normalizedPath;
    }

    private static String stripLeadingApi(String normalizedPath) {
        if ("/api".equals(normalizedPath)) {
            return "";
        }
        if (normalizedPath.startsWith("/api/")) {
            return normalizedPath.substring("/api".length());
        }
        return normalizedPath;
    }

    private static void extractResourceTargetFacts(
            Map<String, Object> rawRecord,
            FactContract factContract,
            Map<String, String> attributeToWire,
            Map<String, Object> trustedFacts,
            Map<String, FactResolutionStatus> trustedStatuses
    ) {
        for (FactDescriptor fd : factContract.descriptorsByPath().values()) {
            String factPath = fd.factPath();
            if (factPath == null || !factPath.startsWith("resource.")) {
                continue;
            }
            String directKey = factPath.substring("resource.".length());
            String wireKey = rawRecord.containsKey(directKey)
                    ? directKey
                    : (fd.attributeId() != null ? attributeToWire.get(fd.attributeId()) : null);
            if (wireKey == null || !rawRecord.containsKey(wireKey)) {
                continue;
            }
            Object rawValue = rawRecord.get(wireKey);
            if (rawValue == null) {
                trustedStatuses.putIfAbsent(factPath, FactResolutionStatus.NULL);
                continue;
            }
            Object coerced = coerceTargetFactValue(rawValue, fd.valueType());
            if (coerced != null) {
                trustedFacts.putIfAbsent(factPath, coerced);
                trustedStatuses.putIfAbsent(factPath, FactResolutionStatus.PRESENT);
            }
        }
    }

    private static Object coerceTargetFactValue(Object rawValue, FactValueType valueType) {
        if (rawValue == null || valueType == null) {
            return rawValue;
        }
        return switch (valueType) {
            case INT64 -> {
                if (rawValue instanceof Number n) {
                    yield n.longValue();
                }
                if (rawValue instanceof String s && !s.isBlank()) {
                    try {
                        yield Long.parseLong(s.trim());
                    } catch (NumberFormatException ignored) {
                        yield rawValue;
                    }
                }
                yield rawValue;
            }
            case DECIMAL -> {
                if (rawValue instanceof BigDecimal bd) {
                    yield bd;
                }
                if (rawValue instanceof Number n) {
                    yield new BigDecimal(n.toString());
                }
                if (rawValue instanceof String s && !s.isBlank()) {
                    try {
                        yield new BigDecimal(s.trim());
                    } catch (NumberFormatException ignored) {
                        yield rawValue;
                    }
                }
                yield rawValue;
            }
            case BOOLEAN -> {
                if (rawValue instanceof Boolean b) {
                    yield b;
                }
                if (rawValue instanceof String s) {
                    if ("true".equalsIgnoreCase(s.trim())) {
                        yield Boolean.TRUE;
                    }
                    if ("false".equalsIgnoreCase(s.trim())) {
                        yield Boolean.FALSE;
                    }
                }
                yield rawValue;
            }
            case STRING, ENUM -> {
                if (rawValue instanceof CharSequence || rawValue instanceof Enum<?>
                        || rawValue instanceof Number || rawValue instanceof Boolean) {
                    yield String.valueOf(rawValue);
                }
                yield rawValue;
            }
            default -> rawValue;
        };
    }

    private static String normalizePath(String path) {
        if (path == null) {
            return "";
        }
        String trimmed = path.trim();
        while (trimmed.endsWith("/") && trimmed.length() > 1) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed.toLowerCase(Locale.ROOT);
    }

    private static List<DtoFieldSchemaMetadata> deriveAdHocSchemas(Map<String, Object> rawRecord) {
        List<DtoFieldSchemaMetadata> list = new ArrayList<>(rawRecord.size());
        for (String key : rawRecord.keySet()) {
            list.add(new DtoFieldSchemaMetadata(
                    key,
                    "attr:" + key,
                    org.praxisplatform.authz.contracts.context.FactValueType.STRING,
                    true));
        }
        return list;
    }
}
