package org.praxisplatform.authz.host.metadata;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import jakarta.validation.constraints.NotNull;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.contracts.annotation.AuthzMask;
import org.praxisplatform.authz.contracts.annotation.AuthzMaskStrategy;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.uischema.annotation.DomainGovernance;
import org.praxisplatform.uischema.annotation.DomainGovernancePreset;

class MetadataDtoDefaultMaskTest {
    record CompositeId(long first, long second) {}

    @DomainGovernance(preset = DomainGovernancePreset.CONFIDENTIAL_OPERATIONAL)
    record ProtectedResponse(
            String label,
            Map<String, Integer> details,
            CompositeId relatedId,
            @NotNull CompositeId requiredId,
            @AuthzMask(strategy = AuthzMaskStrategy.OMIT) Map<String, Integer> omittedDetails) {}

    @Test
    void derivedMasksRehydrateComplexFieldsAndRetainExplicitAndRequiredFieldProtection() {
        var source = new ProtectedResponse("private", Map.of("entry", 7),
                new CompositeId(1, 2), new CompositeId(3, 4), Map.of("omitted", 9));
        var contract = new MetadataDtoGovernanceIntrospector().introspect(ProtectedResponse.class, "records");
        var masks = contract.effectiveMaskDirectives().stream().flatMap(mask ->
                mask.fieldSelector().attributeIds().stream().map(attribute ->
                        new MaskDirective(attribute, mask.strategyId(), mask.parameters()))).toList();
        Set<String> valueDenied = contract.baselineFieldUseDirectives().stream()
                .filter(rule -> rule.category() == FieldUseCategory.VALUE && rule.effect() == RuleEffect.DENY)
                .map(FieldUseEffectDirective::attributeId).collect(Collectors.toSet());

        var result = new DetachedDtoMaskingProcessor().projectAndMask(source, contract.fieldSchemas(), valueDenied, masks);
        var rehydrated = AuthzGovernedResourceServiceSupport.createMaskedProjectionObjectMapper()
                .convertValue(result.detachedProjection(), ProtectedResponse.class);

        assertEquals(Map.of("records.label", "REDACT_CONSTANT", "records.details", "NULLIFY",
                "records.related_id", "NULLIFY", "records.required_id", "OMIT_BY_FIELD_USE_DENY",
                "records.omitted_details", "OMIT"), result.appliedStrategiesByAttributeId());
        assertEquals("***", rehydrated.label());
        assertNull(rehydrated.details());
        assertNull(rehydrated.relatedId());
        assertFalse(result.detachedProjection().containsKey("requiredId"));
        assertFalse(result.detachedProjection().containsKey("omittedDetails"));
        assertEquals(Map.of("entry", 7), source.details());
        assertEquals(new CompositeId(1, 2), source.relatedId());
    }
}
