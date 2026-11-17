package org.praxisplatform.authz.host.metadata;

import java.util.Objects;
import org.praxisplatform.uischema.capability.AvailabilityDecision;
import org.praxisplatform.uischema.capability.ResourceOperationAvailabilityContext;
import org.praxisplatform.uischema.capability.ResourceOperationAvailabilityRule;
import org.springframework.core.Ordered;

/**
 * {@link ResourceOperationAvailabilityRule} delegating to
 * {@link AuthzResourceOperationAvailabilityProvider} so Praxis authorization decisions compose
 * cleanly inside {@code praxis-metadata-starter}'s {@code CompositeResourceOperationAvailabilityEvaluator}
 * alongside host-specific domain availability rules ({@code Wave 1.4B}).
 */
public class AuthzResourceOperationAvailabilityRule implements ResourceOperationAvailabilityRule, Ordered {

    /** Default precedence ensuring authorization evaluation executes early in rule chains. */
    public static final int DEFAULT_ORDER = Ordered.HIGHEST_PRECEDENCE + 300;

    private final AuthzResourceOperationAvailabilityProvider availabilityProvider;
    private final int order;

    /**
     * Creates a rule delegating to {@code availabilityProvider} with {@link #DEFAULT_ORDER}.
     *
     * @param availabilityProvider canonical Praxis authorization availability provider
     */
    public AuthzResourceOperationAvailabilityRule(
            AuthzResourceOperationAvailabilityProvider availabilityProvider
    ) {
        this(availabilityProvider, DEFAULT_ORDER);
    }

    /**
     * Creates a rule delegating to {@code availabilityProvider} with an explicit order.
     *
     * @param availabilityProvider canonical Praxis authorization availability provider
     * @param order Spring {@link Ordered} priority
     */
    public AuthzResourceOperationAvailabilityRule(
            AuthzResourceOperationAvailabilityProvider availabilityProvider,
            int order
    ) {
        this.availabilityProvider = Objects.requireNonNull(
                availabilityProvider, "availabilityProvider is required");
        this.order = order;
    }

    @Override
    public AvailabilityDecision evaluate(ResourceOperationAvailabilityContext context) {
        if (context == null) {
            return AvailabilityDecision.deny("AUTHZ_AVAILABILITY_CONTEXT_MISSING", java.util.Map.of());
        }
        return availabilityProvider.evaluate(context);
    }

    @Override
    public int getOrder() {
        return order;
    }
}
