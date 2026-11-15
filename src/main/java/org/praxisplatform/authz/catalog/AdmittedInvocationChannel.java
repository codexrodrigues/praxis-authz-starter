package org.praxisplatform.authz.catalog;

/**
 * Admitted invocation channels for a governed decision point ({@code P34}, {@code P41}).
 *
 * <p>Discovery and enforcement apply identically across REST endpoints, proxied internal
 * application services, and governed durable workers without requiring a dedicated HTTP
 * controller per internal method ({@code P34}). Unproxied self-invocations are never admitted
 * ({@code P41}).</p>
 */
public enum AdmittedInvocationChannel {
    /** Bound to an HTTP / REST controller operation. */
    REST_ENDPOINT,

    /** Bound to a proxied internal Spring service method (non-REST, {@code P34}, {@code P41}). */
    PROXIED_INTERNAL_SERVICE,

    /** Bound to a governed durable background worker / batch unit ({@code P15}, {@code P34}). */
    GOVERNED_DURABLE_WORKER
}
