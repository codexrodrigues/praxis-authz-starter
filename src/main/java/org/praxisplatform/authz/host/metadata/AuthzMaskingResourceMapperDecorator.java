package org.praxisplatform.authz.host.metadata;

import java.util.List;
import java.util.Objects;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.uischema.mapper.base.ResourceMapper;

/**
 * Decorator around {@code praxis-metadata-starter}'s {@link ResourceMapper} that automatically
 * applies detached DTO masking ({@code STEP_14}/{@code STEP_15}) to {@link #toResponse(Object)}
 * during authorized read queries and post-mutation response materialization while preserving
 * unmasked draft projections during pre-mutation validation ({@code P11}, {@code P12}, {@code P13}, {@code P40}).
 *
 * @param <E> JPA entity type
 * @param <R> response DTO type (supports immutable Java {@code record}s and POJOs)
 * @param <C> create DTO type
 * @param <U> update DTO type
 * @param <ID> entity identifier type
 */
public final class AuthzMaskingResourceMapperDecorator<E, R, C, U, ID>
        implements ResourceMapper<E, R, C, U, ID> {

    private final ResourceMapper<E, R, C, U, ID> delegate;
    private final AuthzGovernedResourceServiceSupport serviceSupport;
    private final Class<R> responseType;
    private final List<DtoFieldSchemaMetadata> fieldSchemas;

    /**
     * Creates a masking decorator around a host {@link ResourceMapper}.
     *
     * @param delegate underlying host {@link ResourceMapper}
     * @param serviceSupport governed resource service support managing query and mutation stages
     * @param responseType response DTO class
     * @param fieldSchemas canonical DTO field schema descriptors
     */
    public AuthzMaskingResourceMapperDecorator(
            ResourceMapper<E, R, C, U, ID> delegate,
            AuthzGovernedResourceServiceSupport serviceSupport,
            Class<R> responseType,
            List<DtoFieldSchemaMetadata> fieldSchemas
    ) {
        this.delegate = Objects.requireNonNull(delegate, "delegate is required");
        this.serviceSupport = Objects.requireNonNull(serviceSupport, "serviceSupport is required");
        this.responseType = Objects.requireNonNull(responseType, "responseType is required");
        this.fieldSchemas = List.copyOf(Objects.requireNonNull(fieldSchemas, "fieldSchemas is required"));
    }

    @Override
    public R toResponse(E entity) {
        R rawResponse = delegate.toResponse(entity);
        if (rawResponse == null) {
            return null;
        }
        return serviceSupport.maskMapperResponseIfReady(rawResponse, responseType, fieldSchemas);
    }

    @Override
    public E newEntity(C dto) {
        return delegate.newEntity(dto);
    }

    @Override
    public void applyUpdate(E entity, U dto) {
        delegate.applyUpdate(entity, dto);
    }

    @Override
    public ID extractId(E entity) {
        return delegate.extractId(entity);
    }
}
