package org.praxisplatform.authz.host.metadata;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import org.springframework.util.ClassUtils;

/**
 * Reflection-safe helper that unwraps Hibernate entity proxies without introducing a hard runtime
 * dependency on {@code org.hibernate.Hibernate} for non-JPA hosts where
 * {@code spring-boot-starter-data-jpa} is absent.
 */
final class AuthzEntityUnproxySupport {

    private static final MethodHandle HIBERNATE_UNPROXY = resolveHibernateUnproxy();

    private AuthzEntityUnproxySupport() {
    }

    private static MethodHandle resolveHibernateUnproxy() {
        ClassLoader cl = AuthzEntityUnproxySupport.class.getClassLoader();
        if (!ClassUtils.isPresent("org.hibernate.Hibernate", cl)) {
            return null;
        }
        try {
            Class<?> hibernateClass = Class.forName("org.hibernate.Hibernate", false, cl);
            return MethodHandles.publicLookup().findStatic(
                    hibernateClass,
                    "unproxy",
                    MethodType.methodType(Object.class, Object.class)
            );
        } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException ex) {
            return null;
        }
    }

    /**
     * Returns the underlying entity implementation when {@code entity} is a Hibernate proxy and
     * Hibernate is present on the classpath; otherwise returns {@code entity} untouched.
     */
    @SuppressWarnings("unchecked")
    static <T> T unproxy(T entity) {
        if (entity == null || HIBERNATE_UNPROXY == null) {
            return entity;
        }
        try {
            return (T) HIBERNATE_UNPROXY.invoke(entity);
        } catch (RuntimeException | Error ex) {
            throw ex;
        } catch (Throwable ex) {
            throw new IllegalStateException("Failed to unproxy entity of type " + entity.getClass().getName(), ex);
        }
    }
}
