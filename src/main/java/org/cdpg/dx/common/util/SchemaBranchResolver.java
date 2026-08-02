package org.cdpg.dx.common.util;

import io.vertx.core.json.pointer.JsonPointer;
import io.vertx.json.schema.Schema;

/**
 * Resolves a {@code $ref} appearing inside a schema back into the {@link Schema} it points at.
 *
 * <p>Exists so {@link RequestValidationErrorFormatter} can re-validate the branches of a failed
 * {@code oneOf} without depending on vertx-web-openapi: the branches of a bundled OpenAPI schema are
 * refs to internal {@code urn:vertxschemas:<uuid>} identifiers, and only the {@code SchemaRouter}
 * built by the router knows how to turn those back into schemas. The api server owns that router and
 * supplies the lambda; everything else treats this as an optional capability and degrades to the
 * generic message when it is absent.
 */
@FunctionalInterface
public interface SchemaBranchResolver {

  /**
   * @param ref the raw {@code $ref} value, e.g. {@code urn:vertxschemas:9129c20a-…#}
   * @param scope scope of the schema the ref was found in, used for relative refs
   * @return the referenced schema, or null when it cannot be resolved — callers must treat null as
   *     "no extra detail available" rather than an error
   */
  Schema resolve(String ref, JsonPointer scope);
}