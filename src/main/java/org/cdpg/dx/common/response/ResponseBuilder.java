package org.cdpg.dx.common.response;

import static org.cdpg.dx.common.config.CorsUtil.HEADER_ALLOW_ORIGIN;
import static org.cdpg.dx.common.config.CorsUtil.allowedOrigins;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.json.EncodeException;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.jackson.DatabindCodec;
import io.vertx.ext.web.RoutingContext;
import org.cdpg.dx.common.HttpStatusCode;
import org.cdpg.dx.common.URNGenerator;
import org.cdpg.dx.common.util.PaginationInfo;

/**
 * Generic response builder for standardized API responses across all DX microservices.
 *
 * <p>Provides static helper methods to:
 * <ul>
 *   <li>Create {@link DxResponse} objects for service-layer results</li>
 *   <li>Send JSON responses directly via {@link RoutingContext} with proper CORS headers</li>
 * </ul>
 *
 * <h3>Usage in controllers:</h3>
 * <pre>{@code
 * // Send success with result
 * ResponseBuilder.sendSuccess(ctx, result, urnGenerator);
 *
 * // Send success with pagination
 * ResponseBuilder.sendSuccess(ctx, result, pageInfo, urnGenerator);
 *
 * // Send created
 * ResponseBuilder.sendCreated(ctx, "Resource created", result, urnGenerator);
 *
 * // Build response object (for service layer)
 * DxResponse<MyResult> response = ResponseBuilder.success(urnGenerator, "detail", result);
 * }</pre>
 */
public class ResponseBuilder {

  private ResponseBuilder() {}

  private static volatile ObjectMapper nullPreservingMapper;

  /**
   * {@link JsonObject#mapFrom(Object)}/{@code encode()} serialize via Vert.x's shared,
   * process-wide {@link DatabindCodec#mapper()}, which {@code AbstractApiServerVerticle}
   * configures with {@code NON_EMPTY} inclusion so response bodies omit null/empty fields by
   * default. That silently drops explicit null values nested inside a {@code result} payload
   * (e.g. an item's {@code "inactive_date": null}). This clones the shared mapper (preserving its
   * date-format/naming config) and overrides inclusion back to {@code ALWAYS} on the clone only,
   * so callers that opt in via the {@code *PreservingNulls} methods below keep nested nulls
   * without changing the default behavior of every other response.
   */
  private static ObjectMapper nullPreservingMapper() {
    ObjectMapper mapper = nullPreservingMapper;
    if (mapper == null) {
      synchronized (ResponseBuilder.class) {
        mapper = nullPreservingMapper;
        if (mapper == null) {
          mapper = DatabindCodec.mapper().copy();
          mapper.setSerializationInclusion(JsonInclude.Include.ALWAYS);
          nullPreservingMapper = mapper;
        }
      }
    }
    return mapper;
  }

  private static String encode(Object response, boolean preserveNulls) {
    if (!preserveNulls) {
      return JsonObject.mapFrom(response).encode();
    }
    try {
      return nullPreservingMapper().writeValueAsString(response);
    } catch (Exception e) {
      throw new EncodeException("Failed to encode response", e);
    }
  }

  // --- Build DxResponse objects (for service-layer use) ---

  public static <T> DxResponse<T> success(
      URNGenerator urnGenerator, String detail, T result, PaginationInfo pageInfo) {
    HttpStatusCode code = HttpStatusCode.SUCCESS;
    String urn = urnGenerator.generateUrn(code.getPath());
    return new DxResponse<>(urn, code.getDescription(), detail, result, pageInfo);
  }

  public static <T> DxResponse<T> success(URNGenerator urnGenerator, String detail, T result) {
    HttpStatusCode code = HttpStatusCode.SUCCESS;
    String urn = urnGenerator.generateUrn(code.getPath());
    return new DxResponse<>(urn, code.getDescription(), detail, result, null);
  }

  public static DxResponse<Void> success(URNGenerator urnGenerator, String detail) {
    return success(urnGenerator, detail, null);
  }

  // --- Send responses via RoutingContext ---

  public static <T> void send(
      RoutingContext ctx,
      HttpStatusCode status,
      String detail,
      T result,
      PaginationInfo pageInfo,
      URNGenerator urnGenerator) {
    send(ctx, status, detail, result, pageInfo, urnGenerator, false);
  }

  private static <T> void send(
      RoutingContext ctx,
      HttpStatusCode status,
      String detail,
      T result,
      PaginationInfo pageInfo,
      URNGenerator urnGenerator,
      boolean preserveNulls) {
    if (status == HttpStatusCode.NO_CONTENT) {
      ctx.response().setStatusCode(status.getValue()).end();
      return;
    }
    String urn = urnGenerator.generateUrn(status.getPath());
    DxResponse<T> response =
        new DxResponse<>(urn, status.getDescription(), detail, result, pageInfo);
    String body = encode(response, preserveNulls);
    String requestOrigin = ctx.request().getHeader("Origin");
    if (allowedOrigins != null
        && requestOrigin != null
        && (allowedOrigins.contains(requestOrigin) || allowedOrigins.contains("*"))) {
      ctx.response()
          .putHeader("Content-Type", "application/json")
          .putHeader(HEADER_ALLOW_ORIGIN, requestOrigin)
          .putHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
          .putHeader("Access-Control-Allow-Headers", "Authorization, Content-Type")
          .setStatusCode(status.getValue())
          .end(body);
    } else {
      ctx.response()
          .putHeader("Content-Type", "application/json")
          .setStatusCode(status.getValue())
          .end(body);
    }
  }

  // --- Success shortcuts ---

  public static void sendSuccess(RoutingContext ctx, String detail, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.SUCCESS, detail, null, null, urnGenerator);
  }

  public static <R> void sendSuccess(RoutingContext ctx, R result, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.SUCCESS, null, result, null, urnGenerator);
  }

  public static <T> void sendSuccess(
      RoutingContext ctx, T result, PaginationInfo pageInfo, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.SUCCESS, null, result, pageInfo, urnGenerator);
  }

  public static <T> void sendSuccess(
      RoutingContext ctx,
      String detail,
      T result,
      PaginationInfo pageInfo,
      URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.SUCCESS, detail, result, pageInfo, urnGenerator);
  }

  public static <T> void sendSuccess(
      RoutingContext ctx, String detail, T result, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.SUCCESS, detail, result, null, urnGenerator);
  }

  // --- Success shortcuts that keep explicit nulls inside `result` (e.g. item payloads) ---

  public static <R> void sendSuccessPreservingNulls(
      RoutingContext ctx, R result, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.SUCCESS, null, result, null, urnGenerator, true);
  }

  public static <T> void sendSuccessPreservingNulls(
      RoutingContext ctx,
      String detail,
      T result,
      PaginationInfo pageInfo,
      URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.SUCCESS, detail, result, pageInfo, urnGenerator, true);
  }

  // --- Created shortcuts ---

  public static <T> void sendCreated(
      RoutingContext ctx, String detail, T result, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.CREATED, detail, result, null, urnGenerator);
  }

  public static <T> void sendCreatedPreservingNulls(
      RoutingContext ctx, String detail, T result, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.CREATED, detail, result, null, urnGenerator, true);
  }

  public static void sendCreated(RoutingContext ctx, String detail, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.CREATED, detail, null, null, urnGenerator);
  }

  // --- Other status shortcuts ---

  public static void sendNoContent(RoutingContext ctx, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.NO_CONTENT, null, null, null, urnGenerator);
  }

  public static void sendProcessing(RoutingContext ctx, String detail, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.PROCESSING, detail, null, null, urnGenerator);
  }

  public static void sendForbiddenNoAccess(RoutingContext ctx, String detail, URNGenerator urnGenerator) {

    send(ctx, HttpStatusCode.FORBIDDEN_NO_ACCESS, detail, null, null, urnGenerator);
  }

  public static <T> void sendForbiddenAccessPending(RoutingContext ctx, String detail, T result,
      URNGenerator urnGenerator) {

    send(ctx, HttpStatusCode.FORBIDDEN_ACCESS_PENDING, detail, result, null, urnGenerator);
  }

  public static <T> void sendForbiddenAccessRejected(RoutingContext ctx, String detail,
                                                     URNGenerator urnGenerator) {

    send(ctx,
        HttpStatusCode.FORBIDDEN_ACCESS_REJECTED, detail, null, null, urnGenerator);
  }

  // --- Error shortcuts ---

  public static void sendError(
      RoutingContext ctx, HttpStatusCode status, URNGenerator urnGenerator) {
    send(ctx, status, status.getDescription(), null, null, urnGenerator);
  }

  public static void sendError(
      RoutingContext ctx, HttpStatusCode status, String detail, URNGenerator urnGenerator) {
    send(ctx, status, detail, null, null, urnGenerator);
  }
}
