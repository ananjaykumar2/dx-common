package org.cdpg.dx.apiserver;

import static org.cdpg.dx.common.config.CorsUtil.allowedOrigins;
import static org.cdpg.dx.common.config.HttpConstants.APPLICATION_JSON;
import static org.cdpg.dx.common.validations.util.Constants.CONTENT_TYPE;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Future;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.jackson.DatabindCodec;
import io.vertx.core.json.pointer.JsonPointer;
import io.vertx.core.net.JksOptions;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.AuthenticationHandler;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.CorsHandler;
import io.vertx.ext.web.handler.TimeoutHandler;
import io.vertx.ext.web.openapi.RouterBuilder;
import io.vertx.ext.web.openapi.RouterBuilderOptions;
import io.vertx.json.schema.SchemaParser;
import io.vertx.json.schema.SchemaRouter;
import io.vertx.serviceproxy.HelperUtils;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auth.appid.handler.AppIdAuthHandler;
import org.cdpg.dx.auth.authentication.client.JwksResolver;
import org.cdpg.dx.auth.authentication.handler.CombinedAuthHandler;
import org.cdpg.dx.auth.authentication.handler.MultiIssuerJwtAuthHandler;
import org.cdpg.dx.auth.authentication.handler.OptionalMultiIssuerJwtAuthHandler;
import org.cdpg.dx.common.FailureHandler;
import org.cdpg.dx.common.HttpStatusCode;
import org.cdpg.dx.common.URNGenerator;
import org.cdpg.dx.common.config.HttpConstants;
import org.cdpg.dx.common.util.BlockingExecutionUtil;
import org.cdpg.dx.common.util.SchemaBranchResolver;

/**
 * Abstract base class for OpenAPI-driven API server verticles.
 *
 * <p>Provides the complete HTTP server lifecycle:
 *
 * <ol>
 *   <li>Jackson ObjectMapper configuration
 *   <li>OpenAPI spec loading with placeholder replacement
 *   <li>JWT authentication handler setup via {@link JwksResolver}
 *   <li>Controller registration via {@link ApiController#register(RouterBuilder)}
 *   <li>CORS, security headers, failure handler, error handler configuration
 *   <li>Health endpoint ({@code /health/live})
 *   <li>SSL configuration
 *   <li>HTTP server startup
 * </ol>
 *
 * <p>Subclasses only need to provide project-specific configuration by overriding abstract methods.
 *
 * <h3>Minimal subclass example:</h3>
 *
 * <pre>{@code
 * public class MyApiServerVerticle extends AbstractApiServerVerticle {
 *   protected String getOpenApiSpecPath(JsonObject config) { return "docs/openapi.yaml"; }
 *   protected int getDefaultPort() { return 8443; }
 *   protected String getDefaultUrnPrefix() { return "urn:dx:myservice:"; }
 *   protected List<ApiController> createControllers(Vertx v, JsonObject c, URNGenerator u) {
 *     return ControllerFactory.createControllers(v, c, u);
 *   }
 * }
 * }</pre>
 */
public abstract class AbstractApiServerVerticle extends AbstractVerticle {
  private static final Logger LOGGER = LogManager.getLogger(AbstractApiServerVerticle.class);
  protected static final String ROUTE_STATIC_SPEC = "/apis/spec";
  protected static final String ROUTE_DOC = "/apis";
  protected URNGenerator urnGenerator;
  private HttpServer server;
  private Router router;
  protected JwksResolver jwksResolver;

  // =====================================================================
  // Abstract methods — subclasses MUST provide
  // =====================================================================
  /** Utility for building standardized error responses. */
  public static String errorResponse(HttpStatusCode code, URNGenerator urnGenerator) {
    String urn = urnGenerator.generateUrn(code.getPath());
    return new JsonObject()
        .put("type", urn)
        .put("title", code.getDescription())
        .put("detail", code.getDescription())
        .toString();
  }

  /** Path to the OpenAPI YAML spec file (e.g., "docs/openapi.yaml"). */
  protected abstract String getOpenApiSpecPath(JsonObject config);

  /** Default HTTP port (used if "httpPort" is not in config). */
  protected abstract int getDefaultPort();

  // =====================================================================
  // Optional overrides — sensible defaults provided
  // =====================================================================

  /** Default URN prefix (e.g., "urn:dx:controlPanel:"). */
  protected abstract String getDefaultUrnPrefix();

  /** Create and return all API controllers for this server. */
  protected abstract List<ApiController> createControllers(
      io.vertx.core.Vertx vertx, JsonObject config, URNGenerator urnGenerator);

  /** Config key for the base URL placeholder replacement. Default: "baseUrl". */
  protected String getBaseUrlConfigKey() {
    return "baseUrl";
  }

  /** Default support email for OpenAPI spec. Default: "support@cdpg.org.in". */
  protected String getDefaultSupportEmail() {
    return "support@cdpg.org.in";
  }

  /**
   * Supplier for internal JWKS key generation (for services that issue their own JWTs). Return null
   * to disable internal key generation.
   */
  protected Supplier<Future<JsonObject>> getJwksInternalProvider() {
    return null;
  }

  /**
   * Body size limit for requests. Default: {@link BodyHandler#DEFAULT_BODY_LIMIT}. Use -1 for
   * unlimited.
   */
  protected long getBodyLimit() {
    return BodyHandler.DEFAULT_BODY_LIMIT;
  }

  /** Default request timeout in milliseconds. Default: 100000 (100s). */
  protected long getDefaultTimeoutMs() {
    return 100000;
  }

  /**
   * Regex pattern for NGSI-LD paths that should use NGSI-LD error format. Return null to disable
   * NGSI-LD error formatting.
   */
  protected String getNgsildPathPattern() {
    return null;
  }

  /**
   * Returns true for routes that stream the request body directly (e.g. bulk ingestion). For these
   * routes the root handler pauses the request instead of buffering it, so streaming parsers can
   * consume the data without first loading the entire payload into memory.
   *
   * <p>Default: {@code false} — all routes are buffered. Override in subclasses to mark specific
   * paths as streaming (e.g. {@code path.contains("/ingestion/")}).
   */
  protected boolean isStreamingRoute(String path) {
    return false;
  }

  /**
   * Hook for registering additional routes on the router (e.g., health, documentation). Called
   * after all OpenAPI routes are registered.
   */
  protected void configureAdditionalRoutes(Router router, JsonObject config) {
    // Default: no-op. Subclasses override to add custom routes.
  }

  /**
   * Returns the {@link AppIdAuthHandler} for AppId/AppSecret Basic-auth authentication, or {@code
   * null} (default) if this service does not support AppId auth.
   *
   * <p>When non-null, the abstract class automatically:
   *
   * <ol>
   *   <li>Wraps it with {@link MultiIssuerJwtAuthHandler} in a {@link CombinedAuthHandler}
   *   <li>Registers that {@code CombinedAuthHandler} as both the {@code "authorization"} and {@code
   *       "appIdAuth"} OpenAPI security schemes
   * </ol>
   *
   * <p>Subclasses only need to construct and return the {@link AppIdAuthHandler} — no {@code
   * createMainAuthHandler()} override is needed.
   *
   * <p>Must be ready after {@link #createControllers} returns (i.e. the gRPC client and caches
   * created there must already be assigned to fields before this is called).
   */
  protected AppIdAuthHandler getAppIdAuthHandler() {
    return null;
  }

  // =====================================================================
  // Lifecycle — NOT overridable
  // =====================================================================

  /**
   * Returns the primary auth handler for the {@code "authorization"} security scheme when AppId
   * auth is NOT configured (i.e. {@link #getAppIdAuthHandler()} returns null). Default: JWT-only.
   * Override only for services that need a fully custom auth handler without AppId support.
   */
  protected AuthenticationHandler createMainAuthHandler(JwksResolver jwksResolver) {
    return new MultiIssuerJwtAuthHandler(jwksResolver);
  }

  /**
   * Optional auth dispatcher. Subclasses return a configured {@link
   * org.cdpg.dx.auth.authentication.handler.AuthenticationHandler} to enable the diagnostic route
   * Default: {@code null} — the diagnostic route is not mounted.
   */
  protected org.cdpg.dx.auth.authentication.handler.AuthenticationHandler getAuthV2Handler() {
    return null;
  }

  // =====================================================================
  // Shared private methods — identical across all DX API servers
  // =====================================================================

  @Override
  public void start() throws Exception {
    int port = config().getInteger("httpPort", getDefaultPort());
    JsonArray corsArray = config().getJsonArray("corsAllowedOrigin");
    if (corsArray == null) {
      throw new IllegalArgumentException(
          "Missing required configuration: 'corsAllowedOrigin' key must be defined in config");
    }
    allowedOrigins = corsArray.getList();
    String urnPrefix = config().getString("urnPrefix", getDefaultUrnPrefix());
    this.urnGenerator = new URNGenerator(urnPrefix);

    // Configure Jackson mappers
    configureJackson();

    // Read base URL from config
    String baseUrl = config().getString(getBaseUrlConfigKey(), "example.com");
    String supportEmail = config().getString("supportEmail", getDefaultSupportEmail());

    // Load and process OpenAPI spec
    String specPath = getOpenApiSpecPath(config());
    String yamlContent =
        vertx.fileSystem().readFileBlocking(specPath).toString(StandardCharsets.UTF_8);

    String updatedYaml =
        yamlContent.replace("${HOSTNAME}", baseUrl).replace("${SUPPORT_EMAIL}", supportEmail);

    Path tempFile = Files.createTempFile("openapi-", ".yaml");
    tempFile.toFile().deleteOnExit();
    vertx
        .fileSystem()
        .writeFileBlocking(tempFile.toAbsolutePath().toString(), Buffer.buffer(updatedYaml));

    Future<RouterBuilder> routerFuture =
        RouterBuilder.create(vertx, tempFile.toAbsolutePath().toString());

    // Init shared worker executor
    BlockingExecutionUtil.initialize(vertx);

    // Create JWKS resolver before controllers so subclasses can use it in createControllers()
    jwksResolver =
        new JwksResolver(vertx, config().getJsonObject("issuers"), getJwksInternalProvider());

    // Create controllers
    List<ApiController> controllers = createControllers(vertx, config(), this.urnGenerator);

    routerFuture
        .onSuccess(
            routerBuilder -> {
              try {

                // Auth handlers — auto-wire CombinedAuthHandler when AppId is configured
                MultiIssuerJwtAuthHandler jwtHandler = new MultiIssuerJwtAuthHandler(jwksResolver);
                OptionalMultiIssuerJwtAuthHandler optionalAuthHandler =
                    new OptionalMultiIssuerJwtAuthHandler(jwksResolver);

                AppIdAuthHandler appIdAuthHandler = getAppIdAuthHandler();
                org.cdpg.dx.auth.authentication.handler.AuthenticationHandler authV2 =
                    getAuthV2Handler();

                AuthenticationHandler mainAuthHandler;
                if (authV2 != null) {
                  mainAuthHandler = authV2;
                  LOGGER.debug("Using AuthenticationHandler for authorization scheme");
                } else if (appIdAuthHandler != null) {
                  mainAuthHandler = new CombinedAuthHandler(appIdAuthHandler, jwtHandler);
                  LOGGER.debug(
                      "AppId auth enabled — using CombinedAuthHandler for authorization + appIdAuth");
                } else {
                  mainAuthHandler = createMainAuthHandler(jwksResolver);
                }

                LOGGER.debug("Adding platform handlers...");
                long timeout = config().getLong("timeout", getDefaultTimeoutMs());
                routerBuilder.rootHandler(TimeoutHandler.create(timeout, 408));

                BodyHandler jsonBodyHandler = BodyHandler.create().setHandleFileUploads(false);
                configureRootHandlerBuilder(routerBuilder, jsonBodyHandler);

                LOGGER.debug("Registering controllers...");
                RouterBuilderOptions factoryOptions =
                    new RouterBuilderOptions().setMountResponseContentTypeHandler(true);
                routerBuilder.setOptions(factoryOptions);

                // OpenAPI security handlers
                routerBuilder.securityHandler("authorization", mainAuthHandler);
                routerBuilder.securityHandler("optionalAuth", optionalAuthHandler);
                if (authV2 != null) {
                  // AuthenticationHandler handles both JWT and Basic (AppId) auth
                  routerBuilder.securityHandler("appIdAuth", authV2);
                } else if (appIdAuthHandler != null) {
                  routerBuilder.securityHandler("appIdAuth", mainAuthHandler);
                }

                controllers.forEach(controller -> controller.register(routerBuilder));

                LOGGER.debug("Creating router...");
                router = routerBuilder.createRouter();

                LOGGER.debug("Configuring CORS and error handlers...");
                configureCorsHandler(router);
                putCommonResponseHeaders(router);
                configureFailureHandler(router, routerBuilder);
                configureErrorHandlers(router);

                // Documentation routes
                router
                    .get(ROUTE_STATIC_SPEC)
                    .produces(APPLICATION_JSON)
                    .handler(ctx -> ctx.response().sendFile(tempFile.toAbsolutePath().toString()));

                router
                    .get(ROUTE_DOC)
                    .produces("text/html")
                    .handler(ctx -> ctx.response().sendFile("docs/apidoc.html"));

                // Health endpoint
                router
                    .get("/health/live")
                    .handler(
                        ctx ->
                            ctx.response()
                                .setStatusCode(200)
                                .putHeader(HttpHeaders.CONTENT_TYPE, "text/plain")
                                .end("Alive"));

                // Allow subclasses to add custom routes
                configureAdditionalRoutes(router, config());
                LOGGER.debug("Starting HTTP server...");
                HttpServerOptions serverOptions = new HttpServerOptions();
                configureSsl(serverOptions);

                server = vertx.createHttpServer(serverOptions);
                server
                    .requestHandler(router)
                    .listen(
                        port,
                        http -> {
                          if (http.succeeded()) {
                            printDeployedEndpoints(router);
                            LOGGER.info(
                                "{} deployed on port: {}", this.getClass().getSimpleName(), port);
                          } else {
                            LOGGER.error(
                                "HTTP server failed to start: {}",
                                http.cause().getMessage(),
                                http.cause());
                          }
                        });
              } catch (Exception e) {
                LOGGER.error(
                    "Error during router creation or server startup: {}", e.getMessage(), e);
              }
            })
        .onFailure(
            failure ->
                LOGGER.error(
                    "Failed to create RouterBuilder from OpenAPI spec: {}",
                    failure.getMessage(),
                    failure));
  }

  protected RouterBuilder configureRootHandlerBuilder(
      RouterBuilder routerBuilder, BodyHandler jsonBodyHandler) {

    routerBuilder.rootHandler(jsonBodyHandler::handle);

    return routerBuilder;
  }

  @Override
  public void stop() {
    if (server != null) {
      server.close();
    }
  }

  private void configureJackson() {
    ObjectMapper mapper = DatabindCodec.mapper();
    mapper.registerModule(new JavaTimeModule());
    mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
    DatabindCodec.mapper().setPropertyNamingStrategy(PropertyNamingStrategies.LOWER_CAMEL_CASE);

    ObjectMapper prettyMapper = mapper.copy();
    prettyMapper.enable(SerializationFeature.INDENT_OUTPUT);
    DatabindCodec.prettyMapper()
        .setPropertyNamingStrategy(PropertyNamingStrategies.LOWER_CAMEL_CASE);
  }

  private void configureCorsHandler(Router router) {
    CorsHandler corsHandler;
    if (allowedOrigins.contains("*")) {
      corsHandler = CorsHandler.create("*").allowCredentials(false);
    } else {
      corsHandler = CorsHandler.create();
      for (String origin : allowedOrigins) {
        corsHandler.addOrigin(origin);
      }
      corsHandler.allowCredentials(true);
    }

    corsHandler
        .allowedMethod(HttpMethod.GET)
        .allowedMethod(HttpMethod.POST)
        .allowedMethod(HttpMethod.OPTIONS)
        .allowedMethod(HttpMethod.PUT)
        .allowedMethod(HttpMethod.DELETE)
        .allowedMethod(HttpMethod.PATCH)
        .allowedHeader("Content-Type")
        .allowedHeader("Authorization")
        .allowedHeader("Origin");

    router.route().handler(corsHandler);
  }

  private void putCommonResponseHeaders(Router router) {
    router
        .route()
        .handler(
            ctx -> {
              ctx.response()
                  .putHeader("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
                  .putHeader("Pragma", "no-cache")
                  .putHeader("Expires", "0")
                  .putHeader("X-Content-Type-Options", "nosniff");
              ctx.next();
            });
  }

  private void configureErrorHandlers(Router router) {
    router.errorHandler(
        401,
        ctx -> {
          HttpServerResponse response = ctx.response();
          if (response.headWritten()) {
            try {
              response.reset();
            } catch (RuntimeException e) {
              LOGGER.error(
                  "Failed to reset response: {}", HelperUtils.convertStackTrace(e).encode());
            }
            return;
          }
          response
              .setStatusCode(401)
              .putHeader(CONTENT_TYPE, APPLICATION_JSON)
              .end("not implemented");
        });
  }

  /** Configures SSL from config. Override to customize SSL provider (e.g., KeyStoreOptions). */
  protected void configureSsl(HttpServerOptions serverOptions) {
    boolean isSsl = config().getBoolean("ssl", false);
    if (isSsl) {
      LOGGER.info("Info: Starting HTTPs server");
      String keystore = config().getString("keystore");
      String keystorePassword = config().getString("keystorePassword");
      serverOptions
          .setSsl(true)
          .setKeyCertOptions(new JksOptions().setPath(keystore).setPassword(keystorePassword));
    } else {
      LOGGER.info("Info: Starting HTTP server");
      serverOptions.setSsl(false);
    }
  }

  private void configureFailureHandler(Router router, RouterBuilder routerBuilder) {
    router
        .route()
        .failureHandler(
            new FailureHandler(
                this.urnGenerator, getNgsildPathPattern(), branchResolver(routerBuilder)));
  }

  /**
   * Lets the failure handler re-validate the branches of a failed {@code oneOf}, which is the only
   * way to report which field was wrong instead of just "no schema matches".
   *
   * <p>The branches of a bundled spec are refs to internal {@code urn:vertxschemas:} ids that only
   * this router's own {@code SchemaRouter} can resolve, so the capability has to come from here.
   * Resolution failures are swallowed: a missing branch costs detail in an error message, which is
   * never worth failing a request over.
   */
  private SchemaBranchResolver branchResolver(RouterBuilder routerBuilder) {
    SchemaRouter schemaRouter = routerBuilder.getSchemaRouter();
    SchemaParser schemaParser = routerBuilder.getSchemaParser();
    if (schemaRouter == null || schemaParser == null) {
      return null;
    }
    return (ref, scope) -> {
      try {
        return schemaRouter.resolveCachedSchema(
            JsonPointer.fromURI(URI.create(ref)), scope, schemaParser);
      } catch (RuntimeException unresolvable) {
        LOGGER.debug("Could not resolve schema branch {} for error detail", ref, unresolvable);
        return null;
      }
    };
  }

  private void printDeployedEndpoints(Router router) {
    for (Route route : router.getRoutes()) {
      if (route.getPath() != null) {
        LOGGER.info("Deployed endpoint [{}] {}", route.methods(), route.getPath());
      }
    }
  }
}
