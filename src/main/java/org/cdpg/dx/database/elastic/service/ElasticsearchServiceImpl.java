package org.cdpg.dx.database.elastic.service;

import static org.cdpg.dx.database.elastic.util.Constants.AGGREGATIONS;
import static org.cdpg.dx.database.elastic.util.Constants.AGGREGATION_LIST;
import static org.cdpg.dx.database.elastic.util.Constants.AGGREGATION_ONLY;
import static org.cdpg.dx.database.elastic.util.Constants.BUCKETS;
import static org.cdpg.dx.database.elastic.util.Constants.COUNT_AGGREGATION_ONLY;
import static org.cdpg.dx.database.elastic.util.Constants.DOC_COUNT;
import static org.cdpg.dx.database.elastic.util.Constants.DOC_IDS_ONLY;
import static org.cdpg.dx.database.elastic.util.Constants.ID;
import static org.cdpg.dx.database.elastic.util.Constants.KEY;
import static org.cdpg.dx.database.elastic.util.Constants.RESULTS;
import static org.cdpg.dx.database.elastic.util.Constants.SOURCE;
import static org.cdpg.dx.database.elastic.util.Constants.SOURCE_AND_ID;
import static org.cdpg.dx.database.elastic.util.Constants.SOURCE_AND_ID_GEOQUERY;
import static org.cdpg.dx.database.elastic.util.Constants.SOURCE_ONLY;
import static org.cdpg.dx.database.elastic.util.Constants.STRING_SIZE;
import static org.cdpg.dx.database.elastic.util.Constants.SUMMARY_KEY;
import static org.cdpg.dx.database.elastic.util.Constants.WORD_VECTOR_KEY;

import co.elastic.clients.elasticsearch.ElasticsearchAsyncClient;
import co.elastic.clients.elasticsearch._types.Refresh;
import co.elastic.clients.elasticsearch._types.Result;
import co.elastic.clients.elasticsearch._types.Script;
import co.elastic.clients.elasticsearch._types.SortOptions;
import co.elastic.clients.elasticsearch._types.aggregations.Aggregation;
import co.elastic.clients.elasticsearch._types.query_dsl.Query;
import co.elastic.clients.elasticsearch.core.BulkRequest;
import co.elastic.clients.elasticsearch.core.CountRequest;
import co.elastic.clients.elasticsearch.core.DeleteByQueryRequest;
import co.elastic.clients.elasticsearch.core.DeleteRequest;
import co.elastic.clients.elasticsearch.core.ExistsRequest;
import co.elastic.clients.elasticsearch.core.GetRequest;
import co.elastic.clients.elasticsearch.core.IndexRequest;
import co.elastic.clients.elasticsearch.core.SearchRequest;
import co.elastic.clients.elasticsearch.core.SearchResponse;
import co.elastic.clients.elasticsearch.core.UpdateByQueryRequest;
import co.elastic.clients.elasticsearch.core.UpdateRequest;
import co.elastic.clients.elasticsearch.core.bulk.BulkResponseItem;
import co.elastic.clients.elasticsearch.core.search.Hit;
import co.elastic.clients.elasticsearch.indices.CreateIndexRequest;
import co.elastic.clients.json.JsonData;
import co.elastic.clients.json.JsonpMapper;
import co.elastic.clients.json.JsonpMapperFeatures;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.json.EncodeException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.jackson.DatabindCodec;
import jakarta.json.stream.JsonGenerator;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.common.exception.DxBadRequestException;
import org.cdpg.dx.common.exception.DxConflictException;
import org.cdpg.dx.common.exception.DxInternalServerErrorException;
import org.cdpg.dx.common.exception.DxNotFoundException;
import org.cdpg.dx.database.elastic.ElasticClient;
import org.cdpg.dx.database.elastic.model.BulkScriptUpdate;
import org.cdpg.dx.database.elastic.model.BulkSyncResult;
import org.cdpg.dx.database.elastic.model.ElasticsearchResponse;
import org.cdpg.dx.database.elastic.model.ElasticsearchSearchResult;
import org.cdpg.dx.database.elastic.model.QueryModel;
import org.cdpg.dx.database.elastic.model.ScrollResult;
import org.elasticsearch.client.Request;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.RestClient;

public class ElasticsearchServiceImpl implements ElasticsearchService {
  private static final Logger LOGGER = LogManager.getLogger(ElasticsearchServiceImpl.class);

  static ElasticClient client;
  private static ElasticsearchAsyncClient asyncClient;
  private static volatile ObjectMapper nullPreservingMapper;

  public ElasticsearchServiceImpl(ElasticClient client) {
    ElasticsearchServiceImpl.client = client;
    asyncClient = client.getClient();
  }

  /**
   * {@link JsonObject#encode()} serializes via Vert.x's shared, process-wide {@link
   * DatabindCodec#mapper()}, which the API server configures with {@code NON_EMPTY} inclusion for
   * response bodies. Using that mapper here would silently drop explicit null values (e.g. {@code
   * "inactive_date": null}) before the document ever reaches Elasticsearch. This clones the shared
   * mapper (preserving date formatting/naming config) and overrides inclusion back to {@code
   * ALWAYS} so ES write payloads keep null values the caller explicitly sent.
   */
  private static ObjectMapper nullPreservingMapper() {
    ObjectMapper mapper = nullPreservingMapper;
    if (mapper == null) {
      synchronized (ElasticsearchServiceImpl.class) {
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

  private static String encodePreservingNulls(JsonObject json) {
    try {
      return nullPreservingMapper().writeValueAsString(json.getMap());
    } catch (Exception e) {
      throw new EncodeException("Failed to encode JSON object", e);
    }
  }

  @Override
  public Future<ElasticsearchSearchResult> search(
      String index, QueryModel queryModel, String options) {
    Promise<ElasticsearchSearchResult> promise = Promise.promise();
    Map<String, Aggregation> aggregations = new HashMap<>();
    if (queryModel.getAggregations() != null) {
      queryModel
          .getAggregations()
          .forEach(
              agg -> aggregations.put(agg.getAggregationName(), agg.toElasticsearchAggregations()));
    }
    SearchRequest.Builder requestBuilder = new SearchRequest.Builder().index(index);
    QueryModel queries = queryModel.getQueries();
    if (queries != null && queries.toElasticsearchQuery() != null) {
      requestBuilder.query(queries.toElasticsearchQuery());
    }
    if (!aggregations.isEmpty()) {
      requestBuilder.aggregations(aggregations);
    }
    int limit = parseSize(options, queryModel);
    requestBuilder.size(limit);
    if (queryModel.getOffset() != null) {
      requestBuilder.from(Integer.parseInt(queryModel.getOffset()));
    }
    if (queryModel.toSourceConfig() != null) {
      requestBuilder.source(queryModel.toSourceConfig());
    }
    if (queryModel.toSortOptions() != null) {
      LOGGER.debug("Sort options: {}", queryModel.toSortOptions());
      requestBuilder.sort(queryModel.toSortOptions());
    }
    SearchRequest request = requestBuilder.build();
    LOGGER.debug("Request: {}", request);
    asyncClient
        .search(request, ObjectNode.class)
        .whenComplete(
            (response, error) -> {
              if (error != null) {
                LOGGER.error("Search failed: {}", error.getMessage());
                promise.fail(new DxInternalServerErrorException(error.getMessage(), error));
                return;
              }
              try {
                List<ElasticsearchResponse> esResponses = new ArrayList<>();
                int totalHitsCount = 0;
                LOGGER.debug("Total :: {}", response.hits().hits().size());
                // 1. Handle hits if needed
                if (!options.startsWith(AGGREGATION_ONLY)) {
                  for (var hit : response.hits().hits()) {
                    String id = hit.id();
                    JsonObject source =
                        hit.source() != null
                            ? new JsonObject(hit.source().toString())
                            : new JsonObject();
                    JsonObject result = new JsonObject();
                    switch (options) {
                      case DOC_IDS_ONLY:
                        result.put(ID, id);
                        break;
                      case SOURCE_AND_ID:
                        result.put(ID, id).put(SOURCE, source);
                        break;
                      case SOURCE_AND_ID_GEOQUERY:
                        source.put("doc_id", id);
                        result.mergeIn(source);
                        break;
                      case SOURCE_ONLY:
                        source.remove(SUMMARY_KEY);
                        source.remove(WORD_VECTOR_KEY);
                        result = source;
                        break;
                      default:
                        result = source;
                        break;
                    }

                    esResponses.add(new ElasticsearchResponse(id, result));
                  }

                  totalHitsCount =
                      (int) (response.hits().total() != null ? response.hits().total().value() : 0);
                }

                // 2. Handle aggregations if needed
                JsonObject aggregationsJson = parseAggregations(response, options);

                promise.complete(
                    new ElasticsearchSearchResult(esResponses, totalHitsCount, aggregationsJson));
              } catch (Exception e) {
                LOGGER.error("Failed to parse search response", e);
                promise.fail(
                    new DxInternalServerErrorException("Failed to parse search result", e));
              }
            });

    return promise.future();
  }

  private int parseSize(String options, QueryModel model) {
    if (options.startsWith(AGGREGATION_ONLY)) {
      return 0;
    }
    try {
      return Optional.ofNullable(model.getLimit()).map(Integer::parseInt).orElse(STRING_SIZE);
    } catch (NumberFormatException e) {
      throw new DxBadRequestException("Invalid 'limit' format");
    }
  }

  private JsonObject parseAggregations(SearchResponse<ObjectNode> response, String options) {
    JsonObject aggResult = new JsonObject();
    JsonpMapper mapper =
        asyncClient._jsonpMapper().withAttribute(JsonpMapperFeatures.SERIALIZE_TYPED_KEYS, false);
    StringWriter writer = new StringWriter();
    try (JsonGenerator generator = mapper.jsonProvider().createGenerator(writer)) {
      mapper.serialize(response, generator);
    } catch (Exception e) {
      LOGGER.error("Error serializing aggregations: ", e);
      throw new DxInternalServerErrorException("Failed to process aggregations", e);
    }
    String result = writer.toString();

    // Parse the aggregations object from the serialized result
    JsonObject rawAggs = new JsonObject(result).getJsonObject(AGGREGATIONS);
    if (rawAggs == null) {
      return aggResult;
    }

    if (AGGREGATION_LIST.equals(options)) {
      for (String aggKey : rawAggs.fieldNames()) {
        JsonArray keys = new JsonArray();
        JsonObject agg = rawAggs.getJsonObject(aggKey);
        if (agg.containsKey(BUCKETS)) {
          JsonArray buckets = agg.getJsonArray(BUCKETS);
          for (int i = 0; i < buckets.size(); i++) {
            keys.add(buckets.getJsonObject(i).getString(KEY));
          }
        }
        aggResult.put(aggKey, keys);
      }
    } else if (COUNT_AGGREGATION_ONLY.equals(options)) {
      JsonObject resultsAgg = rawAggs.getJsonObject(RESULTS);

      if (resultsAgg != null && resultsAgg.containsKey(BUCKETS)) {
        JsonArray buckets = resultsAgg.getJsonArray(BUCKETS);
        for (int i = 0; i < buckets.size(); i++) {
          JsonObject bucket = buckets.getJsonObject(i);
          aggResult.put(bucket.getString(KEY), bucket.getInteger(DOC_COUNT));
        }
      }
    } else {
      aggResult.mergeIn(rawAggs);
    }

    return aggResult;
  }

  @Override
  public Future<Integer> count(String index, QueryModel queryModel) {
    // Convert QueryModel into Elasticsearch Query
    Query query =
        queryModel.getQueries() == null ? null : queryModel.getQueries().toElasticsearchQuery();
    LOGGER.debug("Count query {}", query);
    // Create a CountRequest.Builder for the count query
    CountRequest.Builder requestBuilder = new CountRequest.Builder().index(index);
    // Add query if present
    if (query != null) {
      requestBuilder.query(query);
    }

    CountRequest request = requestBuilder.build();
    LOGGER.debug("Final CountRequest: {}", request);

    // Execute the count query
    return executeCount(request);
  }

  private Future<Integer> executeCount(CountRequest request) {
    Promise<Integer> promise = Promise.promise();
    LOGGER.debug("REQUEST {}", request);
    asyncClient
        .count(request)
        .whenComplete(
            (response, error) -> {
              if (error != null) {
                // Log specific error type for better debugging
                LOGGER.error(
                    "Count operation failed. Error type: {}, Message: {}",
                    error.getClass().getSimpleName(),
                    error.getMessage());

                {
                  if (error.getMessage() != null && error.getMessage().contains("no such index")) {
                    promise.fail(new DxNotFoundException("Resources not Found - no such index"));
                  } else {
                    LOGGER.error("Elasticsearch cluster is unreachable");
                    promise.fail(
                        new DxInternalServerErrorException("Elasticsearch cluster is unreachable"));
                  }
                }
              } else {
                try {
                  LOGGER.debug("COUNT: {}", response);
                  Integer count = Math.toIntExact(response.count());
                  LOGGER.debug("Total document count: {}", count);
                  promise.complete(count);
                } catch (ArithmeticException e) {
                  LOGGER.error("Count value too large for Integer conversion");
                  promise.fail(
                      new DxBadRequestException("Count value too large for Integer conversion"));
                }
              }
            });

    return promise.future();
  }

  // Public API methods

  @Override
  public Future<Void> deleteByQuery(String index, QueryModel queryModel) {
    return validateIndex(index)
        .compose(v -> validateQueryModel(queryModel))
        .compose(v -> executeDeleteByQuery(index, queryModel));
  }

  @Override
  public Future<ElasticsearchResponse> getSingleDocument(String index, QueryModel queryModel) {
    return validateIndex(index).compose(v -> performSingleSearch(index, queryModel));
  }

  @Override
  public Future<ElasticsearchResponse> getDocumentById(String index, String id) {
    return validateIndex(index)
        .compose(v -> validateId(id))
        .compose(v -> executeGetById(index, id));
  }

  private Future<ElasticsearchResponse> executeGetById(String index, String id) {
    Promise<ElasticsearchResponse> promise = Promise.promise();
    GetRequest req = GetRequest.of(g -> g.index(index).id(id));
    asyncClient
        .get(req, ObjectNode.class)
        .whenComplete(
            (resp, err) -> {
              if (err != null) {
                promise.fail(new RuntimeException("Get by ID error", err));
              } else if (!resp.found()) {
                promise.complete(new ElasticsearchResponse());
              } else {
                JsonObject source =
                    resp.source() != null ? new JsonObject(resp.source().toString()) : new JsonObject();
                source.remove(SUMMARY_KEY);
                promise.complete(new ElasticsearchResponse(resp.id(), source));
              }
            });
    return promise.future();
  }

  @Override
  public Future<List<String>> createDocuments(String index, List<QueryModel> documentModels) {
    return validateIndex(index)
        .compose(v -> validateDocumentModels(documentModels))
        .compose(v -> executeBulkIndex(index, documentModels));
  }

  @Override
  public Future<List<String>> createDocumentsAutoId(String index, List<QueryModel> documentModels) {
    return validateIndex(index)
        .compose(v -> validateDocumentModels(documentModels))
        .compose(v -> executeBulkIndexAutoId(index, documentModels));
  }

  @Override
  public Future<Void> deleteDocument(String index, String id) {
    return validateIndex(index)
        .compose(v -> validateId(id))
        .compose(v -> executeDeleteDocument(index, id));
  }

  @Override
  public Future<Void> updateDocument(String index, String id, QueryModel queryModel) {
    LOGGER.debug("Update document with index: {}, id: {}, queryModel: {}", index, id, queryModel);
    return validateIndex(index)
        .compose(v -> validateId(id))
        .compose(v -> validateQueryModel(queryModel))
        .compose(v -> executeExistenceCheck(index, id))
        .compose(v -> executeUpdate(index, id, queryModel));
  }

  @Override
  public Future<Void> patchDocument(String index, String id, QueryModel queryModel) {
    LOGGER.debug("Update document with index: {}, id: {}, queryModel: {}", index, id, queryModel);
    return validateIndex(index)
        .compose(v -> validateId(id))
        .compose(v -> validateQueryModel(queryModel))
        .compose(v -> executeExistenceCheck(index, id))
        .compose(v -> executePatch(index, id, queryModel));
  }

  @Override
  public Future<Void> updateDocumentsByQuery(QueryModel queryModel, String index) {
    return validateIndex(index)
        .compose(v -> validateQueryModel(queryModel))
        .compose(v -> executeUpdateByQuery(index, queryModel));
  }

  @Override
  public Future<Void> createIndex(String index, JsonObject mappings) {
    Promise<Void> promise = Promise.promise();
    validateIndex(index)
        .onFailure(promise::fail)
        .onSuccess(
            v -> {
              LOGGER.debug("Creating index: {} with mappings: {}", index, mappings);
              try {
                // Build create index request directly. If it already exists, treat as success.
                CreateIndexRequest.Builder reqBuilder =
                    new CreateIndexRequest.Builder().index(index);
                try {
                  if (mappings != null && !mappings.isEmpty()) {
                    // Unwrap if the provided JSON already has a top-level "mappings" key
                    JsonObject typeMapping =
                        mappings.containsKey("mappings")
                                && mappings.getValue("mappings") instanceof JsonObject
                            ? mappings.getJsonObject("mappings")
                            : mappings;
                    String mappingsJson = typeMapping.encode();
                    reqBuilder.mappings(m -> m.withJson(new StringReader(mappingsJson)));
                  }
                } catch (Exception e) {
                  LOGGER.error("Failed to apply mappings JSON", e);
                  promise.fail(new DxBadRequestException("Invalid mappings JSON"));
                  return;
                }

                CreateIndexRequest createReq = reqBuilder.build();
                asyncClient
                    .indices()
                    .create(createReq)
                    .whenComplete(
                        (createResp, createErr) -> {
                          LOGGER.debug("RESPONSE {} ", createResp);
                          if (createErr != null) {
                            String message =
                                createErr.getMessage() != null ? createErr.getMessage() : "";
                            // If index already exists, consider it a no-op success
                            if (message.contains("resource_already_exists_exception")
                                || message.contains("index_already_exists_exception")
                                || message.contains("already exists")) {
                              LOGGER.debug("Index {} already exists ", index);
                              promise.fail(new DxConflictException("Index already exists"));
                              return;
                            }
                            LOGGER.error("Create index failed: {}", message, createErr);
                            promise.fail(
                                new DxInternalServerErrorException(
                                    "Create index failed", createErr));
                          } else if (!createResp.acknowledged()) {
                            LOGGER.error("Create index not acknowledged for index {}", index);
                            promise.fail(
                                new DxInternalServerErrorException(
                                    "Create index not acknowledged"));
                          } else {
                            LOGGER.debug("Index {} created", index);
                            promise.complete();
                          }
                        });
              } catch (Exception e) {
                promise.fail(
                    new DxInternalServerErrorException("Unexpected error creating index", e));
              }
            });
    return promise.future();
  }

  @Override
  public Future<BulkSyncResult> bulkUpdateById(String index, List<BulkScriptUpdate> updates) {
    return validateIndex(index).compose(v -> executeBulkUpdateById(index, updates));
  }

  private Future<BulkSyncResult> executeBulkUpdateById(
      String index, List<BulkScriptUpdate> updates) {
    Promise<BulkSyncResult> promise = Promise.promise();

    BulkRequest.Builder bulkBuilder = new BulkRequest.Builder();

    for (BulkScriptUpdate upd : updates) {
      Script script =
          Script.of(
              s ->
                  s.lang("painless")
                      .source(upd.getScriptSource())
                      .params(
                          upd.getScriptParams().getMap().entrySet().stream()
                              .collect(
                                  Collectors.toMap(
                                      Map.Entry::getKey, e -> JsonData.of(e.getValue())))));

      bulkBuilder.operations(
          op -> op.update(u -> u.index(index).id(upd.getId()).action(a -> a.script(script))));
    }

    BulkRequest request = bulkBuilder.refresh(Refresh.WaitFor).build();

    LOGGER.debug("Bulk update request: {}", request);

    asyncClient
        .bulk(request)
        .whenComplete(
            (resp, err) -> {
              if (err != null) {
                LOGGER.error("Bulk update failed", err);
                promise.fail(new DxInternalServerErrorException("Bulk update failed", err));
                return;
              }

              int success = 0;
              List<JsonObject> failures = new ArrayList<>();

              for (var item : resp.items()) {
                if (item.error() != null) {

                  // Missing docs are expected -- log & continue
                  LOGGER.warn(
                      "Bulk update failed for id {} : {}", item.id(), item.error().reason());

                  failures.add(
                      new JsonObject()
                          .put("id", item.id())
                          .put("reason", item.error().type())
                          .put("message", item.error().reason()));

                } else {
                  success++;
                }
              }

              // Fail ONLY if everything failed
              if (success == 0) {
                promise.fail(new DxInternalServerErrorException("All bulk updates failed"));
                return;
              }

              promise.complete(
                  new BulkSyncResult(updates.size(), success, failures.size(), failures));
            });

    return promise.future();
  }

  // Validation helpers

  private Future<Void> validateIndex(String index) {
    if (index == null || index.trim().isEmpty()) {
      String msg = "Index cannot be null or empty";
      LOGGER.error(msg);
      return Future.failedFuture(new IllegalArgumentException(msg));
    }
    return Future.succeededFuture();
  }

  private Future<Void> validateId(String id) {
    if (id == null || id.trim().isEmpty()) {
      String msg = "Document ID cannot be null or empty";
      LOGGER.error(msg);
      return Future.failedFuture(new IllegalArgumentException(msg));
    }
    return Future.succeededFuture();
  }

  private Future<Void> validateQueryModel(QueryModel model) {
    if (model == null) {
      String msg = "QueryModel cannot be null";
      LOGGER.error(msg);
      return Future.failedFuture(new IllegalArgumentException(msg));
    }
    return Future.succeededFuture();
  }

  private Future<Void> validateDocumentModels(List<QueryModel> models) {
    if (models == null || models.isEmpty()) {
      String msg = "DocumentModels list cannot be null or empty";
      LOGGER.error(msg);
      return Future.failedFuture(new IllegalArgumentException(msg));
    }
    return Future.succeededFuture();
  }

  // Execution logic

  private Future<Void> executeDeleteByQuery(String indices, QueryModel queryModel) {
    Promise<Void> promise = Promise.promise();
    DeleteByQueryRequest request =
        new DeleteByQueryRequest.Builder()
            .index(indices)
            .query(queryModel.toElasticsearchQuery())
            .build();
    LOGGER.debug("DeleteByQuery Request: {}", request);
    asyncClient
        .deleteByQuery(request)
        .whenComplete(
            (resp, err) -> {
              if (err != null) {
                LOGGER.error("deleteByQuery failed {}", err.getMessage());
                promise.fail(new RuntimeException("Failed to execute deleteByQuery", err));
              } else {
                LOGGER.info("Deleted {} documents", resp.deleted());
                promise.complete();
              }
            });
    return promise.future();
  }

  private Future<ElasticsearchResponse> performSingleSearch(String index, QueryModel model) {
    Promise<ElasticsearchResponse> promise = Promise.promise();
    SearchRequest.Builder builder =
        new SearchRequest.Builder()
            .index(index)
            .query(model.toElasticsearchQuery())
            .size(1)
            .from(0);
    asyncClient
        .search(builder.build(), ObjectNode.class)
        .whenComplete(
            (resp, err) -> {
              if (err != null) {
                promise.fail(new RuntimeException("Search error", err));
              } else if (resp.hits().total().value() == 0) {
                LOGGER.debug("No documents found ");
                promise.complete(new ElasticsearchResponse());
              } else {
                Hit<ObjectNode> hit = resp.hits().hits().getFirst();
                LOGGER.debug("Single document found with ID: {}", hit.id());
                JsonObject source =
                    hit.source() != null ? new JsonObject(hit.source().toString()) : new JsonObject();
                source.remove(SUMMARY_KEY);
                ElasticsearchResponse response = new ElasticsearchResponse(hit.id(), source);
                promise.complete(response);
              }
            });
    return promise.future();
  }

  private Future<List<String>> executeBulkIndex(String index, List<QueryModel> models) {
    Promise<List<String>> promise = Promise.promise();
    LOGGER.debug("Index {}", index);
    BulkRequest.Builder bulkBuilder = new BulkRequest.Builder();
    models.forEach(
        queryModel -> {
          JsonObject doc = queryModel.extractDocumentFromQueryModel();
          String rawJson = encodePreservingNulls(doc);
          JsonData jsonData = JsonData.fromJson(rawJson);

          bulkBuilder.operations(
              operation ->
                  operation.index(
                      docs -> docs.index(index).id(doc.getString("id")).document(jsonData)));
        });
    BulkRequest request = bulkBuilder.build();
    asyncClient
        .bulk(request)
        .whenComplete(
            (bulkResponse, error) -> {
              if (bulkResponse.errors()) {
                LOGGER.error("bulk index failed");
                promise.fail(new RuntimeException("Bulk index error"));
              } else {
                // LOGGER.debug("bulk Response {}", bulkResponse);
                List<String> ids =
                    bulkResponse.items().stream()
                        .map(BulkResponseItem::id)
                        .collect(Collectors.toList());
                // LOGGER.debug("ids: {}", ids);
                promise.complete(ids);
              }
            });
    return promise.future();
  }

  private Future<List<String>> executeBulkIndexAutoId(String index, List<QueryModel> models) {
    Promise<List<String>> promise = Promise.promise();
    LOGGER.debug("Index " + index);
    BulkRequest.Builder bulkBuilder = new BulkRequest.Builder();
    models.forEach(
        queryModel -> {
          JsonObject doc = queryModel.extractDocumentFromQueryModel();
          String rawJson = encodePreservingNulls(doc);
          JsonData jsonData = JsonData.fromJson(rawJson);

          bulkBuilder.operations(
              operation -> operation.index(docs -> docs.index(index).document(jsonData)));
        });
    BulkRequest request = bulkBuilder.build();
    asyncClient
        .bulk(request)
        .whenComplete(
            (bulkResponse, error) -> {
              if (bulkResponse.errors()) {
                LOGGER.error("bulk index failed");
                promise.fail(new RuntimeException("Bulk index error"));
              } else {
                // LOGGER.debug("bulk Response " + bulkResponse);
                List<String> ids =
                    bulkResponse.items().stream()
                        .map(BulkResponseItem::id)
                        .collect(Collectors.toList());
                // LOGGER.debug("ids: " + ids);
                promise.complete(ids);
              }
            });
    return promise.future();
  }

  private Future<Void> executeDeleteDocument(String index, String id) {
    LOGGER.debug("Deleting document with ID: {}", id);
    Promise<Void> promise = Promise.promise();
    DeleteRequest req = DeleteRequest.of(d -> d.index(index).id(id));
    asyncClient
        .delete(req)
        .whenComplete(
            (resp, err) -> {
              if (err != null) {
                LOGGER.error("delete failed", err);
                promise.fail(new RuntimeException("Delete error"));
              } else if (resp.result() == Result.NotFound) {
                LOGGER.warn("Document not found: {}", id);
                promise.fail(new RuntimeException("Document not found"));
              } else {
                promise.complete();
              }
            });
    return promise.future();
  }

  private Future<Void> executeExistenceCheck(String index, String id) {
    Promise<Void> promise = Promise.promise();
    ExistsRequest req = ExistsRequest.of(e -> e.index(index).id(id));
    asyncClient
        .exists(req)
        .whenComplete(
            (res, err) -> {
              if (err != null || !res.value()) {
                String msg = err != null ? "Existence check failed" : "Document not found";
                LOGGER.error(msg, err);
                promise.fail(new RuntimeException(msg, err));
              } else {
                LOGGER.debug("Document with ID: {} exists in index: {}", id, index);
                promise.complete();
              }
            });
    return promise.future();
  }

  private Future<Void> executeUpdate(String index, String id, QueryModel model) {
    Promise<Void> promise = Promise.promise();

    JsonObject doc = model.extractDocumentFromQueryModel();

    IndexRequest<JsonData> request =
        new IndexRequest.Builder<JsonData>()
            .index(index)
            .id(id)
            .document(JsonData.fromJson(encodePreservingNulls(doc)))
            .build();

    asyncClient
        .index(request)
        .whenComplete(
            (res, err) -> {
              if (err != null) {
                LOGGER.error("update failed {}", err.getMessage(), err);
                promise.fail(new RuntimeException("Update error", err));
              } else {
                promise.complete();
              }
            });
    return promise.future();
  }

  private Future<Void> executePatch(String index, String id, QueryModel model) {
    Promise<Void> promise = Promise.promise();
    Script script = model.toElasticsearchScript();

    UpdateRequest.Builder<String, JsonData> builder =
        new UpdateRequest.Builder<String, JsonData>().index(index).id(id).retryOnConflict(3);

    if (script != null) {
      builder.script(script);
    } else {
      JsonObject doc = model.extractDocumentFromQueryModel();
      builder.doc(JsonData.fromJson(encodePreservingNulls(doc)));
    }

    UpdateRequest<String, JsonData> request = builder.build();

    asyncClient
        .update(request, JsonObject.class)
        .whenComplete(
            (res, err) -> {
              if (err != null) {
                LOGGER.error("patch failed {}", err.getMessage(), err);
                promise.fail(new RuntimeException("Update error", err));
              } else {
                promise.complete();
              }
            });
    return promise.future();
  }

  private Future<Void> executeUpdateByQuery(String index, QueryModel model) {
    Promise<Void> promise = Promise.promise();
    UpdateByQueryRequest.Builder builder =
        new UpdateByQueryRequest.Builder().index(index).query(model.toElasticsearchQuery());

    Script script = model.toElasticsearchScript();
    if (script != null) {
      builder.script(script);
    }
    UpdateByQueryRequest request = builder.build();
    LOGGER.debug("UpdateByQuery Request: {}", request);
    asyncClient
        .updateByQuery(request)
        .whenComplete(
            (res, err) -> {
              if (err != null) {
                LOGGER.error("updateByQuery failed {}", err.getMessage());
                promise.fail(new RuntimeException("UpdateByQuery error", err));
              } else {
                LOGGER.info("Updated {} documents", res);
                promise.complete();
              }
            });
    return promise.future();
  }

  @Override
  public Future<ScrollResult> scrollSearch(
      String index, QueryModel queryModel, String scrollTimeout, String options) {
    Promise<ScrollResult> promise = Promise.promise();
    try {
      RestClient restClient = client.getLowLevelClient();

      JsonObject body = new JsonObject();

      // Use the QueryModel's built-in method to get the query
      if (queryModel != null && queryModel.getQueries() != null) {
        Query esQuery = queryModel.getQueries().toElasticsearchQuery();
        if (esQuery != null) {
          body.put("query", serializeQuery(esQuery));
        } else {
          body.put("query", new JsonObject().put("match_all", new JsonObject()));
        }
      } else {
        body.put("query", new JsonObject().put("match_all", new JsonObject()));
      }

      // Override the size for scroll operations to use a reasonable batch size
      int scrollBatchSize = 10000;
      body.put("size", scrollBatchSize);

      // Add sorting if available in queryModel
      if (queryModel != null
          && queryModel.getSortFields() != null
          && !queryModel.getSortFields().isEmpty()) {
        JsonArray sortArray = new JsonArray();
        queryModel
            .getSortFields()
            .forEach(
                (field, order) -> {
                  JsonObject sortObj = new JsonObject();
                  JsonObject fieldSort = new JsonObject().put("order", order.toLowerCase());
                  sortObj.put(field, fieldSort);
                  sortArray.add(sortObj);
                });
        body.put("sort", sortArray);
      }

      Request request = new Request("POST", "/" + index + "/_search?scroll=" + scrollTimeout);
      request.setJsonEntity(body.encode());

      LOGGER.debug(
          "REST scroll search for index: {} with scroll batch size: {}", index, scrollBatchSize);
      LOGGER.debug("Query being executed: {}", body.encodePrettily());

      Vertx vertx = Vertx.currentContext().owner();
      vertx.executeBlocking(
          fut -> {
            try {
              Response response = restClient.performRequest(request);
              String json =
                  new String(
                      response.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
              JsonObject resp = new JsonObject(json);

              String scrollId = resp.getString("_scroll_id");
              List<ElasticsearchResponse> results = parseHits(resp);
              fut.complete(new ScrollResult(results, scrollId));
            } catch (Exception e) {
              fut.fail(e);
            }
          },
          res -> {
            if (res.succeeded()) {
              ScrollResult result = (ScrollResult) res.result();
              LOGGER.debug("REST scroll search returned {} documents", result.getResults().size());
              promise.complete(result);
            } else {
              LOGGER.error("REST scroll search failed", res.cause());
              promise.fail(res.cause());
            }
          });
    } catch (Exception e) {
      LOGGER.error("Error in REST scroll search", e);
      promise.fail(e);
    }
    return promise.future();
  }

  @Override
  public Future<ScrollResult> continueScroll(String scrollId, String scrollTimeout) {
    Promise<ScrollResult> promise = Promise.promise();
    try {
      RestClient restClient = client.getLowLevelClient();

      // Simple scroll continuation query
      String scrollQuery =
          "{\"scroll\":\"" + scrollTimeout + "\",\"scroll_id\":\"" + scrollId + "\"}";

      Request request = new Request("POST", "/_search/scroll");
      request.setJsonEntity(scrollQuery);

      LOGGER.debug("Continuing scroll with ID: {}", scrollId);

      Vertx vertx = Vertx.currentContext().owner();
      vertx.executeBlocking(
          fut -> {
            try {
              Response response = restClient.performRequest(request);
              String json =
                  new String(
                      response.getEntity().getContent().readAllBytes(), StandardCharsets.UTF_8);
              JsonObject resp = new JsonObject(json);

              String newScrollId = resp.getString("_scroll_id");
              List<ElasticsearchResponse> results = parseHits(resp);
              fut.complete(new ScrollResult(results, newScrollId));
            } catch (Exception e) {
              fut.fail(e);
            }
          },
          res -> {
            if (res.succeeded()) {
              promise.complete((ScrollResult) res.result());
            } else {
              promise.fail(res.cause());
            }
          });
    } catch (Exception e) {
      promise.fail(e);
    }
    return promise.future();
  }

  private JsonObject serializeQuery(Query query) {
    if (query == null) {
      return new JsonObject().put("match_all", new JsonObject());
    }

    JsonpMapper mapper = asyncClient._jsonpMapper();
    StringWriter writer = new StringWriter();
    try (jakarta.json.stream.JsonGenerator generator =
        mapper.jsonProvider().createGenerator(writer)) {
      mapper.serialize(query, generator);
    } catch (Exception e) {
      LOGGER.warn("Failed to serialize query, using match_all", e);
      return new JsonObject().put("match_all", new JsonObject());
    }

    String queryJson = writer.toString();
    if (queryJson == null || queryJson.trim().isEmpty() || queryJson.equals("{}")) {
      return new JsonObject().put("match_all", new JsonObject());
    }

    return new JsonObject(queryJson);
  }

  // Helper to serialize SortOptions to JsonArray
  private JsonArray serializeSortOptions(List<SortOptions> sortOptions) {
    JsonArray arr = new JsonArray();
    JsonpMapper mapper = asyncClient._jsonpMapper();
    for (SortOptions so : sortOptions) {
      StringWriter writer = new StringWriter();
      try (jakarta.json.stream.JsonGenerator generator =
          mapper.jsonProvider().createGenerator(writer)) {
        mapper.serialize(so, generator);
      }
      arr.add(new JsonObject(writer.toString()));
    }
    return arr;
  }

  @Override
  public Future<Void> clearScroll(String scrollId) {
    Promise<Void> promise = Promise.promise();
    try {
      RestClient restClient = client.getLowLevelClient();
      JsonObject body = new JsonObject().put("scroll_id", scrollId);
      Request request = new Request("DELETE", "/_search/scroll");
      request.setJsonEntity(body.encode());
      Vertx vertx = Vertx.currentContext().owner();
      vertx.executeBlocking(
          fut -> {
            try {
              restClient.performRequest(request);
              fut.complete();
            } catch (Exception e) {
              fut.fail(e);
            }
          },
          res -> {
            if (res.succeeded()) promise.complete();
            else promise.fail(res.cause());
          });
    } catch (Exception e) {
      promise.fail(e);
    }
    return promise.future();
  }

  private List<ElasticsearchResponse> parseHits(JsonObject resp) {
    List<ElasticsearchResponse> results = new ArrayList<>();
    try {
      if (resp.containsKey("hits")) {
        JsonObject hitsObj = resp.getJsonObject("hits");
        if (hitsObj != null && hitsObj.containsKey("hits")) {
          JsonArray hitsArray = hitsObj.getJsonArray("hits");
          if (hitsArray != null) {
            for (Object hitObj : hitsArray) {
              if (hitObj instanceof JsonObject) {
                JsonObject hit = (JsonObject) hitObj;
                String id = hit.getString("_id", "");
                JsonObject source = hit.getJsonObject("_source");
                if (source == null) {
                  source = new JsonObject();
                }
                results.add(new ElasticsearchResponse(id, source));
              }
            }
          }
        }
      }
    } catch (Exception e) {
      LOGGER.error("Error parsing hits from Elasticsearch response", e);
    }
    return results;
  }
}
