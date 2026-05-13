package org.cdpg.dx.database.elastic.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.cdpg.dx.common.exception.DxEsException;
import org.cdpg.dx.database.elastic.util.QueryType;

/**
 * Decorator that adds text search (multi-match) queries to the bool query.
 * Supports plain text, fuzzy, and autocomplete modes.
 */
public class TextSearchQueryDecorator implements ElasticsearchQueryDecorator {

  private final Map<FilterType, List<QueryModel>> queryMap;
  private final TextSearchRequestDTO request;

  public TextSearchQueryDecorator(
      Map<FilterType, List<QueryModel>> queryMap, TextSearchRequestDTO request) {
    this.queryMap = queryMap;
    this.request = request;
  }

  @Override
  public Map<FilterType, List<QueryModel>> add() {
    if (request == null) {
      return queryMap;
    }
    if (request.q() == null || request.q().isBlank()) {
      throw new DxEsException("bad text query values");
    }
    String textAttr = request.q();
    boolean isFuzzy = Boolean.TRUE.equals(request.fuzzy());
    boolean isAutoComplete = Boolean.TRUE.equals(request.autoComplete());

    List<QueryModel> shouldQueries = new ArrayList<>();
    List<String> fields = buildFields(request);

    if (isFuzzy) {
      shouldQueries.add(
          new QueryModel(QueryType.MULTI_MATCH)
              .setQueryParameters(
                  Map.of(
                      "fields",
                      fields,
                      "query",
                      textAttr,
                      "fuzziness",
                      "AUTO",
                      "boost",
                      "1.0")));
    }

    if (isAutoComplete) {
      shouldQueries.add(
          new QueryModel(QueryType.MULTI_MATCH)
              .setQueryParameters(
                  Map.of(
                      "fields",
                      fields,
                      "query",
                      textAttr,
                      "type",
                      "BoolPrefix",
                      "boost",
                      "5.0")));
    }

    if (!isFuzzy && !isAutoComplete) {
      shouldQueries.add(
          new QueryModel(QueryType.MULTI_MATCH)
              .setQueryParameters(
                  Map.of(
                      "fields", fields,
                      "query", textAttr,
                      "boost", "3.0")));
    }

    QueryModel boolModel = new QueryModel(QueryType.BOOL);
    boolModel.setShouldQueries(shouldQueries);
    boolModel.setMinimumShouldMatch("1");

    queryMap.computeIfAbsent(FilterType.MUST, k -> new ArrayList<>()).add(boolModel);
    return queryMap;
  }

  private List<String> buildFields(TextSearchRequestDTO request) {
    if (request.options() != null && request.options().fields() != null) {
      return request.options().fields().stream()
          .map(f -> f.boost() != null ? f.name() + "^" + f.boost() : f.name())
          .toList();
    }
    //fallback to default
    return List.of("label", "tags", "description", "name^5");
  }

}
