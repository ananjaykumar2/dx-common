package org.cdpg.dx.database.elastic.model;

import static org.cdpg.dx.database.elastic.util.Constants.AFTER_RANGE;
import static org.cdpg.dx.database.elastic.util.Constants.AFTER_TEMPORAL;
import static org.cdpg.dx.database.elastic.util.Constants.BEFORE_RANGE;
import static org.cdpg.dx.database.elastic.util.Constants.BEFORE_TEMPORAL;
import static org.cdpg.dx.database.elastic.util.Constants.BETWEEN_RANGE;
import static org.cdpg.dx.database.elastic.util.Constants.BETWEEN_TEMPORAL;
import static org.cdpg.dx.database.elastic.util.Constants.CASE_INSENSITIVE;
import static org.cdpg.dx.database.elastic.util.Constants.DATA_UPLOAD_STATUS;
import static org.cdpg.dx.database.elastic.util.Constants.DESCRIPTION_ATTR;
import static org.cdpg.dx.database.elastic.util.Constants.FIELD;
import static org.cdpg.dx.database.elastic.util.Constants.FILE_FORMAT;
import static org.cdpg.dx.database.elastic.util.Constants.FLATTENED_TERM;
import static org.cdpg.dx.database.elastic.util.Constants.GREATER_THAN;
import static org.cdpg.dx.database.elastic.util.Constants.GREATER_THAN_EQUALS;
import static org.cdpg.dx.database.elastic.util.Constants.KEYWORD_KEY;
import static org.cdpg.dx.database.elastic.util.Constants.LESS_THAN;
import static org.cdpg.dx.database.elastic.util.Constants.LESS_THAN_EQUALS;
import static org.cdpg.dx.database.elastic.util.Constants.LOCATION;
import static org.cdpg.dx.database.elastic.util.Constants.TAGS;
import static org.cdpg.dx.database.elastic.util.Constants.TERM;
import static org.cdpg.dx.database.elastic.util.Constants.VALUE;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.common.exception.DxEsException;
import org.cdpg.dx.database.elastic.util.QueryType;

/**
 * Decorator that adds search criteria (term, range, wildcard, match) queries.
 * Supports field-type-aware query building for description, tags, fileFormat, etc.
 */
public class SearchCriteriaQueryDecorator implements ElasticsearchQueryDecorator {

  private static final Logger LOGGER = LogManager.getLogger(SearchCriteriaQueryDecorator.class);

  private final Map<FilterType, List<QueryModel>> queryMap;
  private final SearchCriteriaRequestDTO request;

  public SearchCriteriaQueryDecorator(
      Map<FilterType, List<QueryModel>> queryMap, SearchCriteriaRequestDTO request) {
    this.queryMap = queryMap;
    this.request = request;
  }

  @Override
  public Map<FilterType, List<QueryModel>> add() {
    if (request == null || request.getSearchCriteria() == null) {
      return queryMap;
    }
    List<SearchCriteriaDTO> criteria = request.getSearchCriteria();
    if (criteria.isEmpty()) {
      throw new DxEsException("Invalid Property Value: Empty searchCriteria");
    }

    List<QueryModel> mustList = new ArrayList<>();

    for (SearchCriteriaDTO criterion : criteria) {
      String field = criterion.getField();
      List<Object> values = criterion.getValues();
      String type = criterion.getSearchType() != null ? criterion.getSearchType() : TERM;
      LOGGER.info("Searchtype, field, values, cST {},{},{}", field, values, type);

      switch (type) {
        case TERM:
          mustList.add(buildTermQuery(field, values));
          break;
        case FLATTENED_TERM:
          mustList.add(buildFlattenedTermQuery(field, values));
          break;
        case BETWEEN_RANGE:
        case BETWEEN_TEMPORAL:
          if (values.size() != 2) {
            throw new DxEsException("Expected 2 values for between-type search");
          }
          mustList.add(
              buildRangeQuery(
                  field,
                  Map.of(
                      GREATER_THAN_EQUALS, values.get(0).toString(),
                      LESS_THAN_EQUALS, values.get(1).toString())));
          break;
        case BEFORE_RANGE:
        case BEFORE_TEMPORAL:
          mustList.add(buildRangeQuery(field, Map.of(LESS_THAN, values.get(0).toString())));
          break;
        case AFTER_RANGE:
        case AFTER_TEMPORAL:
          mustList.add(buildRangeQuery(field, Map.of(GREATER_THAN, values.get(0).toString())));
          break;
        default:
          throw new DxEsException("Unsupported searchType: " + type);
      }
    }

    queryMap
        .computeIfAbsent(FilterType.FILTER, k -> new ArrayList<>())
        .add(new QueryModel(QueryType.BOOL).setMustQueries(mustList));
    return queryMap;
  }

  private QueryModel buildTermQuery(String field, List<Object> values) {
    List<QueryModel> shouldQueries = new ArrayList<>();
    for (Object valueObj : values) {

      if (DATA_UPLOAD_STATUS.equals(field)) {
        shouldQueries.add(
            new QueryModel(QueryType.TERM)
                .setQueryParameters(Map.of(FIELD, field, VALUE, valueObj)));
        continue;
      }

      String value = valueObj.toString();
      if (DESCRIPTION_ATTR.equals(field) || field.startsWith(LOCATION)) {
        shouldQueries.add(
            new QueryModel(QueryType.MATCH).setQueryParameters(Map.of(FIELD, field, VALUE, value)));
      } else if (TAGS.equals(field)) {
        shouldQueries.add(
            new QueryModel(QueryType.MATCH_PHRASE)
                .setQueryParameters(Map.of(FIELD, field, VALUE, value)));
      } else if (FILE_FORMAT.equals(field)) {
        shouldQueries.add(
            new QueryModel(QueryType.WILDCARD)
                .setQueryParameters(
                    Map.of(
                        FIELD,
                        field + KEYWORD_KEY,
                        VALUE,
                        value.toLowerCase(),
                        CASE_INSENSITIVE,
                        true)));
      } else {
        String searchField = field.endsWith(KEYWORD_KEY) ? field : field + KEYWORD_KEY;
        shouldQueries.add(
            new QueryModel(QueryType.TERM)
                .setQueryParameters(Map.of(FIELD, searchField, VALUE, value)));
      }
    }
    QueryModel queryModel = new QueryModel(QueryType.BOOL);
    queryModel.setShouldQueries(shouldQueries);
    return queryModel;
  }

  private QueryModel buildFlattenedTermQuery(String field, List<Object> values) {
    List<QueryModel> shouldQueries = new ArrayList<>();
    for (Object v : values) {
      shouldQueries.add(
          new QueryModel(QueryType.TERM)
              .setQueryParameters(Map.of(FIELD, field, VALUE, v.toString())));
    }
    QueryModel queryModel = new QueryModel(QueryType.BOOL);
    queryModel.setShouldQueries(shouldQueries);
    return queryModel;
  }

  private QueryModel buildRangeQuery(String field, Map<String, String> operators) {
    Map<String, Object> rangeParams = new HashMap<>();
    rangeParams.put(FIELD, field);
    rangeParams.putAll(operators);
    return new QueryModel(QueryType.RANGE).setQueryParameters(rangeParams);
  }
}
