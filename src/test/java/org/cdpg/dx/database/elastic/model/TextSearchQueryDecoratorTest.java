package org.cdpg.dx.database.elastic.model;

import static org.assertj.core.api.Assertions.*;

import java.util.*;
import org.cdpg.dx.common.exception.DxEsException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("TextSearchQueryDecorator Tests")
class TextSearchQueryDecoratorTest {

  private Map<FilterType, List<QueryModel>> createEmptyQueryMap() {
    Map<FilterType, List<QueryModel>> map = new EnumMap<>(FilterType.class);
    for (FilterType ft : FilterType.values()) {
      map.put(ft, new ArrayList<>());
    }
    return map;
  }

  @Nested
  @DisplayName("add()")
  class AddTests {

    @Test
    @DisplayName("null request should return queryMap unchanged")
    void nullRequest() {
      Map<FilterType, List<QueryModel>> map = createEmptyQueryMap();
      Map<FilterType, List<QueryModel>> result =
          new TextSearchQueryDecorator(map, null).add();
      assertThat(result.get(FilterType.MUST)).isEmpty();
    }

    @Test
    @DisplayName("blank query should throw DxEsException")
    void blankQuery() {
      Map<FilterType, List<QueryModel>> map = createEmptyQueryMap();
      TextSearchRequestDTO dto = new TextSearchRequestDTO("  ", false, false, null);
      assertThatThrownBy(() -> new TextSearchQueryDecorator(map, dto).add())
          .isInstanceOf(DxEsException.class);
    }

    @Test
    @DisplayName("plain text should add MUST query")
    void plainText() {
      Map<FilterType, List<QueryModel>> map = createEmptyQueryMap();
      TextSearchRequestDTO dto = new TextSearchRequestDTO("water quality", false, false, null);
      Map<FilterType, List<QueryModel>> result =
          new TextSearchQueryDecorator(map, dto).add();
      assertThat(result.get(FilterType.MUST)).hasSize(1);
    }

    @Test
    @DisplayName("fuzzy should add MULTI_MATCH with fuzziness")
    void fuzzySearch() {
      Map<FilterType, List<QueryModel>> map = createEmptyQueryMap();
      TextSearchRequestDTO dto = new TextSearchRequestDTO("water", true, false, null);
      Map<FilterType, List<QueryModel>> result =
          new TextSearchQueryDecorator(map, dto).add();
      assertThat(result.get(FilterType.MUST)).hasSize(1);
    }

    @Test
    @DisplayName("autocomplete should add MULTI_MATCH with BoolPrefix")
    void autoComplete() {
      Map<FilterType, List<QueryModel>> map = createEmptyQueryMap();
      TextSearchRequestDTO dto = new TextSearchRequestDTO("wat", false, true, null);
      Map<FilterType, List<QueryModel>> result =
          new TextSearchQueryDecorator(map, dto).add();
      assertThat(result.get(FilterType.MUST)).hasSize(1);
    }
  }
}
