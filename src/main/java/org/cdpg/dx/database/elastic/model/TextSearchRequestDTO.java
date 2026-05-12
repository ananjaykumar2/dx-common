package org.cdpg.dx.database.elastic.model;

/**
 * DTO for text search parameters.
 *
 * @param q the search query text
 * @param fuzzy whether to enable fuzzy matching
 * @param autoComplete whether to enable autocomplete matching
 */
public record TextSearchRequestDTO(String q, Boolean fuzzy, Boolean autoComplete,
                                   TextSearchOptionsDTO options) {
}
