package org.cdpg.dx.database.elastic.model;

import java.util.List;

public record TextSearchOptionsDTO(List<TextFieldDTO> fields) {
}
