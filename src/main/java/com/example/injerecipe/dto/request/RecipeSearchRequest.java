package com.example.injerecipe.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
public class RecipeSearchRequest {
    @Schema(description = "검색어 목록", example = "[\"된장찌개\", \"김치찌개\"]")
    List<String> keywords;
}

