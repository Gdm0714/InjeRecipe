package com.example.injerecipe.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class RecipeRequest {
    @Schema(description = "시작 페이지", example = "1")
    int start;
    @Schema(description = "마지막 페이지", example = "5")
    int end;
}
