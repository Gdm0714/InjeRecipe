package com.example.injerecipe.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

public record RefrigeratorRequest (
        @Schema(description = "레시피 재료", example = "[\"파\", \"마늘\"]")
        List<String> ingredient
){
}
