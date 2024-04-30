package com.example.injerecipe.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

@Getter
public class IngredientsRequest {

    @Schema(description = "아이디", example = "test1234")
    String account;

}
