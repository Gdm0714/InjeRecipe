package com.example.injerecipe.dto.response;

import com.example.injerecipe.entity.RefrigeratorItem;
import io.swagger.v3.oas.annotations.media.Schema;

public record RefrigeratorResponse(
        @Schema(description = "회원 고유키", example = "c0a80121-7aeb-4b4b-8b7a-9b9b9b9b9b9b")
        Long id,
        @Schema(description = "레시피 재료", example = "파")
        String ingredient
)
{
        public static RefrigeratorResponse from(RefrigeratorItem item){
                return new RefrigeratorResponse(
                        item.getMember().getId(),
                        item.getIngredient()
                );
        }
}
