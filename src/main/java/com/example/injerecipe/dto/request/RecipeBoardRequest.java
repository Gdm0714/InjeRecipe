package com.example.injerecipe.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.Getter;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Data
public class RecipeBoardRequest {

    @Schema(description = "일련번호", example = "33")
    private String recipeSeq;

    @Schema(description = "레시피 이름", example = "된장찌개")
    private String recipeNm;

    @Schema(description = "조리 방법", example = "끓이기")
    private String recipeWay;

    @Schema(description = "음식 종류", example = "국&찌개")
    private String recipePat;

    @Schema(description = "칼로리", example = "197")
    private String recipeEng;

    @Schema(description = "이미지", example = "1")
    private MultipartFile recipeFileS;

    @Schema(description = "재료 정보", example = "두부 20g(2×2×2cm), 애느타리버섯 20g(4가닥), 감자 10g(4×3×1cm), 양파 10g(2×1cm), 대파 10g(5cm), 된장 5g(1작은술), 물 300ml(1½컵)")
    private String recipePartsDtls;

    private List<MultipartFile> recipeImages;
    private List<String> recipeManuals;
}
