package com.example.injerecipe.dto.response;

import com.example.injerecipe.entity.Recipe;
import com.example.injerecipe.entity.RecipeBoard;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class RecipeBoardSearchResponse {
    private String userName;

    private String recipeSeq;

    private String recipeNm;

    private String recipeWay;

    private String recipePat;

    private String recipeEng;

    private String recipeFileS;

    private String recipePartsDtls;

    private List<String> recipeImages;
    private List<String> recipeManuals;

    public static RecipeBoardSearchResponse from(RecipeBoard recipe, String userName){
        return RecipeBoardSearchResponse.builder()
                .userName(userName)
                .recipeSeq(recipe.getRecipeSeq())
                .recipeNm(recipe.getRecipeNm())
                .recipeWay(recipe.getRecipeWay())
                .recipePat(recipe.getRecipePat())
                .recipeEng(recipe.getRecipeEng())
                .recipeFileS(recipe.getRecipeFileS())
                .recipePartsDtls(recipe.getRecipePartsDtls())
                .recipeImages(recipe.getRecipeImages())
                .recipeManuals(recipe.getRecipeManuals())
                .build();
    }
}
