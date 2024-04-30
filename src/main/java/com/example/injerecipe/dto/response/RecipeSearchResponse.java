package com.example.injerecipe.dto.response;

import com.example.injerecipe.entity.Recipe;
import com.example.injerecipe.entity.RecipeBoard;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;

import java.util.List;

@Getter
@Builder
public class RecipeSearchResponse {
    private String recipeSeq;

    private String recipeNm;

    private String recipeWay;

    private String recipePat;

    private String recipeEng;

    private String recipeFileS;

    private String recipePartsDtls;

    private List<String> recipeImages;

    private List<String> recipeManuals;

    private String errorMessage;

    public static RecipeSearchResponse from(Recipe recipe){

        return RecipeSearchResponse.builder()
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

    public static RecipeSearchResponse from(RecipeBoard recipe) {

        return RecipeSearchResponse.builder()
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
