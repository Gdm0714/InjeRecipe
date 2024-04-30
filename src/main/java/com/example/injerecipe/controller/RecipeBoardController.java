package com.example.injerecipe.controller;

import com.example.injerecipe.dto.ApiResponse;
import com.example.injerecipe.dto.request.RecipeBoardRequest;
import com.example.injerecipe.dto.request.RecipeSearchRequest;
import com.example.injerecipe.service.RecipeBoardService;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/board")
@RequiredArgsConstructor
public class RecipeBoardController {
    private final RecipeBoardService recipeBoardService;

    @Operation(summary = "레시피 업로드")
    @PostMapping(name = "/write", consumes = {MediaType.MULTIPART_FORM_DATA_VALUE, MediaType.APPLICATION_JSON_VALUE})
    public ApiResponse registerRecipe(@ModelAttribute RecipeBoardRequest request, @AuthenticationPrincipal User user) throws IOException {
        return ApiResponse.success(recipeBoardService.registerRecipe(request, new Long(user.getUsername())));
    }

    @Operation(summary = "레시피 다중 검색")
    @PostMapping("/search/recipes")
    public ApiResponse searchRecipes(@RequestBody RecipeSearchRequest request) {
        return ApiResponse.success(recipeBoardService.searchRecipes(request));
    }

    @Operation(summary = "레시피 단일 검색")
    @PostMapping("/search/recipe")
    public ApiResponse searchRecipe(@RequestBody RecipeSearchRequest request) {
        return ApiResponse.success(recipeBoardService.searchRecipe(request));
    }

    @Operation(summary = "멤버별 레시피 전체 조회")
    @PostMapping("/member/posts")
    public ApiResponse getMemberPosts(@AuthenticationPrincipal User user){
        return ApiResponse.success(recipeBoardService.getMemberPosts(new Long(user.getUsername())));
    }
    @Operation(summary = "작성된 전체 레시피 조회")
    @PostMapping("/posts")
    public ApiResponse getPosts(@AuthenticationPrincipal User user){
        return ApiResponse.success(recipeBoardService.getPosts());
    }
}
