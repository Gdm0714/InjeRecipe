package com.example.injerecipe.controller;

import com.example.injerecipe.dto.ApiResponse;
import com.example.injerecipe.dto.request.RefrigeratorRequest;
import com.example.injerecipe.service.RefrigeratorService;
import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/refrigerator")
@RequiredArgsConstructor
public class RefrigeratorController {
    private final RefrigeratorService refrigeratorService;

    @Operation(summary = "재료 등록")
    @PostMapping("/ingredient")
    public ApiResponse addIngredientToRefrigerator(@RequestBody RefrigeratorRequest refrigeratorRequest, @AuthenticationPrincipal User user) {
        return ApiResponse.success(refrigeratorService.addIngredientToRefrigerator(refrigeratorRequest, new Long(user.getUsername())));
    }

    @Operation(summary = "전체 재료 조회")
    @PostMapping("/ingredients")
    public ApiResponse getIngredients(@AuthenticationPrincipal User user) {
        return ApiResponse.success(refrigeratorService.getItem(new Long(user.getUsername())));
    }
}
