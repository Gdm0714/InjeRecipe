package com.example.injerecipe.controller;



import com.example.injerecipe.dto.ApiResponse;
import com.example.injerecipe.dto.request.MemberSignUpRequest;
import com.example.injerecipe.dto.request.SignInRequest;
import com.example.injerecipe.service.MemberService;

import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/member")
@RequiredArgsConstructor
public class MemberController {


    private final MemberService memberService;

    @Operation(summary = "회원 가입")
    @PostMapping("/signUp")
    public ApiResponse signUp(@RequestBody MemberSignUpRequest request) throws Exception {

        return ApiResponse.success(memberService.signUp(request));
    }

    @Operation(summary = "로그인")
    @PostMapping("/sign-in")
    public ApiResponse signIn(@RequestBody SignInRequest request) {
        return ApiResponse.success(memberService.signIn(request));

    }
}
