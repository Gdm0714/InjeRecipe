package com.example.injerecipe.controller;

import com.example.injerecipe.dto.ApiResponse;
import com.example.injerecipe.dto.request.MemberSignUpRequest;
import com.example.injerecipe.service.MemberService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;

@Tag(name = "OAuth API")
@RestController
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final MemberService memberService;

    @Operation(summary = "유저 정보")
    @GetMapping("/loginInfo")
    public String oauthLoginInfo(Authentication authentication){
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        Map<String, Object> attributes = oAuth2User.getAttributes();
        return attributes.toString();
    }

    @Operation(summary = "소셜 멤버 정보 저장")
    @PostMapping("/signUp")

    public String oauthSignUp(@RequestBody MemberSignUpRequest request)throws Exception {
        memberService.signUp(request);
        return "회원가입 성공 !";

    }

}
