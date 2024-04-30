package com.example.injerecipe.dto.request;


import com.example.injerecipe.dto.Role;
import com.example.injerecipe.dto.SocialType;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class MemberSignUpRequest {

    @Schema(description = "아이디", example = "test1234")
    private String account;

    @Schema(description = "비밀번호", example = "test1234")
    private String password;

    @Schema(description = "닉네임", example = "윈터")
    private String nickname;

    @Schema(description = "나이", example = "25")

    private int age;

    private Role role;

    private SocialType socialType;

    private String socialId;

    private String imageUrl;
}
