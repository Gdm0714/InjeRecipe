package com.example.injerecipe.service;

import com.example.injerecipe.dto.Role;
import com.example.injerecipe.dto.request.MemberSignUpRequest;
import com.example.injerecipe.dto.request.SignInRequest;
import com.example.injerecipe.dto.response.MemberSignUpResponse;
import com.example.injerecipe.dto.response.SignInResponse;
import com.example.injerecipe.entity.Member;
import com.example.injerecipe.jwt.JwtTokenProvider;
import com.example.injerecipe.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service // 스프링에서 이 클래스를 서비스로 인식하게 하는 어노테이션
@Transactional // 이 클래스의 메소드에서 발생하는 작업들이 하나의 트랜잭션으로 처리되게 하는 어노테이션
@RequiredArgsConstructor // final이나 @NonNull인 필드들만 파라미터로 받는 생성자를 생성하는 lombok 어노테이션
public class MemberService {

    private final MemberRepository memberRepository; // 회원 정보를 관리하는 레포지토리
    private final PasswordEncoder passwordEncoder; // 비밀번호를 암호화하는 데 사용하는 인코더
    private final JwtTokenProvider tokenProvider; // JWT 토큰을 생성하고 검증하는 데 사용하는 프로바이더

    // 회원 가입을 처리하는 메소드
    public MemberSignUpResponse signUp(MemberSignUpRequest request) throws Exception {

        if (memberRepository.findByEmail(request.getAccount()).isPresent()) { // 이메일로 회원을 찾음
            throw new Exception("이미 존재하는 계정입니다."); // 회원이 있으면 예외 발생
        }
        if (memberRepository.findByNickname(request.getNickname()).isPresent()) { // 닉네임으로 회원을 찾음
            throw new Exception("이미 존재하는 닉네임입니다."); // 회원이 있으면 예외 발생
        }

        Member member = Member.builder() // Member 객체를 생성
                .account(request.getAccount()) // 계정 정보 설정
                .password(request.getPassword()) // 비밀번호 정보 설정
                .nickname(request.getNickname()) // 닉네임 정보 설정
                .age(request.getAge()) // 나이 정보 설정
                .role(Role.USER) // 역할 정보 설정
                .build();

        member.passwordEncode(passwordEncoder); // 비밀번호를 암호화
        memberRepository.save(member); // 회원 정보를 저장
        return MemberSignUpResponse.from(member); // 회원 가입 응답을 반환
    }

    // 로그인을 처리하는 메소드
    @Transactional(readOnly = true)
    public SignInResponse signIn(SignInRequest request) {
        Member member = memberRepository.findByAccount(request.account()) // 계정으로 회원을 찾음
                .filter(it -> passwordEncoder.matches(request.password(), it.getPassword())) // 비밀번호가 일치하는지 확인
                .orElseThrow(() -> new IllegalArgumentException("아이디 또는 비밀번호가 일치하지 않습니다.")); // 회원이 없거나 비밀번호가 일치하지 않으면 예외 발생
        String token = tokenProvider.createToken(String.format("%s:%s", member.getId(), member.getRole()), member.getAccount()); // 토큰을 생성
        return new SignInResponse(member.getName(), member.getRole(), token); // 로그인 응답을 반환
    }
}

