package com.example.injerecipe.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.injerecipe.repository.MemberRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

@Service // 스프링에서 이 클래스를 서비스로 인식하게 하는 어노테이션
@RequiredArgsConstructor // final이나 @NonNull인 필드들만 파라미터로 받는 생성자를 생성하는 lombok 어노테이션
@Getter // 모든 필드에 대한 getter를 생성하는 lombok 어노테이션
@Slf4j // 로깅을 위한 Slf4j 로거를 생성하는 lombok 어노테이션
public class JwtService {

    @Value("${jwt.secretKey}") // application.properties 파일에서 jwt.secretKey 값을 가져와서 변수에 할당
    private String secretKey;

    @Value("${jwt.access.expiration}") // application.properties 파일에서 jwt.access.expiration 값을 가져와서 변수에 할당
    private Long accessTokenExpirationPeriod;

    @Value("${jwt.refresh.expiration}") // application.properties 파일에서 jwt.refresh.expiration 값을 가져와서 변수에 할당
    private Long refreshTokenExpirationPeriod;

    @Value("${jwt.access.header}") // application.properties 파일에서 jwt.access.header 값을 가져와서 변수에 할당
    private String accessHeader;

    @Value("${jwt.refresh.header}") // application.properties 파일에서 jwt.refresh.header 값을 가져와서 변수에 할당
    private String refreshHeader;

    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String EMAIL_CLAIM = "email";
    private static final String BEARER = "Bearer ";

    private final MemberRepository memberRepository; // 회원 정보를 관리하는 레포지토리

    // 액세스 토큰을 생성하는 메소드
    public String createAccessToken(String email) {
        Date now = new Date();
        return JWT.create()
                .withSubject(ACCESS_TOKEN_SUBJECT) // 토큰의 주제 설정
                .withExpiresAt(new Date(now.getTime() + accessTokenExpirationPeriod)) // 토큰의 만료 시간 설정
                .withClaim(EMAIL_CLAIM, email) // 토큰에 이메일 정보를 추가
                .sign(Algorithm.HMAC512(secretKey)); // 토큰에 서명
    }

    // 리프레시 토큰을 생성하는 메소드
    public String createRefreshToken() {
        Date now = new Date();
        return JWT.create()
                .withSubject(REFRESH_TOKEN_SUBJECT) // 토큰의 주제 설정
                .withExpiresAt(new Date(now.getTime() + refreshTokenExpirationPeriod)) // 토큰의 만료 시간 설정
                .sign(Algorithm.HMAC512(secretKey)); // 토큰에 서명
    }

    // 응답에 액세스 토큰을 추가하는 메소드
    public void sendAccessToken(HttpServletResponse response, String accessToken) {
        response.setStatus(HttpServletResponse.SC_OK); // 응답 상태를 OK로 설정
        response.setHeader(accessHeader, accessToken); // 응답 헤더에 액세스 토큰 추가
        log.info("재발급된 Access Token : {}", accessToken); // 로그에 액세스 토큰 정보 출력
    }

    // 응답에 액세스 토큰과 리프레시 토큰을 추가하는 메소드
    public void sendAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken) {
        response.setStatus(HttpServletResponse.SC_OK); // 응답 상태를 OK로 설정
        setAccessTokenHeader(response, accessToken); // 응답 헤더에 액세스 토큰 추가
        setRefreshTokenHeader(response, refreshToken); // 응답 헤더에 리프레시 토큰 추가
        log.info("Access Token, Refresh Token 헤더 설정 완료"); // 로그에 토큰 헤더 설정 완료 메시지 출력
    }

    // 요청에서 리프레시 토큰을 추출하는 메소드
    public Optional<String> extractRefreshToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(refreshHeader)) // 요청 헤더에서 리프레시 토큰을 가져옴
                .filter(refreshToken -> refreshToken.startsWith(BEARER)) // 토큰이 "Bearer "로 시작하는지 확인
                .map(refreshToken -> refreshToken.replace(BEARER, "")); // "Bearer "를 제거하고 토큰만 반환
    }

    // 요청에서 액세스 토큰을 추출하는 메소드
    public Optional<String> extractAccessToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(accessHeader)) // 요청 헤더에서 액세스 토큰을 가져옴
                .filter(refreshToken -> refreshToken.startsWith(BEARER)) // 토큰이 "Bearer "로 시작하는지 확인
                .map(refreshToken -> refreshToken.replace(BEARER, "")); // "Bearer "를 제거하고 토큰만 반환
    }

    // 액세스 토큰에서 이메일을 추출하는 메소드
    public Optional<String> extractEmail(String accessToken) {
        try {
            return Optional.ofNullable(JWT.require(Algorithm.HMAC512(secretKey)) // 토큰을 검증
                    .build()
                    .verify(accessToken)
                    .getClaim(EMAIL_CLAIM) // 이메일 정보를 가져옴
                    .asString());
        } catch (Exception e) {
            log.error("액세스 토큰이 유효하지 않습니다."); // 로그에 에러 메시지 출력
            return Optional.empty(); // 유효하지 않은 토큰인 경우 빈 Optional 반환
        }
    }

    // 응답에 액세스 토큰을 설정하는 메소드
    public void setAccessTokenHeader(HttpServletResponse response, String accessToken) {
        response.setHeader(accessHeader, accessToken); // 응답 헤더에 액세스 토큰 추가
    }

    // 응답에 리프레시 토큰을 설정하는 메소드
    public void setRefreshTokenHeader(HttpServletResponse response, String refreshToken) {
        response.setHeader(refreshHeader, refreshToken); // 응답 헤더에 리프레시 토큰 추가
    }

    // 회원의 리프레시 토큰을 업데이트하는 메소드
    public void updateRefreshToken(String email, String refreshToken) {
        memberRepository.findByEmail(email) // 이메일로 회원을 찾음
                .ifPresentOrElse(
                        member -> member.updateRefreshToken(refreshToken), // 회원이 있으면 리프레시 토큰 업데이트
                        () -> new Exception("일치하는 회원이 없습니다.") // 회원이 없으면 예외 발생
                );
    }

    // 토큰이 유효한지 검사하는 메소드
    public boolean isTokenValid(String token) {
        try {
            JWT.require(Algorithm.HMAC512(secretKey)).build().verify(token); // 토큰을 검증
            return true; // 유효한 토큰인 경우 true 반환
        } catch (Exception e) {
            log.error("유효하지 않은 토큰입니다. {}", e.getMessage()); // 로그에 에러 메시지 출력
            return false; // 유효하지 않은 토큰인 경우 false 반환
        }
    }
}
