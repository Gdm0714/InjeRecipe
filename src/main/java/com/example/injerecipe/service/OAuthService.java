package com.example.injerecipe.service;

import com.example.injerecipe.dto.SocialType;
import com.example.injerecipe.oauth2.CustomOAuth2User;
import com.example.injerecipe.oauth2.OAuthAttributes;
import com.example.injerecipe.entity.Member;
import com.example.injerecipe.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.Map;

@Service // 스프링에서 이 클래스를 서비스로 인식하게 하는 어노테이션
@Transactional // 이 클래스의 메소드에서 발생하는 작업들이 하나의 트랜잭션으로 처리되게 하는 어노테이션
@RequiredArgsConstructor // final이나 @NonNull인 필드들만 파라미터로 받는 생성자를 생성하는 lombok 어노테이션
@Slf4j // 로깅을 위한 Slf4j 로거를 생성하는 lombok 어노테이션
public class OAuthService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> { // OAuth2UserService 인터페이스를 구현하는 OAuth 서비스 클래스

    private final MemberRepository memberRepository; // 회원 정보를 관리하는 레포지토리

    private static final String NAVER = "naver"; // 네이버 소셜 로그인을 나타내는 상수
    private static final String KAKAO = "kakao"; // 카카오 소셜 로그인을 나타내는 상수

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException { // OAuth2 로그인 요청을 처리하는 메소드
        log.info("CustomOAuth2UserService.loadUser() 실행 - OAuth2 로그인 요청 진입");

        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService(); // 기본 OAuth2UserService를 사용하여 OAuth2User를 로드
        OAuth2User oAuth2User = delegate.loadUser(userRequest); // OAuth2User를 로드

        String registrationId = userRequest.getClientRegistration().getRegistrationId(); // 클라이언트 등록 ID를 가져옴
        SocialType socialType = getSocialType(registrationId); // 소셜 타입을 가져옴
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName(); // 사용자 이름 속성 이름을 가져옴
        Map<String, Object> attributes = oAuth2User.getAttributes(); // OAuth2User의 속성을 가져옴

        OAuthAttributes extractAttributes = OAuthAttributes.of(socialType, userNameAttributeName, attributes); // OAuthAttributes를 생성

        Member createdUser = getUser(extractAttributes, socialType); // 사용자를 가져옴

        return new CustomOAuth2User( // CustomOAuth2User를 생성
                Collections.singleton(new SimpleGrantedAuthority(createdUser.getRole().getKey())), // 권한을 설정
                attributes, // 속성을 설정
                extractAttributes.getNameAttributeKey(), // 이름 속성 키를 설정
                createdUser.getEmail(), // 이메일을 설정
                createdUser.getRole() // 역할을 설정
        );
    }

    private SocialType getSocialType(String registrationId) { // 소셜 타입을 가져오는 메소드
        if(NAVER.equals(registrationId)) { // 네이버인 경우
            return SocialType.NAVER;
        }
        if(KAKAO.equals(registrationId)) { // 카카오인 경우
            return SocialType.KAKAO;
        }
        return SocialType.GOOGLE; // 그 외의 경우는 구글로 간주
    }

    private Member getUser(OAuthAttributes attributes, SocialType socialType) { // 사용자를 가져오는 메소드
        Member findUser = memberRepository.findBySocialTypeAndSocialId(socialType,
                attributes.getOauth2UserInfo().getId()).orElse(null); // 소셜 타입과 소셜 ID로 사용자를 찾음

        if(findUser == null) { // 사용자가 없는 경우
            return saveUser(attributes, socialType); // 사용자를 저장
        }
        return findUser; // 사용자를 반환
    }

    private Member saveUser(OAuthAttributes attributes, SocialType socialType) { // 사용자를 저장하는 메소드
        Member createdUser = attributes.toEntity(socialType, attributes.getOauth2UserInfo()); // Member 객체를 생성
        return memberRepository.save(createdUser); // 사용자를 저장하고 반환
    }

    public Member saverUser(Member member){ // 사용자를 저장하는 메소드
        return memberRepository.save(member); // 사용자를 저장하고 반환
    }
}
