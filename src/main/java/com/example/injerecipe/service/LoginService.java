package com.example.injerecipe.service;

import com.example.injerecipe.entity.Member;
import com.example.injerecipe.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service // 스프링에서 이 클래스를 서비스로 인식하게 하는 어노테이션
@Transactional // 이 클래스의 메소드에서 발생하는 작업들이 하나의 트랜잭션으로 처리되게 하는 어노테이션
@RequiredArgsConstructor // final이나 @NonNull인 필드들만 파라미터로 받는 생성자를 생성하는 lombok 어노테이션
public class LoginService implements UserDetailsService { // UserDetailsService 인터페이스를 구현하는 로그인 서비스 클래스

    private final MemberRepository memberRepository; // 회원 정보를 관리하는 레포지토리

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException { // 사용자 이름(이메일)을 기반으로 사용자 정보를 로드하는 메소드
        Member member = memberRepository.findByEmail(email) // 이메일로 회원을 찾음
                .orElseThrow(() -> new UsernameNotFoundException("해당 이메일이 존재하지 않습니다.")); // 회원이 없으면 예외 발생

        return org.springframework.security.core.userdetails.User.builder() // UserDetails 객체를 생성
                .username(member.getEmail()) // 이메일을 사용자 이름으로 설정
                .password(member.getPassword()) // 비밀번호를 설정
                .roles(member.getRole().name()) // 역할을 설정
                .build(); // UserDetails 객체를 생성
    }
}
