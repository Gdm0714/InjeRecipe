package com.example.injerecipe.repository;


import com.example.injerecipe.dto.SocialType;
import com.example.injerecipe.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByEmail(String email);
    Optional<Member> findByAccount(String account);
    Optional<Member> findById(Long id);

    Optional<Member> findByNickname(String nickname);
    Optional<Member> findByRefreshToken(String refreshToken);
    Optional<Member> findBySocialTypeAndSocialId(SocialType socialType, String socialId);

}
