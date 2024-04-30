package com.example.injerecipe.jwt;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
public class JwtTokenProvider {
    private final String secretKey;
    private final long expirationHours;
    private final String issuer;

    public JwtTokenProvider(
            @Value("${jwt.secretKey}") String secretKey,
            @Value("${jwt.expirationHours}") long expirationHours,
            @Value("${jwt.issuer}") String issuer
    ) {
        this.secretKey = secretKey;
        this.expirationHours = expirationHours;
        this.issuer = issuer;
    }

    public String createToken(String userSpecification) {

        //claims.put("account", account);

        return Jwts.builder()
                .signWith(new SecretKeySpec(secretKey.getBytes(), SignatureAlgorithm.HS512.getJcaName()))   // HS512 알고리즘을 사용하여 secretKey를 이용해 서명
                .setSubject(userSpecification)  // JWT 토큰 제목
                .setIssuer(issuer)  // JWT 토큰 발급자
                .setExpiration(Date.from(Instant.now().plus(expirationHours, ChronoUnit.HOURS)))    // JWT 토큰 만료 시간
                //.setClaims(claims)
                .compact(); // JWT 토큰 생성
    }


    public String validateTokenAndGetSubject(String token){
        return Jwts.parserBuilder()
                .setSigningKey(secretKey.getBytes())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}
