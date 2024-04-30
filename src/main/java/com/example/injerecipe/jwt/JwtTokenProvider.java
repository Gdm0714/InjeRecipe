package com.example.injerecipe.jwt;

import com.example.injerecipe.dto.TokenDto;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

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

    public String createToken(String userSpecification, String account) {

        //Claims claims = Jwts.claims();
        //claims.put("account", account);

        return Jwts.builder()
                .signWith(new SecretKeySpec(secretKey.getBytes(), SignatureAlgorithm.HS512.getJcaName()))   // HS512 알고리즘을 사용하여 secretKey를 이용해 서명
                .setSubject(userSpecification)  // JWT 토큰 제목
                .setIssuer(issuer)  // JWT 토큰 발급자
                .setIssuedAt(Timestamp.valueOf(LocalDateTime.now()))    // JWT 토큰 발급 시간
                .setExpiration(Date.from(Instant.now().plus(expirationHours, ChronoUnit.HOURS)))    // JWT 토큰 만료 시간
                //.setClaims(claims)
                .compact(); // JWT 토큰 생성
    }

    public String getAccount(String token){
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody().getSubject();
    }

    private static Claims extractClaims(String token, String secretKey) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
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
