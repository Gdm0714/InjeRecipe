package com.example.injerecipe.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class RefrigeratorItem {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "refrigerator_id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id")
    private Member member;

    private String ingredient;



    public static RefrigeratorItem from(Member member, String ingredient){
        return RefrigeratorItem.builder()
                .member(member)
                .ingredient(ingredient)
                .build();
    }

}
