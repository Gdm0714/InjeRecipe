package com.example.injerecipe.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.List;

@Entity
@Getter
@Builder
@Table
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class Recipe {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "recipe_id")
    private Long id;

    private String recipeSeq;

    private String recipeNm;

    private String recipeWay;

    private String recipePat;

    private String recipeEng;

    private String recipeFileS;

    @Column(name = "recipePartsDtls", length = 2048)
    private String recipePartsDtls;

    @ElementCollection
    @CollectionTable(name = "recipe_images", joinColumns = @JoinColumn(name = "recipe_id"))
    @Column(name = "image_url")
    private List<String> recipeImages;

    @ElementCollection
    @CollectionTable(name = "recipe_manuals", joinColumns = @JoinColumn(name = "recipe_id"))
    @Column(name = "manual_text", length = 2048)
    private List<String> recipeManuals;
}
