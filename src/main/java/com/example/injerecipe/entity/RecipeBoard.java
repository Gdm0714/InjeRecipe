package com.example.injerecipe.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
public class RecipeBoard extends BaseEntity{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "board_id")
    private Long id;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id", nullable = false)
    private Member member;

    private String recipeSeq;

    private String recipeNm;

    private String recipeWay;

    private String recipePat;

    private String recipeEng;

    private String recipeFileS;

    @Column(name = "recipePartsDtls", length = 2048)
    private String recipePartsDtls;

    @ElementCollection
    @CollectionTable(name = "recipe_board_images", joinColumns = @JoinColumn(name = "board_id"))
    @Column(name = "image_url")
    private List<String> recipeImages;

    @ElementCollection
    @CollectionTable(name = "recipe_board_manuals", joinColumns = @JoinColumn(name = "board_id"))
    @Column(name = "manual_text", length = 2048)
    private List<String> recipeManuals;


}
