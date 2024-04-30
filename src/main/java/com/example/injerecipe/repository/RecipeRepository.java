package com.example.injerecipe.repository;

import com.example.injerecipe.entity.Recipe;
import com.example.injerecipe.entity.RecipeBoard;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface RecipeRepository extends JpaRepository<Recipe, Long> {
    @Query("SELECT r FROM Recipe r WHERE LOWER(r.recipeNm) LIKE LOWER(CONCAT('%', :keyword, '%'))")
    List<Recipe> findByRecipeNmContainingKeyword(@Param("keyword") String keyword);

}
