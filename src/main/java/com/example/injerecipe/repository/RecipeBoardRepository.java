package com.example.injerecipe.repository;

import com.example.injerecipe.entity.Recipe;
import com.example.injerecipe.entity.RecipeBoard;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface RecipeBoardRepository extends JpaRepository<RecipeBoard, Long> {

    @Query("SELECT r FROM RecipeBoard r WHERE LOWER(r.recipeNm) LIKE LOWER(CONCAT('%', :keyword, '%'))")
    List<RecipeBoard> findByRecipeNmContainingKeyword(@Param("keyword") String keyword);
    List<RecipeBoard> findAllByMemberId(Long id);

    List<RecipeBoard> findAllByOrderByLastModifiedAtDesc();
}
