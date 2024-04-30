package com.example.injerecipe.service;

import com.example.injerecipe.dto.request.RecipeBoardRequest;
import com.example.injerecipe.dto.request.RecipeSearchRequest;
import com.example.injerecipe.dto.response.RecipeBoardSearchResponse;
import com.example.injerecipe.dto.response.RecipeSearchResponse;
import com.example.injerecipe.entity.Member;
import com.example.injerecipe.entity.RecipeBoard;
import com.example.injerecipe.repository.MemberRepository;
import com.example.injerecipe.repository.RecipeBoardRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service // 스프링에서 이 클래스를 서비스로 인식하게 하는 어노테이션
@Transactional // 이 클래스의 메소드에서 발생하는 작업들이 하나의 트랜잭션으로 처리되게 하는 어노테이션
@RequiredArgsConstructor // final이나 @NonNull인 필드들만 파라미터로 받는 생성자를 생성하는 lombok 어노테이션
public class RecipeBoardService {

    private final RecipeBoardRepository recipeBoardRepository; // 레시피 게시판 정보를 관리하는 레포지토리
    private final MemberRepository memberRepository; // 회원 정보를 관리하는 레포지토리
    private final AmazonS3Service amazonS3Service; // Amazon S3 서비스를 사용하기 위한 객체

    // 레시피를 등록하는 메소드
    public RecipeBoard registerRecipe(RecipeBoardRequest request, Long id) throws IOException {
        Member member = memberRepository.findById(id) // id로 회원을 찾음
                .orElseThrow(() -> new UsernameNotFoundException("해당 이메일이 존재하지 않습니다.")); // 회원이 없으면 예외 발생

        // 이미지 업로드 및 URL 생성
        List<String> recipeImageUrls = uploadImagesToS3(request.getRecipeImages()); // 이미지를 S3에 업로드하고 URL을 가져옴
        List<String> imageUrls = uploadImagesToS3(request.getRecipeImages()); // 이미지를 S3에 업로드하고 URL을 가져옴

        // 레시피 생성
        RecipeBoard.RecipeBoardBuilder recipeBoard = RecipeBoard.builder() // RecipeBoard 객체를 생성
                .recipeSeq(request.getRecipeSeq()) // 레시피 순서 설정
                .recipeNm(request.getRecipeNm()) // 레시피 이름 설정
                .recipeWay(request.getRecipeWay()) // 레시피 방법 설정
                .recipePat(request.getRecipePat()) // 레시피 패턴 설정
                .recipeEng(request.getRecipeEng()) // 레시피 영어 이름 설정
                .recipeFileS(imageUrls.get(0)) // 레시피 파일 설정
                .recipePartsDtls(request.getRecipePartsDtls()) // 레시피 부품 세부 정보 설정
                .recipeImages(recipeImageUrls) // 레시피 이미지 설정
                .recipeManuals(request.getRecipeManuals()) // 레시피 매뉴얼 설정
                .member(member); // 회원 설정

        return recipeBoardRepository.save(recipeBoard.build()); // 레시피 게시판 정보를 저장하고 반환
    }

    // 회원의 게시물을 가져오는 메소드
    public List<RecipeBoardSearchResponse> getMemberPosts(Long id){
        Member member = memberRepository.findById(id) // id로 회원을 찾음
                .orElseThrow(() -> new UsernameNotFoundException("해당 이메일이 존재하지 않습니다.")); // 회원이 없으면 예외 발생
        List<RecipeBoard> recipeBoardList = recipeBoardRepository.findAllByMemberId(id); // 회원의 모든 게시물을 가져옴
        List<RecipeBoardSearchResponse> responseList = new ArrayList<>();

        for (RecipeBoard board : recipeBoardList) { // 게시물 리스트를 순회
            responseList.add(RecipeBoardSearchResponse.from(board, member.getNickname())); // 게시물 정보를 응답 리스트에 추가
        }

        return responseList; // 응답 리스트를 반환
    }

    // 모든 게시물을 가져오는 메소드
    public List<RecipeBoardSearchResponse> getPosts() {

        List<RecipeBoard> boardList = recipeBoardRepository.findAllByOrderByLastModifiedAtDesc(); // 모든 게시물을 가져옴
        List<RecipeBoardSearchResponse> responseDtoList = new ArrayList<>();

        for (RecipeBoard board : boardList) { // 게시물 리스트를 순회
            Member member = memberRepository.findById(board.getMember().getId()) // 게시물의 회원을 찾음
                    .orElseThrow(() -> new UsernameNotFoundException("해당 이메일이 존재하지 않습니다.")); // 회원이 없으면 예외 발생
            responseDtoList.add(RecipeBoardSearchResponse.from(board, member.getNickname())); // 게시물 정보를 응답 리스트에 추가
        }

        return responseDtoList; // 응답 리스트를 반환
    }

    // 이미지를 S3에 업로드하는 메소드
    private List<String> uploadImagesToS3(List<MultipartFile> images) throws IOException {
        List<String> imageUrls = new ArrayList<>();

        for (MultipartFile image : images) { // 이미지 리스트를 순회
            String fileName = UUID.randomUUID().toString() + "_" + image.getOriginalFilename(); // 파일 이름을 생성
            String imageUrl = amazonS3Service.uploadImage(image, fileName); // 이미지를 S3에 업로드하고 URL을 가져옴
            imageUrls.add(imageUrl); // URL을 리스트에 추가
        }

        return imageUrls; // URL 리스트를 반환
    }

    // 레시피를 검색하는 메소드
    public List<RecipeSearchResponse> searchRecipes(RecipeSearchRequest request) {
        List<RecipeSearchResponse> searchResponses = new ArrayList<>();

        List<String> keywords = request.getKeywords(); // 키워드 리스트를 가져옴

        for (String keyword : keywords) { // 키워드 리스트를 순회
            if (keyword != null) {
                List<RecipeBoard> recipes = recipeBoardRepository.findByRecipeNmContainingKeyword(keyword); // 키워드가 포함된 레시피를 찾음
                if (!recipes.isEmpty()) {
                    searchResponses.add(RecipeSearchResponse.from(recipes.get(0))); // 레시피 정보를 응답 리스트에 추가
                } else {
                    searchResponses.add(RecipeSearchResponse.builder() // 레시피 검색 응답을 생성
                            .recipeNm(keyword)
                            .errorMessage("해당 레시피를 추가해주세요.") // 에러 메시지 설정
                            .build());
                }
            }
        }
        return searchResponses; // 응답 리스트를 반환
    }

    // 레시피를 검색하는 메소드
    public List<RecipeSearchResponse> searchRecipe(RecipeSearchRequest request) {
        List<RecipeBoard> recipeList = recipeBoardRepository.findByRecipeNmContainingKeyword(request.getKeywords().get(0)); // 키워드가 포함된 레시피를 찾음
        List<RecipeSearchResponse> searchResponses = new ArrayList<>();

        if(!searchResponses.isEmpty()) {
            for (RecipeBoard recipe : recipeList) { // 레시피 리스트를 순회
                searchResponses.add(RecipeSearchResponse.from(recipe)); // 레시피 정보를 응답 리스트에 추가
            }
        }
        else{
            searchResponses.add(RecipeSearchResponse.builder() // 레시피 검색 응답을 생성
                    .recipeNm(request.getKeywords().get(0))
                    .errorMessage("해당 레시피를 추가해주세요.") // 에러 메시지 설정
                    .build());
        }
        return searchResponses; // 응답 리스트를 반환
    }
}
