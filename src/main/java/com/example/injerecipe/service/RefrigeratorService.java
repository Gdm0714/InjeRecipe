package com.example.injerecipe.service;

import com.example.injerecipe.common.SuccessResponse;
import com.example.injerecipe.dto.request.IngredientsRequest;
import com.example.injerecipe.dto.request.RefrigeratorRequest;
import com.example.injerecipe.dto.response.RefrigeratorResponse;
import com.example.injerecipe.entity.Member;
import com.example.injerecipe.entity.RefrigeratorItem;
import com.example.injerecipe.repository.MemberRepository;
import com.example.injerecipe.repository.RefrigeratorItemRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service // 스프링에서 이 클래스를 서비스로 인식하게 하는 어노테이션
@Transactional // 이 클래스의 메소드에서 발생하는 작업들이 하나의 트랜잭션으로 처리되게 하는 어노테이션
@RequiredArgsConstructor // final이나 @NonNull인 필드들만 파라미터로 받는 생성자를 생성하는 lombok 어노테이션
public class RefrigeratorService {

    private final RefrigeratorItemRepository refrigeratorItemRepository; // 냉장고 아이템 정보를 관리하는 레포지토리
    private final MemberRepository memberRepository; // 회원 정보를 관리하는 레포지토리

    private String notExist = "계정이 존재하지 않습니다."; // 계정이 존재하지 않을 때의 에러 메시지

    // 냉장고에 재료를 추가하는 메소드
    public SuccessResponse addIngredientToRefrigerator(RefrigeratorRequest refrigeratorRequest, Long id) {
        Member member = memberRepository.findById(id) // id로 회원을 찾음
                .orElseThrow(() -> new UsernameNotFoundException("해당 이메일이 존재하지 않습니다.")); // 회원이 없으면 예외 발생
        List<String> ingredients = refrigeratorRequest.ingredient(); // 요청에서 재료 리스트를 가져옴
        for(String ingredient: ingredients) { // 재료 리스트를 순회
            Optional<RefrigeratorItem> item = refrigeratorItemRepository.findByIngredient(ingredient); // 재료로 냉장고 아이템을 찾음
            refrigeratorItemRepository.save(RefrigeratorItem.from(member, ingredient)); // 냉장고 아이템을 저장
        }
        return SuccessResponse.of(HttpStatus.OK, "성공!"); // 성공 응답을 반환
    }

    // 회원의 냉장고 아이템을 가져오는 메소드
    public List<RefrigeratorResponse> getItem(Long id){
        Member member = memberRepository.findById(id) // id로 회원을 찾음
                .orElseThrow(() -> new UsernameNotFoundException("해당 이메일이 존재하지 않습니다.")); // 회원이 없으면 예외 발생
        List<RefrigeratorItem> itemList = refrigeratorItemRepository.findByMember(member); // 회원의 모든 냉장고 아이템을 가져옴
        List<RefrigeratorResponse> responseList = new ArrayList<>();
        for(RefrigeratorItem item : itemList){ // 냉장고 아이템 리스트를 순회
            responseList.add(RefrigeratorResponse.from(item)); // 냉장고 아이템 정보를 응답 리스트에 추가
        }
        return responseList; // 응답 리스트를 반환
    }
}
