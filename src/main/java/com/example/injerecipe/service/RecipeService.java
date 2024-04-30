package com.example.injerecipe.service;

import com.example.injerecipe.dto.request.RecipeSearchRequest;
import com.example.injerecipe.dto.response.RecipeSearchResponse;
import com.example.injerecipe.entity.Recipe;
import com.example.injerecipe.repository.RecipeRepository;
import lombok.RequiredArgsConstructor;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

@Service // 스프링에서 이 클래스를 서비스로 인식하게 하는 어노테이션
@Transactional // 이 클래스의 메소드에서 발생하는 작업들이 하나의 트랜잭션으로 처리되게 하는 어노테이션
@RequiredArgsConstructor // final이나 @NonNull인 필드들만 파라미터로 받는 생성자를 생성하는 lombok 어노테이션
public class RecipeService {

    @Value("${openApi.recipe.serviceKey}") // application.properties 파일에서 openApi.recipe.serviceKey 값을 가져와서 변수에 할당
    private String recipeServiceKey;

    @Value("${openApi.dataType}") // application.properties 파일에서 openApi.dataType 값을 가져와서 변수에 할당
    private String dataType;

    private final RecipeRepository recipeRepository; // 레시피 정보를 관리하는 레포지토리

    // 레시피를 검색하는 메소드
    public List<RecipeSearchResponse> searchRecipes(RecipeSearchRequest request) {
        List<RecipeSearchResponse> searchResponses = new ArrayList<>();
        List<String> keywords = request.getKeywords(); // 요청에서 키워드 리스트를 가져옴

        for (String keyword : keywords) { // 키워드 리스트를 순회
            if (keyword != null) {
                List<Recipe> recipes = recipeRepository.findByRecipeNmContainingKeyword(keyword); // 키워드가 포함된 레시피를 찾음
                System.out.println(recipes);
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
        List<Recipe> recipeList = recipeRepository.findByRecipeNmContainingKeyword(request.getKeywords().get(0)); // 키워드가 포함된 레시피를 찾음
        List<RecipeSearchResponse> searchResponses = new ArrayList<>();

        if(!recipeList.isEmpty()) {
            for (Recipe recipe : recipeList) { // 레시피 리스트를 순회
                searchResponses.add(RecipeSearchResponse.from(recipe)); // 레시피 정보를 응답 리스트에 추가
            }
        }else{
            searchResponses.add(RecipeSearchResponse.builder() // 레시피 검색 응답을 생성
                    .recipeNm(request.getKeywords().get(0))
                    .errorMessage("해당 레시피를 추가해주세요.") // 에러 메시지 설정
                    .build());
        }
        return searchResponses; // 응답 리스트를 반환
    }

    // 레시피를 가져오는 메소드
    public String getRecipe(int start, int end) throws ParseException {
        HttpURLConnection urlConnection = null;
        InputStream stream = null;
        String result = null;

        String urlStr = "http://openapi.foodsafetykorea.go.kr/api" +
                "/" + recipeServiceKey +
                "/COOKRCP01" +
                "/" + dataType +
                "/" + start +
                "/" + end;

        try {
            URL url = new URL(urlStr); // URL을 생성

            urlConnection = (HttpURLConnection) url.openConnection(); // URL 연결을 생성
            stream = getNetworkConnection(urlConnection); // 네트워크 연결을 가져옴
            result = readStreamToString(stream); // 스트림을 문자열로 변환

            if (stream != null) stream.close(); // 스트림을 닫음
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (urlConnection != null) {
                urlConnection.disconnect(); // URL 연결을 닫음
            }
        }
        JSONParser jsonParser = new JSONParser();
        Object obj = jsonParser.parse(result);
        JSONObject jsonObject = (JSONObject) jsonParser.parse(result);
        JSONObject jsonCook = (JSONObject) jsonObject.get("COOKRCP01");
        JSONArray jsonArray = (JSONArray) jsonCook.get("row");
        for(int i = 0; i<jsonArray.size(); i++) {
            JSONObject jsonRow = (JSONObject) jsonArray.get(i);
            recipeRepository.save(makeDto(jsonRow)); // 레시피 정보를 저장
        }
        return result; // 결과를 반환
    }

    // 네트워크 연결을 가져오는 메소드
    private InputStream getNetworkConnection(HttpURLConnection urlConnection) throws IOException {
        urlConnection.setConnectTimeout(3000); // 연결 타임아웃을 설정
        urlConnection.setReadTimeout(3000); // 읽기 타임아웃을 설정
        urlConnection.setRequestMethod("GET"); // 요청 방식을 GET으로 설정
        urlConnection.setDoInput(true); // 입력 가능하게 설정

        if (urlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("HTTP error code : " + urlConnection.getResponseCode()); // HTTP 에러 코드가 OK가 아니면 예외 발생
        }

        return urlConnection.getInputStream(); // 입력 스트림을 반환
    }

    // 스트림을 문자열로 변환하는 메소드
    private String readStreamToString(InputStream stream) throws IOException {
        StringBuilder result = new StringBuilder();

        BufferedReader br = new BufferedReader(new InputStreamReader(stream, "UTF-8")); // 버퍼드 리더를 생성

        String readLine;
        while ((readLine = br.readLine()) != null) { // 줄을 읽음
            result.append(readLine + "\n\r"); // 결과에 줄을 추가
        }

        br.close(); // 버퍼드 리더를 닫음

        return result.toString(); // 결과를 반환
    }

    // JSONObject를 Recipe로 변환하는 메소드
    private Recipe makeDto(JSONObject item) {
        Recipe.RecipeBuilder recipeBuilder = Recipe.builder() // Recipe 객체를 생성
                .recipeSeq(getString(item, "RCP_SEQ")) // 레시피 순서 설정
                .recipeNm(getString(item, "RCP_NM")) // 레시피 이름 설정
                .recipeWay(getString(item, "RCP_WAY2")) // 레시피 방법 설정
                .recipePat(getString(item, "RCP_PAT2")) // 레시피 패턴 설정
                .recipeEng(getString(item, "INFO_ENG")) // 레시피 영어 이름 설정
                .recipeFileS(getString(item, "ATT_FILE_NO_MAIN")) // 레시피 파일 설정
                .recipePartsDtls(getString(item, "RCP_PARTS_DTLS")); // 레시피 부품 세부 정보 설정

        List<String> recipeImages = new ArrayList<>();
        List<String> recipeManuals = new ArrayList<>();

        for (int i = 1; i <= 20; i++) {
            String imageKey = "MANUAL_IMG" + String.format("%02d", i);
            String manualKey = "MANUAL" + String.format("%02d", i);
            recipeImages.add(getString(item, imageKey)); // 레시피 이미지를 추가
            recipeManuals.add(getString(item, manualKey)); // 레시피 매뉴얼을 추가
        }

        recipeBuilder
                .recipeImages(recipeImages) // 레시피 이미지를 설정
                .recipeManuals(recipeManuals); // 레시피 매뉴얼을 설정

        return recipeBuilder.build(); // Recipe 객체를 생성하고 반환
    }

    // JSONObject에서 문자열을 가져오는 메소드
    private String getString(JSONObject item, String key) {
        return (String) item.get(key); // key에 해당하는 값을 가져옴
    }
}
