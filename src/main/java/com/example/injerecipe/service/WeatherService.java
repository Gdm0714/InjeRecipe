package com.example.injerecipe.service;

import lombok.RequiredArgsConstructor;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;


@Service // 스프링에서 이 클래스를 서비스로 인식하게 하는 어노테이션
@Transactional // 이 클래스의 메소드에서 발생하는 작업들이 하나의 트랜잭션으로 처리되게 하는 어노테이션
@RequiredArgsConstructor // final이나 @NonNull인 필드들만 파라미터로 받는 생성자를 생성하는 lombok 어노테이션
public class WeatherService {

    @Value("${openweathermap.key}") // application.properties 파일에서 openweathermap.key 값을 가져와서 변수에 할당
    private String apiKey; // OpenWeatherMap API 키

    // 위도와 경도를 기반으로 날씨 정보를 가져오는 메소드
    public String getWeatherString(String lat, String lon){
        String apiUrl = "https://api.openweathermap.org/data/2.5/weather?lat=" + lat + "&lon=" + lon +"&appid=" + apiKey; // API URL을 생성
        try{
            URL url = new URL(apiUrl); // URL을 생성
            HttpURLConnection connection = (HttpURLConnection) url.openConnection(); // URL 연결을 생성
            connection.setRequestMethod("GET"); // 요청 방식을 GET으로 설정
            int responseCode = connection.getResponseCode(); // 응답 코드를 가져옴

            BufferedReader br;
            if(responseCode == 200){ // 응답 코드가 200인 경우
                br = new BufferedReader(new InputStreamReader(connection.getInputStream())); // 입력 스트림을 생성
            }else{ // 그 외의 경우
                br = new BufferedReader(new InputStreamReader(connection.getErrorStream())); // 에러 스트림을 생성
            }
            String inputLine;
            StringBuilder response = new StringBuilder();

            while((inputLine = br.readLine()) != null){ // 줄을 읽음
                response.append(inputLine); // 응답에 줄을 추가
            }
            br.close(); // 버퍼드 리더를 닫음
            return response.toString(); // 응답을 반환
        }catch (Exception e){
            return "fail"; // 예외가 발생하면 실패 메시지를 반환
        }
    }

    // 날씨 정보를 파싱하는 메소드
    public Map<String, Object> parseWeather(String jsonString){
        JSONParser jsonParser = new JSONParser(); // JSON 파서를 생성
        JSONObject jsonObject;

        try{
            jsonObject = (JSONObject) jsonParser.parse(jsonString); // JSON 문자열을 파싱
        }catch (ParseException e){
            throw new RuntimeException(e); // 파싱 중 예외가 발생하면 런타임 예외를 발생시킴
        }

        Map<String, Object> resultMap = new HashMap<>(); // 결과 맵을 생성
        JSONObject mainData = (JSONObject) jsonObject.get("weather"); // 날씨 데이터를 가져옴
        resultMap.put("temp", mainData.get("temp")); // 온도를 결과 맵에 추가
        System.out.println(mainData.get("main")); // 메인 날씨 정보를 출력
        resultMap.put("main", mainData.get("main")); // 메인 날씨 정보를 결과 맵에 추가
        resultMap.put("icon", mainData.get("icon")); // 아이콘을 결과 맵에 추가
        return resultMap; // 결과 맵을 반환
    }
}