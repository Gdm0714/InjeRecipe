package com.example.injerecipe.controller;

import com.example.injerecipe.dto.ApiResponse;
import com.example.injerecipe.dto.request.WeatherRequest;
import com.example.injerecipe.service.WeatherService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;

@Tag(name = "날씨 API")
@RestController
@RequestMapping("/weather")
@RequiredArgsConstructor
public class WeatherController {
    private final WeatherService weatherService;

    @Operation(summary = "위도 경도로 날씨 받아오기")
    @PostMapping("/get")
    public ApiResponse getWeather(@RequestBody WeatherRequest request){
        return ApiResponse.success(weatherService.getWeatherString(request.getLat(), request.getLon()));
    }
}
