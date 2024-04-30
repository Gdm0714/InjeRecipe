package com.example.injerecipe.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class WeatherRequest {
    String lat;
    String lon;
}
