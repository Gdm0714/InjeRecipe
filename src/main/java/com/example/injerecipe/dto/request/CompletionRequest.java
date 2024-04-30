package com.example.injerecipe.dto.request;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class CompletionRequest {
    private String model;

    private String prompt;

    private float temperature;

    @Builder
    CompletionRequest(String model, String prompt, float temperature){
        this.model = model;
        this.prompt = prompt;
        this.temperature = temperature;
    }

}
