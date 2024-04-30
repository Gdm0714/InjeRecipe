package com.example.injerecipe.controller;

import com.example.injerecipe.dto.request.ChatRequest;
import com.example.injerecipe.dto.request.PromptRequest;
import com.example.injerecipe.dto.response.ChatResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@Tag(name = "Chat Gpt API")
@RequestMapping("/openai")
@RestController
@RequiredArgsConstructor
public class ChatController {

    @Qualifier("openaiRestTemplate")
    private final RestTemplate restTemplate;

    @Value("${openai.model}")
    private String model;

    @Value("${openai.api.url}")
    private String apiUrl;

    @Operation(summary = "챗봇에게 질문하기")
    @PostMapping("/chat")
    public String chat(@RequestBody PromptRequest promptRequest) {
        ChatRequest request = new ChatRequest(model, promptRequest.getPrompt());
        ChatResponse response = restTemplate.postForObject(apiUrl, request, ChatResponse.class);
        if (response == null || response.getChoices() == null || response.getChoices().isEmpty()) {
            return "No response";
        }
        return response.getChoices().get(0).getMessage().getContent();
    }
}
