package com.example.injerecipe.dto.response;

import com.example.injerecipe.dto.Message;
import lombok.*;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ChatResponse {
    private List<Choice> choices;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Choice {
        private int index;
        private Message message;
    }
}
