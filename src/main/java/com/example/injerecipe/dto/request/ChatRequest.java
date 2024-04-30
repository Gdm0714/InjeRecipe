package com.example.injerecipe.dto.request;

import com.example.injerecipe.dto.Message;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class ChatRequest {
    private String model;
    private List<Message> messages;
    private int n = 1;
    private double temperature;

    public ChatRequest(String model, String prompt){
        this.model = model;
        this.messages = new ArrayList<>();
        this.messages.add(new Message("user", prompt));
    }
}
