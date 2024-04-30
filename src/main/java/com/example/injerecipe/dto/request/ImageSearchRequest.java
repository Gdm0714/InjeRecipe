package com.example.injerecipe.dto.request;

import lombok.Data;
import lombok.Getter;

import java.util.List;

@Getter
public class ImageSearchRequest {
    private List<String> name;
}
