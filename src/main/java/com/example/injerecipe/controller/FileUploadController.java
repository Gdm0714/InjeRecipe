package com.example.injerecipe.controller;

import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.example.injerecipe.dto.ApiResponse;
import com.example.injerecipe.dto.request.ImageSearchRequest;
import com.example.injerecipe.dto.request.ImageUploadRequest;
import com.example.injerecipe.dto.request.RecipeSearchRequest;
import com.example.injerecipe.service.ImageService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@Tag(name = "aws s3 API")
@RestController
@RequestMapping("/image")
@RequiredArgsConstructor
public class FileUploadController {

    private final ImageService imageService;

    @Operation(summary = "aws s3 파일 업로드")
    @PostMapping(name = "/upload", consumes = {MediaType.MULTIPART_FORM_DATA_VALUE, MediaType.APPLICATION_JSON_VALUE})
    public ApiResponse uploadFile(@ModelAttribute ImageUploadRequest request)throws IOException{
        return ApiResponse.success(imageService.registerImage(request));
    }



    @Operation(summary = "이미지 검색")
    @PostMapping("/search")
    public ApiResponse searchRecipe(@RequestBody ImageSearchRequest request) {
        return ApiResponse.success(imageService.searchImage(request));
    }
}
