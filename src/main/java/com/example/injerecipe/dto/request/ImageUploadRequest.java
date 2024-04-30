package com.example.injerecipe.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Data
public class ImageUploadRequest {
    private List<MultipartFile> image;
}
