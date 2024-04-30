package com.example.injerecipe.dto.response;

import com.example.injerecipe.dto.request.ImageUploadRequest;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
public class ImageUploadResponse {
    private List<String> imageUrl;

    public static ImageUploadResponse from(List<String> imageUrls){
        return ImageUploadResponse.builder()
                .imageUrl(imageUrls)
                .build();
    }
}
