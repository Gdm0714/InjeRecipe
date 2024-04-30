package com.example.injerecipe.service;

import com.example.injerecipe.dto.request.ImageSearchRequest;
import com.example.injerecipe.dto.request.ImageUploadRequest;
import com.example.injerecipe.dto.response.ImageUploadResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service // 스프링에서 이 클래스를 서비스로 인식하게 하는 어노테이션
@Transactional // 이 클래스의 메소드에서 발생하는 작업들이 하나의 트랜잭션으로 처리되게 하는 어노테이션
@RequiredArgsConstructor // final이나 @NonNull인 필드들만 파라미터로 받는 생성자를 생성하는 lombok 어노테이션
public class ImageService {
    private final AmazonS3Service amazonS3Service; // Amazon S3 서비스를 사용하기 위한 객체

    // 이미지를 등록하는 메소드
    public ImageUploadResponse registerImage(ImageUploadRequest request)throws IOException{
        List<MultipartFile> imageList = request.getImage(); // 요청에서 이미지 리스트를 가져옴
        List<String> imageUrls = new ArrayList<>(); // 이미지 URL을 저장할 리스트
        for(MultipartFile image: imageList) { // 이미지 리스트를 순회
            String imageUrl = uploadImagesToS3(image); // 이미지를 S3에 업로드하고 URL을 가져옴
            imageUrls.add(imageUrl); // URL을 리스트에 추가
        }
        return ImageUploadResponse.from(imageUrls); // 이미지 URL 리스트를 반환
    }

    // 이미지를 검색하는 메소드
    public List<String> searchImage(ImageSearchRequest request){
        List<String> nameList = request.getName(); // 요청에서 이름 리스트를 가져옴
        List<String> url = new ArrayList<>(); // URL을 저장할 리스트
        for(String name: nameList) { // 이름 리스트를 순회
            url.add(amazonS3Service.getImageUrlsWithKeyword(name)); // 이름에 해당하는 이미지의 URL을 가져옴
        }
        return url; // URL 리스트를 반환
    }

    // 이미지를 S3에 업로드하는 메소드
    private String uploadImagesToS3(MultipartFile image) throws IOException {
        String fileName = UUID.randomUUID().toString() + "_" + image.getOriginalFilename(); // 파일 이름을 생성
        String imageUrl = amazonS3Service.uploadImage(image, fileName); // 이미지를 S3에 업로드하고 URL을 가져옴

        return imageUrl; // URL을 반환
    }
}
