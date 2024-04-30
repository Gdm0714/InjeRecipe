package com.example.injerecipe.service;

import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.*;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;


@Service // 스프링에서 이 클래스를 서비스로 인식하게 하는 어노테이션
@Transactional // 이 클래스의 메소드에서 발생하는 작업들이 하나의 트랜잭션으로 처리되게 하는 어노테이션
@RequiredArgsConstructor // final이나 @NonNull인 필드들만 파라미터로 받는 생성자를 생성하는 lombok 어노테이션
public class AmazonS3Service {

    private final AmazonS3 amazonS3; // Amazon S3 서비스를 사용하기 위한 객체

    @Value("${cloud.aws.s3.bucket}") // application.properties 파일에서 cloud.aws.s3.bucket 값을 가져와서 변수에 할당
    private String bucketName; // S3 버킷 이름

    // 이미지를 S3에 업로드하는 메소드
    public String uploadImage(MultipartFile image, String fileName) throws IOException {
        try (InputStream inputStream = image.getInputStream()) { // 이미지를 InputStream으로 변환
            ObjectMetadata metadata = new ObjectMetadata(); // 메타데이터 객체 생성
            metadata.setContentLength(image.getSize()); // 메타데이터에 이미지 크기 설정
            metadata.setContentType(image.getContentType()); // 메타데이터에 이미지 타입 설정

            PutObjectRequest putObjectRequest = new PutObjectRequest(bucketName, fileName, inputStream, metadata); // S3에 업로드할 객체 생성

            putObjectRequest.setCannedAcl(CannedAccessControlList.PublicRead); // 객체에 대한 public read 권한 설정

            amazonS3.putObject(putObjectRequest); // 객체를 S3에 업로드

            return amazonS3.getUrl(bucketName, fileName).toString(); // 업로드된 객체의 URL을 반환
        }
    }

    // 키워드가 포함된 이미지의 URL을 가져오는 메소드
    public String getImageUrlsWithKeyword(String keyword) {
        List<String> imageUrls = new ArrayList<>(); // 이미지 URL을 저장할 리스트
        String url = "";
        ListObjectsV2Request request = new ListObjectsV2Request()
                .withBucketName(bucketName)
                .withPrefix(""); // 모든 객체를 검색하려면 prefix를 비워둡니다.

        ListObjectsV2Result result;
        do {
            result = amazonS3.listObjectsV2(request); // S3 버킷에서 객체 리스트를 가져옴

            for (com.amazonaws.services.s3.model.S3ObjectSummary objectSummary : result.getObjectSummaries()) { // 객체 리스트를 순회
                String key = objectSummary.getKey(); // 객체의 키를 가져옴
                if (key.contains(keyword)) { // 키에 키워드가 포함되어 있으면
                    String imageUrl = amazonS3.getUrl(bucketName, key).toString(); // 객체의 URL을 가져옴
                    imageUrls.add(imageUrl); // URL을 리스트에 추가
                }
            }
            request.setContinuationToken(result.getNextContinuationToken()); // 다음 페이지의 토큰을 설정
        } while (result.isTruncated()); // 모든 페이지를 순회할 때까지 반복
        if(!imageUrls.isEmpty()) url = imageUrls.get(0); // 이미지 URL 리스트가 비어있지 않으면 첫 번째 URL을 반환
        else{
            return null; // 이미지 URL 리스트가 비어있으면 null을 반환
        }
        return url;
    }
}
