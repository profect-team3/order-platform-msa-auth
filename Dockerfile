FROM gradle:8.8-jdk17 AS builder
WORKDIR /workspace

COPY gradlew gradlew.bat settings.gradle ./
COPY gradle ./gradle
COPY order-platform-msa-auth ./order-platform-msa-auth
COPY order-platform-msa-auth/build.cloud.gradle ./order-platform-msa-auth/build.gradle

RUN ./gradlew :order-platform-msa-auth:build -x test

FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

COPY --from=builder /workspace/order-platform-msa-auth/build/libs/*.jar /app/application.jar

EXPOSE 8083
ENTRYPOINT ["java", "-Dspring.profiles.active=prod", "-jar", "/app/application.jar"]

