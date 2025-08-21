FROM gradle:8.8-jdk17 AS builder
WORKDIR /workspace

COPY gradlew gradlew.bat settings.gradle build.cloud.gradle ./
COPY gradle ./gradle

COPY order-platform-msa-auth ./order-platform-msa-auth

RUN ./gradlew :order-platform-msa-auth:build -x test

FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

COPY --from=builder /workspace/order-platform-msa-auth/build/libs/*.jar /app/application.jar

EXPOSE 8083
ENTRYPOINT ["java", "-jar", "/app/application.jar"]
