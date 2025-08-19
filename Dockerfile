# Stage 1: Build
FROM gradle:8.8-jdk17 AS builder
WORKDIR /workspace

COPY gradlew gradlew.bat /workspace/
COPY gradle /workspace/gradle
COPY settings.gradle* build.gradle* gradle.properties* /workspace/
COPY . /workspace/

RUN chmod +x ./gradlew

RUN ./gradlew :order-platform-msa-auth:build -x test

FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

COPY --from=builder /workspace/order-platform-msa-auth/build/libs/*.jar /app/application.jar

EXPOSE 8083
ENTRYPOINT ["java", "-jar", "/app/application.jar"]
