FROM eclipse-temurin:17-jdk-jammy

WORKDIR /app

COPY target/api-gateway-*.jar api-gateway.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "api-gateway.jar"]