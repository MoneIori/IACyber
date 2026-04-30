FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace

# Copia il parent POM e tutti i moduli necessari (context = root progetto)
COPY pom.xml ./pom.xml
COPY spring-services/gateway-service/pom.xml ./spring-services/gateway-service/pom.xml
COPY spring-services/gateway-service/src ./spring-services/gateway-service/src

# Build solo il modulo gateway, skippa gli altri
RUN --mount=type=cache,target=/root/.m2 \
    mvn -pl spring-services/gateway-service -am -DskipTests package

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
RUN addgroup -S iacyber && adduser -S iacyber -G iacyber
COPY --from=build /workspace/spring-services/gateway-service/target/*.jar app.jar
USER iacyber
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
