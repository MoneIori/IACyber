FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace

COPY pom.xml ./pom.xml
COPY spring-services/ingestion-service/pom.xml ./spring-services/ingestion-service/pom.xml
COPY spring-services/ingestion-service/src ./spring-services/ingestion-service/src

RUN --mount=type=cache,target=/root/.m2 \
    mvn -pl spring-services/ingestion-service -am -DskipTests package

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
RUN addgroup -S iacyber && adduser -S iacyber -G iacyber
COPY --from=build /workspace/spring-services/ingestion-service/target/*.jar app.jar
USER iacyber
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "app.jar"]
