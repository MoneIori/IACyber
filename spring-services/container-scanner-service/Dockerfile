FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace

COPY pom.xml ./pom.xml
COPY spring-services/container-scanner-service/pom.xml ./spring-services/container-scanner-service/pom.xml
COPY spring-services/container-scanner-service/src ./spring-services/container-scanner-service/src

RUN --mount=type=cache,target=/root/.m2 \
    mvn -pl spring-services/container-scanner-service -am -DskipTests package

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Installa Trivy, Grype, Kubescape — disponibili come CLI nel container
RUN apk add --no-cache curl bash && \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin && \
    curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

RUN addgroup -S iacyber && adduser -S iacyber -G iacyber
COPY --from=build /workspace/spring-services/container-scanner-service/target/*.jar app.jar

USER iacyber
EXPOSE 8083
ENTRYPOINT ["java", "-jar", "app.jar"]
