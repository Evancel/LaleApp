# Build
FROM gradle:8.14-jdk21 AS build

# We’ll work in /home/gradle/app (Gradle user has home here)
USER root
RUN mkdir -p /home/gradle/app && chown -R gradle:gradle /home/gradle
USER gradle
WORKDIR /home/gradle/app

# Copy Gradle wrapper + root Gradle files (from project root = context)
COPY --chown=gradle:gradle gradle gradle
COPY --chown=gradle:gradle gradlew .
COPY --chown=gradle:gradle settings.gradle build.gradle ./

# Make wrapper usable (if repo checked out on Windows)
RUN chmod +x gradlew

# Copy only user-service module (not whole repo)
COPY --chown=gradle:gradle user-service/build.gradle user-service/
COPY --chown=gradle:gradle user-service/src user-service/src

# Build only user-service jar in the multi-module project
RUN ./gradlew --no-daemon :user-service:bootJar -x test

# Run
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Create non-root user
RUN addgroup -S app && adduser -S app -G app
USER app

# Copy the fat jar for user-service
COPY --from=build /home/gradle/app/user-service/build/libs/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
