# DAYPASS ZK prover sidecar as a container: brings its own Linux for the
# blst-java natives, so no WSL/Java-25 host setup is needed.
# Build and run from the repo root: docker compose up -d daypass-prover

FROM eclipse-temurin:25-jdk AS build
ARG GRADLE_VERSION=9.6.1
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL -o /tmp/gradle.zip "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
 && unzip -q /tmp/gradle.zip -d /opt && rm /tmp/gradle.zip
ENV PATH="/opt/gradle-${GRADLE_VERSION}/bin:${PATH}"
WORKDIR /src
COPY settings.gradle build.gradle ./
COPY src ./src
RUN gradle --no-daemon installDist

FROM eclipse-temurin:25-jre
RUN apt-get update && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/build/install/daypass-prover /opt/daypass-prover
# Dev trusted-setup cache baked in as fallback; compose mounts the repo's data/
# over it so the VK (and with it the verifier policyId) stays identical to
# local WSL runs. A fresh setup would silently change the policyId.
COPY data /app/data
EXPOSE 8799
HEALTHCHECK --interval=15s --timeout=5s --start-period=180s \
  CMD curl -fsS http://localhost:8799/health || exit 1
CMD ["/opt/daypass-prover/bin/daypass-prover"]
