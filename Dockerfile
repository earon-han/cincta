ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE} AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential python3 ca-certificates file git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Copy public project inputs explicitly; local plans and unrelated files must
# not enter the image even if they are present in the build context.
COPY Makefile README.md LICENSE SECURITY.md AGENTS.md CHANGELOG.md .gitignore .dockerignore ./
COPY src/ ./src/
COPY include/ ./include/
COPY tests/ ./tests/
COPY scripts/ ./scripts/
COPY docs/ ./docs/
COPY examples/ ./examples/
COPY .github/ ./.github/
COPY reports/README.md reports/v02-summary.json ./reports/
RUN make BUILD=build STATIC=1 && mkdir -p /out && cp build/cincta /out/cincta

# Tests run with Docker's default seccomp/AppArmor profile and a non-root UID.
# Landlock availability still depends on the HOST kernel; Docker does not add it.
FROM build AS test
RUN useradd --create-home --uid 10001 tester && chown -R tester:tester /src
USER tester
CMD ["sh", "scripts/test_all.sh", "docker"]

FROM scratch AS binary
COPY --from=build /out/cincta /cincta
ENTRYPOINT ["/cincta"]
