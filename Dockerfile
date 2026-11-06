ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE} AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential python3 ca-certificates file \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN make STATIC=1 && mkdir -p /out && cp build/cincta /out/cincta

# Tests run with Docker's default seccomp/AppArmor profile and a non-root UID.
# Landlock availability still depends on the HOST kernel; Docker does not add it.
FROM build AS test
RUN useradd --create-home --uid 10001 tester && chown -R tester:tester /src
USER tester
CMD ["sh", "scripts/test_all.sh", "docker"]

FROM scratch AS binary
COPY --from=build /out/cincta /cincta
ENTRYPOINT ["/cincta"]
