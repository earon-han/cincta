FROM sha256:c7694a1b0afacbdb771ed4463a6b57c297abe204f862674757a2174e85d64be7
COPY cincta /src/build/cincta
USER tester
CMD ["sh", "scripts/test_all.sh", "docker"]
