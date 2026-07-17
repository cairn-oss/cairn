# Cairn — local-first IaC auditor.
# Build:  docker build -t cairn .
# Run:    docker run --rm -v "$PWD:/scan:ro" cairn scan /scan
#
# Multi-stage: build wheels once, ship a slim non-root runtime.

FROM python:3.14-slim AS build
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.14-slim
LABEL org.opencontainers.image.title="Cairn" \
      org.opencontainers.image.description="Local-first IaC auditor fusing cost + security, with fixes." \
      org.opencontainers.image.source="https://github.com/cairn-oss/cairn" \
      org.opencontainers.image.licenses="MIT"

# Non-root by default: scanning must never need privileges.
RUN useradd --create-home --uid 10001 cairn
COPY --from=build /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

USER cairn
WORKDIR /scan
ENTRYPOINT ["cairn"]
CMD ["--help"]
