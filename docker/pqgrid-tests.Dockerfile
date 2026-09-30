# Runs the pqgrid test suite on Linux with OpenSSL 3.5 (the validated design-validation image + pytest).
# Build from the project root:  docker build -f docker/pqgrid-tests.Dockerfile -t pqgrid-tests .
# Run:                          docker run --rm pqgrid-tests
# BASE is the CANONICAL environment (design-validation/Dockerfile, Debian trixie) unless stated otherwise. Where it
# cannot be built, docker/substitute-ubuntu.Dockerfile gives a SUBSTITUTE base (--build-arg BASE=...); results from
# it must be labelled SUBSTITUTE (IMPLEMENTATION-ROADMAP §15).
ARG BASE=pqgrid-validation
FROM ${BASE}
RUN /opt/venv/bin/pip install --no-cache-dir -q pytest==9.1.1
WORKDIR /app
COPY pytest.ini /app/pytest.ini
COPY pqgrid /app/pqgrid
COPY tests /app/tests
COPY tools /app/tools
CMD ["python", "-m", "pytest", "-rs"]
