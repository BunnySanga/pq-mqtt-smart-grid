# Runs the pqgrid test suite on Linux with OpenSSL 3.5 (the validated design-validation image + pytest).
# Build from the project root:  docker build -f docker/pqgrid-tests.Dockerfile -t pqgrid-tests .
# Run:                          docker run --rm pqgrid-tests
FROM pqgrid-validation
RUN /opt/venv/bin/pip install --no-cache-dir -q pytest==9.1.1
WORKDIR /app
COPY pytest.ini /app/pytest.ini
COPY pqgrid /app/pqgrid
COPY tests /app/tests
CMD ["python", "-m", "pytest", "-rs"]
