# Constrained-IoT audit experiments. Extends the verified validation image; adds only libfaketime
# (to move a single process's clock, e.g. to 1970, without touching the container's or host's clock).
FROM pqgrid-validation
RUN apt-get update && apt-get install -y --no-install-recommends faketime \
    && rm -rf /var/lib/apt/lists/*
COPY . /audit
RUN chmod +x /audit/*.sh
WORKDIR /audit
