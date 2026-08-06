FROM python:3.11-slim

# Build tools for the supervisor.
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc make libc6-dev libcjson-dev pkg-config \
      curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/supervisor
COPY supervisor/ /opt/supervisor/
RUN make clean && make

# Where envelopes and target agent code are mounted at run time.
RUN mkdir -p /work /work/envelopes /work/sessions /work/results

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV PATH=/opt/supervisor:$PATH
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
