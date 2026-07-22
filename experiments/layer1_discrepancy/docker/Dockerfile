# Minimal image for the Layer 1 discrepancy diagnostic:
# python3 for the scripted agent, strace for L1 ground truth, nothing else.
FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends strace && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY container_agent_script.py /work/container_agent_script.py

# The container entrypoint runs strace -f -ttt around the agent script.
# stderr is where strace + agent MARK lines both go, so they interleave.
# stdout is reserved for the agent's own prints.
CMD ["/bin/sh", "-c", "strace -f -ttt -e 'trace=all' -o /work/l1.strace python3 /work/container_agent_script.py"]
