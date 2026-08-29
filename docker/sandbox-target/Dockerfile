# Disposable target container for the Dark Web Risk Sandbox.
#
# Contains ONLY: a Python runtime, the simulator's sandbox package, and a
# synthetic workspace. No networking tools, no real data, no malware.
#
# Build from the repository root:
#   docker build -t dark-web-sandbox-target:latest -f docker/sandbox-target/Dockerfile .

FROM python:3.12-slim

# Unprivileged, fixed uid so the host can run the container with --user 10001:10001.
RUN groupadd --gid 10001 simuser \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin simuser

WORKDIR /opt/simulator

# Only the sandbox package is copied in -- the Flask app, its database and the
# marketplace content never enter the container.
COPY sandbox/ /opt/simulator/sandbox/

RUN mkdir -p /workspace && chown 10001:10001 /workspace

ENV PYTHONPATH=/opt/simulator \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001

# Seed the deterministic synthetic baseline, then idle. The container performs
# no autonomous activity; every action is driven by an explicit `docker exec`
# from the Flask scenario controller.
CMD ["sh", "-c", "python -m sandbox.tools.seed > /dev/null && exec sleep infinity"]
