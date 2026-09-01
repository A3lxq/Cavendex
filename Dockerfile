# syntax=docker/dockerfile:1
#
# Multi-stage build: the `builder` stage installs the exact,
# hash-verified dependency closure from requirements.lock.txt (the same
# lock file `pip install --require-hashes` uses for production installs
# per DEPLOYMENT.md — this doesn't invent a second pinning mechanism),
# then the runtime stage copies just the installed site-packages and
# the cavendex package itself, so the final image doesn't carry pip's
# build cache or wheel artifacts.

FROM python:3.12-slim AS builder

WORKDIR /build

COPY requirements.lock.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock.txt

COPY . .
RUN pip install --no-cache-dir --no-deps .


FROM python:3.12-slim AS runtime

# git is only exercised by the opt-in `backup` compose service
# (vault_backup.py shells out to it) — installed unconditionally here
# since it's a tiny apt package and every other mode ignores it.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /usr/sbin/nologin cavendex

# `pip install .` in the builder stage already put every module
# (api.py, launcher.py, static/, agents/, etc.) inside site-packages —
# copying that plus the generated `cavendex` console-script entry point
# is the whole app; no separate copy of the source tree is needed
# (or read: the console-script wrapper never consults CWD for imports).
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/cavendex /usr/local/bin/cavendex

# Just a working directory for relative-path defaults
# (CAVENDEX_DATA_DIR, OBSIDIAN_VAULT_PATH, etc.) to resolve against and
# for docker-compose.yml's bind mounts to land in — not app code.
WORKDIR /app
RUN chown -R cavendex:cavendex /app
USER cavendex

EXPOSE 8000

ENTRYPOINT ["cavendex"]
CMD ["serve", "--host", "0.0.0.0"]
