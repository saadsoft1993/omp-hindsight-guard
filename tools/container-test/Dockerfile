# Runs the whole test suite on Ubuntu with Python 3.10 and 3.14 (bash, zsh and fish installed, so every hook
# variant is exercised). Build context is the repository root:
#   docker build -f tools/container-test/Dockerfile -t omp-hindsight-guard-test .
#   docker run --rm omp-hindsight-guard-test
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
	&& apt-get install -y --no-install-recommends bash zsh fish curl git ca-certificates perl shellcheck \
	&& rm -rf /var/lib/apt/lists/*
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh
RUN useradd --create-home tester
COPY --chown=tester . /src
USER tester
WORKDIR /src
RUN for v in 3.10 3.14; do \
		uv venv --python "$v" "/home/tester/py$v" \
		&& uv pip install --python "/home/tester/py$v/bin/python" -e '.[test]' ruff; \
	done
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["bash", "-c", "set -e; /home/tester/py3.14/bin/ruff check . && /home/tester/py3.14/bin/ruff format --check . && shellcheck -x src/omp_hindsight_guard/scripts/*.sh src/omp_hindsight_guard/hooks/*.bash src/omp_hindsight_guard/hooks/omp-shim.sh && for v in 3.10 3.14; do echo \"== python $v\"; \"/home/tester/py$v/bin/python\" -m pytest -q -p no:cacheprovider tests; done"]
