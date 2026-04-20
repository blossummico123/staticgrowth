# ---------------------------------------------------------------------------
# AI Sentinel — Container Image (Full Scanning Stack)
# All 16+ open-source security tools pre-installed
# ---------------------------------------------------------------------------
FROM python:3.12-slim

WORKDIR /app

# ---------------------------------------------------------------------------
# 1. System dependencies + runtimes for non-Python scanners
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    wget \
    unzip \
    gnupg \
    ca-certificates \
    build-essential \
    libhdf5-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# -- Node.js 20 LTS (for Promptfoo) ----------------------------------------
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# -- Go 1.22 (for OSV-Scanner) ----------------------------------------------
ENV GOLANG_VERSION=1.22.5
RUN wget -q "https://go.dev/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz" \
    && tar -C /usr/local -xzf "go${GOLANG_VERSION}.linux-amd64.tar.gz" \
    && rm "go${GOLANG_VERSION}.linux-amd64.tar.gz"
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

# -- Rust (for pickle-fuzzer) -----------------------------------------------
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# ---------------------------------------------------------------------------
# 2. Install Python dependencies (all open-source scanning libraries)
# ---------------------------------------------------------------------------
COPY api/requirements.txt /app/api/requirements.txt
RUN pip install --no-cache-dir -r api/requirements.txt

# ---------------------------------------------------------------------------
# 3. Install non-Python CLI tools
# ---------------------------------------------------------------------------

# -- Promptfoo (npm) --------------------------------------------------------
RUN npm install -g promptfoo

# -- OSV-Scanner (Go) -------------------------------------------------------
RUN go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest

# -- Syft (SBOM generator from Anchore) -------------------------------------
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# -- CodeQL (GitHub semantic code analysis) ---------------------------------
RUN wget -q "https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz" \
    && tar -xzf codeql-bundle-linux64.tar.gz -C /usr/local \
    && rm codeql-bundle-linux64.tar.gz \
    && ln -sf /usr/local/codeql/codeql /usr/local/bin/codeql

# -- SafeDep vet (dependency malware detection + reachability) ---------------
RUN wget -q "https://github.com/safedep/vet/releases/latest/download/vet_linux_amd64.tar.gz" \
    && tar -xzf vet_linux_amd64.tar.gz -C /usr/local/bin vet \
    && rm vet_linux_amd64.tar.gz \
    && chmod +x /usr/local/bin/vet

# -- CycloneDX CLI (SBOM merge / convert / diff) ----------------------------
RUN wget -q "https://github.com/CycloneDX/cyclonedx-cli/releases/latest/download/cyclonedx-linux-x64" \
    -O /usr/local/bin/cyclonedx-cli \
    && chmod +x /usr/local/bin/cyclonedx-cli

# -- Pickle-Fuzzer (Rust / Cargo) -------------------------------------------
RUN cargo install pickle-fuzzer || true

# ---------------------------------------------------------------------------
# 4. Copy application code + all scripts, configs, and tests
# ---------------------------------------------------------------------------
COPY api/ /app/api/
COPY scripts/ /app/scripts/
COPY configs/ /app/configs/
COPY tests/ /app/tests/
COPY Makefile /app/Makefile
COPY pyproject.toml /app/pyproject.toml
COPY generate_all_fixtures.py /app/generate_all_fixtures.py

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Run the API
CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
