.PHONY: help install install-minimal scan scan-fast scan-code scan-models scan-deps \
       scan-prompts scan-agents scan-sbom validate-scanners check-tools report report-pdf \
       clean test generate-fixtures

SHELL := /bin/bash
TARGET ?= .
RESULTS_DIR ?= sentinel-results/$(shell date +%Y%m%d-%H%M%S)
SCRIPTS_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))scripts
CONFIGS_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))configs

# Export for scripts
export TARGET
export RESULTS_DIR
export CONFIGS_DIR

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

install: ## Install all tools (full 16-tool stack)
	@bash $(SCRIPTS_DIR)/install.sh full

install-minimal: ## Install minimum viable tools (5-tool stack)
	@bash $(SCRIPTS_DIR)/install.sh minimal

_setup:
	@mkdir -p $(RESULTS_DIR)/{code,models,prompts,agents,deps,sbom}
	@echo "==> Results directory: $(RESULTS_DIR)"

scan: _setup scan-code scan-agents scan-models scan-prompts scan-deps scan-sbom report ## Run full scan (all 6 layers)

scan-fast: _setup ## Run fast PR-level scan (~2 min)
	@bash $(SCRIPTS_DIR)/scan-code.sh fast
	@bash $(SCRIPTS_DIR)/scan-models.sh fast
	@bash $(SCRIPTS_DIR)/scan-deps.sh fast
	@bash $(SCRIPTS_DIR)/report.sh

scan-code: _setup ## Layer 1: Code SAST (Semgrep + CodeQL)
	@bash $(SCRIPTS_DIR)/scan-code.sh

scan-models: _setup ## Layer 2: Model artifact scanning
	@bash $(SCRIPTS_DIR)/scan-models.sh

scan-prompts: _setup ## Layer 3: Prompt regression testing (Promptfoo)
	@bash $(SCRIPTS_DIR)/scan-prompts.sh

scan-agents: _setup ## Layer 1b: Agent architecture analysis
	@bash $(SCRIPTS_DIR)/scan-agents.sh

scan-deps: _setup ## Layer 4: Dependency vulnerability scanning
	@bash $(SCRIPTS_DIR)/scan-deps.sh

scan-sbom: _setup ## Layer 5: SBOM generation and governance
	@bash $(SCRIPTS_DIR)/scan-sbom.sh

validate-scanners: _setup ## Meta: Test scanners with adversarial samples
	@bash $(SCRIPTS_DIR)/validate-scanners.sh

check-tools: ## Show which tools are installed
	@echo "==> Checking installed tools..."
	@command -v semgrep       >/dev/null 2>&1 && echo "  [✓] semgrep"       || echo "  [✗] semgrep"
	@command -v codeql        >/dev/null 2>&1 && echo "  [✓] codeql"        || echo "  [✗] codeql"
	@command -v modelscan     >/dev/null 2>&1 && echo "  [✓] modelscan"     || echo "  [✗] modelscan"
	@command -v picklescan    >/dev/null 2>&1 && echo "  [✓] picklescan"    || echo "  [✗] picklescan"
	@command -v modelaudit    >/dev/null 2>&1 && echo "  [✓] modelaudit"    || echo "  [✗] modelaudit"
	@command -v veritensor    >/dev/null 2>&1 && echo "  [✓] veritensor"    || echo "  [✗] veritensor"
	@command -v fickling      >/dev/null 2>&1 && echo "  [✓] fickling"      || echo "  [✗] fickling"
	@command -v bait-scan     >/dev/null 2>&1 && echo "  [✓] bait-scan"     || echo "  [✗] bait-scan"
	@command -v promptfoo     >/dev/null 2>&1 && echo "  [✓] promptfoo"     || echo "  [✗] promptfoo"
	@command -v agentic-radar >/dev/null 2>&1 && echo "  [✓] agentic-radar" || echo "  [✗] agentic-radar"
	@command -v osv-scanner   >/dev/null 2>&1 && echo "  [✓] osv-scanner"   || echo "  [✗] osv-scanner"
	@command -v vet           >/dev/null 2>&1 && echo "  [✓] vet (safedep)" || echo "  [✗] vet (safedep)"
	@command -v cve-bin-tool  >/dev/null 2>&1 && echo "  [✓] cve-bin-tool"  || echo "  [✗] cve-bin-tool"
	@command -v aisbom        >/dev/null 2>&1 && echo "  [✓] aisbom"        || echo "  [✗] aisbom"
	@command -v syft          >/dev/null 2>&1 && echo "  [✓] syft"          || echo "  [✗] syft"
	@command -v cyclonedx-cli >/dev/null 2>&1 && echo "  [✓] cyclonedx-cli" || echo "  [✗] cyclonedx-cli"
	@command -v pickle-fuzzer >/dev/null 2>&1 && echo "  [✓] pickle-fuzzer" || echo "  [✗] pickle-fuzzer"

report: ## Generate unified markdown report
	@bash $(SCRIPTS_DIR)/report.sh

report-pdf: generate-fixtures ## Full 6-layer scan + fixture validation → PDF report
	@python $(SCRIPTS_DIR)/generate-pdf-report.py --scan-fixtures --target $(TARGET) --configs-dir $(CONFIGS_DIR) -o sentinel-report.pdf

generate-fixtures: ## Regenerate test model fixtures (safe + malicious)
	@python tests/fixtures/generate-fixtures.py

test: generate-fixtures ## Test scanners against ground truth fixtures
	@bash tests/test-scanners.sh

test-verbose: generate-fixtures ## Test scanners with per-file details
	@bash tests/test-scanners.sh --verbose

clean: ## Remove all scan results
	@rm -rf sentinel-results/
	@echo "==> Cleaned sentinel-results/"
