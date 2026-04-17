## Parallel fetch wrapper for trivy-db.
## Overrides the upstream download_and_extract macro to use aria2c
## (multi-connection per file) + pigz (parallel decompression), and
## splits each tarball into its own target so `make -jN fetch-all`
## runs them concurrently.

include Makefile

# Override upstream macro: aria2c with 16 connections per file, pigz for extract.
# Falls back to wget+gzip if aria2c/pigz are unavailable.
define download_and_extract
	@echo "Downloading $(1)..." && \
	TMP_FILE=$$(mktemp) && \
	if command -v aria2c >/dev/null 2>&1; then \
		aria2c -q -x 16 -s 16 -k 1M --allow-overwrite=true \
			--auto-file-renaming=false -d "$$(dirname "$$TMP_FILE")" \
			-o "$$(basename "$$TMP_FILE")" "$(1)"; \
	else \
		wget -q "$(1)" -O "$$TMP_FILE"; \
	fi && \
	if command -v pigz >/dev/null 2>&1; then \
		pigz -dc "$$TMP_FILE" | tar xf - -C $(2) --strip-components=1; \
	else \
		tar xzf "$$TMP_FILE" -C $(2) --strip-components=1; \
	fi && \
	rm -f "$$TMP_FILE"
endef

.PHONY: fetch-all
fetch-all: \
	fetch-ruby fetch-php fetch-nodejs fetch-bitnami fetch-ghsa fetch-govulndb \
	fetch-cocoapods fetch-k8s fetch-julia \
	fetch-vuln-list fetch-vuln-list-redhat fetch-vuln-list-debian \
	fetch-vuln-list-nvd fetch-vuln-list-aqua

.PHONY: fetch-ruby
fetch-ruby:
	mkdir -p $(CACHE_DIR)/ruby-advisory-db
	$(call download_and_extract,https://github.com/rubysec/ruby-advisory-db/archive/master.tar.gz,$(CACHE_DIR)/ruby-advisory-db)

.PHONY: fetch-php
fetch-php:
	mkdir -p $(CACHE_DIR)/php-security-advisories
	$(call download_and_extract,https://github.com/FriendsOfPHP/security-advisories/archive/master.tar.gz,$(CACHE_DIR)/php-security-advisories)

.PHONY: fetch-nodejs
fetch-nodejs:
	mkdir -p $(CACHE_DIR)/nodejs-security-wg
	$(call download_and_extract,https://github.com/nodejs/security-wg/archive/main.tar.gz,$(CACHE_DIR)/nodejs-security-wg)

.PHONY: fetch-bitnami
fetch-bitnami:
	mkdir -p $(CACHE_DIR)/bitnami-vulndb
	$(call download_and_extract,https://github.com/bitnami/vulndb/archive/main.tar.gz,$(CACHE_DIR)/bitnami-vulndb)

.PHONY: fetch-ghsa
fetch-ghsa:
	mkdir -p $(CACHE_DIR)/ghsa
	$(call download_and_extract,https://github.com/github/advisory-database/archive/refs/heads/main.tar.gz,$(CACHE_DIR)/ghsa)

.PHONY: fetch-govulndb
fetch-govulndb:
	mkdir -p $(CACHE_DIR)/govulndb
	$(call download_and_extract,https://github.com/golang/vulndb/archive/refs/heads/master.tar.gz,$(CACHE_DIR)/govulndb)

.PHONY: fetch-cocoapods
fetch-cocoapods:
	mkdir -p $(CACHE_DIR)/cocoapods-specs
	$(call download_and_extract,https://github.com/CocoaPods/Specs/archive/master.tar.gz,$(CACHE_DIR)/cocoapods-specs)

.PHONY: fetch-k8s
fetch-k8s:
	mkdir -p $(CACHE_DIR)/k8s-cve-feed
	$(call download_and_extract,https://github.com/kubernetes-sigs/cve-feed-osv/archive/main.tar.gz,$(CACHE_DIR)/k8s-cve-feed)

.PHONY: fetch-julia
fetch-julia:
	mkdir -p $(CACHE_DIR)/julia
	$(call download_and_extract,https://github.com/JuliaLang/SecurityAdvisories.jl/archive/refs/heads/generated/osv.tar.gz,$(CACHE_DIR)/julia)

.PHONY: fetch-vuln-list
fetch-vuln-list:
	mkdir -p $(CACHE_DIR)/vuln-list
	$(call download_and_extract,https://github.com/$(REPO_OWNER)/vuln-list/archive/main.tar.gz,$(CACHE_DIR)/vuln-list)

.PHONY: fetch-vuln-list-redhat
fetch-vuln-list-redhat:
	mkdir -p $(CACHE_DIR)/vuln-list-redhat
	$(call download_and_extract,https://github.com/$(REPO_OWNER)/vuln-list-redhat/archive/main.tar.gz,$(CACHE_DIR)/vuln-list-redhat)

.PHONY: fetch-vuln-list-debian
fetch-vuln-list-debian:
	mkdir -p $(CACHE_DIR)/vuln-list-debian
	$(call download_and_extract,https://github.com/$(REPO_OWNER)/vuln-list-debian/archive/main.tar.gz,$(CACHE_DIR)/vuln-list-debian)

.PHONY: fetch-vuln-list-nvd
fetch-vuln-list-nvd:
	mkdir -p $(CACHE_DIR)/vuln-list-nvd
	$(call download_and_extract,https://github.com/$(REPO_OWNER)/vuln-list-nvd/archive/main.tar.gz,$(CACHE_DIR)/vuln-list-nvd)

.PHONY: fetch-vuln-list-aqua
fetch-vuln-list-aqua:
	mkdir -p $(CACHE_DIR)/vuln-list-aqua
	$(call download_and_extract,https://github.com/$(REPO_OWNER)/vuln-list-aqua/archive/main.tar.gz,$(CACHE_DIR)/vuln-list-aqua)