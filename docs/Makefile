# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line and environment.
PYTHON        ?= python
SPHINXOPTS    ?=
SPHINXBUILD   ?= sphinx-build
SOURCEDIR     = source
BUILDDIR      = build
APIDOCOUT     = $(SOURCEDIR)/auto
PACKAGEDIR    = ../aivm

# Put it first so that "make" without an argument behaves like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

# Reconstruct the API reference from the current package before every HTML
# build. The generated RST remains checked in so changes are reviewable.
apidoc:
	@rm -rf "$(APIDOCOUT)"
	@$(PYTHON) -m sphinx.ext.apidoc \
		--private \
		--separate \
		--force \
		--output-dir "$(APIDOCOUT)" \
		"$(PACKAGEDIR)"

architecture-check:
	@cd .. && $(PYTHON) dev/devcheck/architecture_docs.py check

html: architecture-check apidoc
	@$(SPHINXBUILD) -M html "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help apidoc architecture-check html Makefile

# Catch-all target: route all other targets to Sphinx using make mode.
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
