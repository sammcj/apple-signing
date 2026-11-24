# Builds the example app and runs the checks. Signing lives in macsign.py.
SHELL := /bin/bash
# Xcode's Python, the oldest macsign supports.
PYTHON ?= /usr/bin/python3
MACSIGN := $(PYTHON) macsign.py

APP := build/Example.app
SIGNED := build/signing/Example.app
ENTITLEMENTS := Example/Example.entitlements

.DEFAULT_GOAL := help
.PHONY: help example run install release version lint format test clean

help:
	@printf 'Usage: make <target>\n\n'
	@printf '  example   build the example app\n'
	@printf '  run       development sign the example, then open it\n'
	@printf '  install   development sign the example, then install it\n'
	@printf '  release   sign, notarise and package the example\n'
	@printf '  test      unit tests, then ad-hoc sign and verify the example (no credentials needed)\n'
	@printf '  lint      check macsign and its tests (needs uv)\n'
	@printf '  format    format macsign and its tests (needs uv)\n'
	@printf '  version   show the macsign version\n'
	@printf '  clean     remove the example app and its DMGs\n\n'
	@printf 'For your own app: ./macsign.py --help\n'

example:
	@rm -rf "$(APP)"
	@mkdir -p "$(APP)/Contents/MacOS"
	@cp Example/Info.plist "$(APP)/Contents/Info.plist"
	@swiftc -O -parse-as-library -target "$$(uname -m)-apple-macosx14.0" Example/Example.swift -o "$(APP)/Contents/MacOS/Example"

run: example
	@$(MACSIGN) sign "$(APP)" --entitlements "$(ENTITLEMENTS)"
	@open "$(SIGNED)"

install: example
	@$(MACSIGN) install "$(APP)" --entitlements "$(ENTITLEMENTS)"

release: example
	@$(MACSIGN) release "$(APP)" --entitlements "$(ENTITLEMENTS)"

version:
	@$(MACSIGN) --version

lint:
	@uvx ruff check .
	@uvx ruff format --check .
	@uvx ty check

format:
	@uvx ruff check --fix .
	@uvx ruff format .

test: example
	@$(PYTHON) -m unittest discover -s tests
	@$(MACSIGN) sign "$(APP)" --identity - --entitlements "$(ENTITLEMENTS)" --stage build/test
	@$(MACSIGN) verify build/test/Example.app --entitlements "$(ENTITLEMENTS)"

clean:
	rm -rf "$(APP)" "$(SIGNED)" build/test
	rm -f dist/Example-*.dmg
