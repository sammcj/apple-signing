# Sign, notarise and package a macOS app for distribution outside the App Store.
# Works with the GNU Make 3.81 that ships with macOS. The logic lives in scripts/.
SHELL := /bin/bash

# An already built .app to sign. It is copied, never changed. Empty builds the app in Example/.
APP_SOURCE ?=
# zsh passes VAR=~/path through without expanding it.
override APP_SOURCE := $(subst ~/,$(HOME)/,$(APP_SOURCE))
# Entitlements for the main app. __TEAM_ID__ in the file becomes your Team ID. Empty keeps whatever the app has.
ENTITLEMENTS ?= $(if $(APP_SOURCE),,$(wildcard Example/Example.entitlements))
# Provisioning profile to embed. Only needed for restricted entitlements (see README).
PROFILE ?=
override ENTITLEMENTS := $(subst ~/,$(HOME)/,$(ENTITLEMENTS))
override PROFILE := $(subst ~/,$(HOME)/,$(PROFILE))
# Keychain service the credentials are stored under. They are per developer, so every app can share one service.
KEYCHAIN_SERVICE ?= apple-release

APP_NAME := $(if $(APP_SOURCE),$(shell basename "$(APP_SOURCE)" .app),Example)
STAGE := build/signing
APP := $(STAGE)/$(APP_NAME).app
DIST := dist
INSTALL_DIR ?= /Applications
# Expanded when used, after bundle has put the app in place.
VERSION = $(shell plutil -extract CFBundleShortVersionString raw -o - "$(APP)/Contents/Info.plist" 2>/dev/null)
DMG = $(DIST)/$(APP_NAME)-$(VERSION).dmg

export ENTITLEMENTS PROFILE KEYCHAIN_SERVICE

.DEFAULT_GOAL := help
.NOTPARALLEL:
.PHONY: help setup check bundle sign run install notarise history dmg verify lint test clean

help:
	@printf 'Usage: make <target> [APP_SOURCE=path/to/My.app] [ENTITLEMENTS=file] [PROFILE=file]\n\n'
	@printf '  setup     store signing and notarisation credentials in the Keychain\n'
	@printf '  check     show what is configured, fail if a release would not work\n'
	@printf '  bundle    copy APP_SOURCE into $(STAGE), or build the example app\n'
	@printf '  sign      bundle, then development sign (falls back to ad-hoc)\n'
	@printf '  run       sign, then open the app\n'
	@printf '  install   sign, then replace the copy in $(INSTALL_DIR)\n'
	@printf '  notarise  bundle, Developer ID sign, notarise and staple the app\n'
	@printf '  history   list submissions to Apple, or ID=... for the log of one\n'
	@printf '  dmg       notarise, then build, sign, notarise and staple a DMG, then verify\n'
	@printf '  verify    check signatures, hardened runtime, Gatekeeper and staples\n'
	@printf '  lint      shellcheck the scripts\n'
	@printf '  test      ad-hoc sign and verify the app, no credentials needed\n'
	@printf '  clean     remove $(STAGE) and the DMGs of this app\n'

setup:
	@scripts/setup-keychain.sh

check:
	@scripts/check.sh

# Using this in your own project: replace this recipe with your build, leaving the result at $(APP).
bundle:
	@[ ! "$(APP_SOURCE)" -ef "$(APP)" ] || { echo "ERROR: APP_SOURCE is the staging copy itself" >&2; exit 1; }
	@mkdir -p "$(STAGE)"
	@rm -rf "$(APP)"
ifneq ($(APP_SOURCE),)
	@ditto "$(APP_SOURCE)" "$(APP)"
	@# codesign refuses Finder info and other extended attributes, which iCloud folders add.
	@xattr -cr "$(APP)"
else
	@mkdir -p "$(APP)/Contents/MacOS"
	@cp Example/Info.plist "$(APP)/Contents/Info.plist"
	@swiftc -O -parse-as-library -target "$$(uname -m)-apple-macosx14.0" Example/Example.swift -o "$(APP)/Contents/MacOS/Example"
endif

sign: bundle
	@scripts/sign.sh "$(APP)" dev

run: sign
	@open "$(APP)"

# Not notarised: Gatekeeper only wants a ticket for downloaded (quarantined) apps. Quit the app first.
install: sign
	@rm -rf "$(INSTALL_DIR)/$(APP_NAME).app.new"
	@ditto "$(APP)" "$(INSTALL_DIR)/$(APP_NAME).app.new"
	@rm -rf "$(INSTALL_DIR)/$(APP_NAME).app"
	@mv "$(INSTALL_DIR)/$(APP_NAME).app.new" "$(INSTALL_DIR)/$(APP_NAME).app"
	@codesign --verify --deep --strict "$(INSTALL_DIR)/$(APP_NAME).app"
	@echo "Installed $(INSTALL_DIR)/$(APP_NAME).app"

# Credentials are checked first, so a misconfigured run fails before anything is built or uploaded.
notarise: check bundle
	@scripts/sign.sh "$(APP)" release
	@mkdir -p "$(DIST)"
	@# The notary service takes a zip, DMG or pkg, not a bare .app. The zip is only for the upload: a zip cannot
	@# be stapled, so the app is.
	@ditto -c -k --keepParent "$(APP)" "$(DIST)/$(APP_NAME).zip"
	@scripts/notarise.sh "$(DIST)/$(APP_NAME).zip" "$(APP)"
	@rm -f "$(DIST)/$(APP_NAME).zip"

history:
	@scripts/history.sh $(ID)

# The app is stapled before it goes in the DMG, so it launches offline once copied out. The DMG gets its own ticket.
dmg: notarise
	@scripts/create-dmg.sh "$(APP)" "$(DMG)"
	@scripts/notarise.sh "$(DMG)" "$(DMG)"
	@scripts/verify.sh "$(APP)" "$(DMG)"

verify:
	@scripts/verify.sh "$(APP)" "$(DMG)"

lint:
	@shellcheck -x -P SCRIPTDIR scripts/*.sh

test: bundle
	@SIGN_IDENTITY=- scripts/sign.sh "$(APP)" dev
	@scripts/verify.sh "$(APP)"

clean:
	rm -rf "$(STAGE)"
	rm -f "$(DIST)/$(APP_NAME)"-*.dmg "$(DIST)/$(APP_NAME).zip"
