TF_VERSION := 0.14.9

PLATFORM := $(shell uname -s | tr A-Z a-z)
ARCH := $(shell uname -m | sed 's/x86_64/amd64/' | sed -e 's/i[3,6]86/386/')

DIR := transfer_server_custom_idp

# Name of Terraform executable file
TF := terraform-$(TF_VERSION)

ifeq ($(TF_AUTO_APPROVE), true)
tf_flags := -auto-approve
endif

.ONESHELL:
.SHELLFLAGS = -ce
.PHONY: build
build:
	# To run Lambda, we have to build a ZIP archive with our code plus all dependencies in it.
	# Unfortunately, Poetry cannot do that out of the box yet. The workaround was adapted from:
	#     https://github.com/python-poetry/poetry/issues/1937
	mkdir -p build
	rm -rf build/*
	poetry export -f requirements.txt --without-hashes | pip install -r /dev/stdin -t build/
	cp -rf ${DIR} build/

	rm -f build.zip
	cd build/ && zip -r ../build.zip *


.ONESHELL:
.SHELLFLAGS = -ce
.PHONY: lint
lint:
	mypy --ignore-missing-imports ${DIR}
	flakehell lint ${DIR}


.ONESHELL:
.SHELLFLAGS = -ce
.PHONY: format
format:
	isort ${DIR}
