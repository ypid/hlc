PIP_OPTIONS =
NOSE_OPTIONS =
RELEASE_OPENPGP_FINGERPRINT ?= C505B5C93B0DB3D338A1B6005FE92C12EE88E1F0
RELEASE_OPENPGP_CMD ?= gpg
PYPI_REPO ?= pypi

.PHONY: FORCE_MAKE

.PHONY: default
default: list

## list targets (help) {{{
.PHONY: list
# https://stackoverflow.com/a/26339924/2239985
list:
	@echo "This Makefile has the following targets:"
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^(:?[^[:alnum:]]|FORCE_MAKE$$)' -e '^$@$$' | sed 's/^/    /'
## }}}

## Git hooks {{{
.PHONY: install-pre-commit-hook
install-pre-commit-hook: ./docs/_prepare/hooks/pre-commit
	ln -srf "$<" "$(shell git rev-parse --git-dir)/hooks"

.PHONY: run-pre-commit-hook
run-pre-commit-hook: ./docs/_prepare/hooks/pre-commit
	"$<"

.PHONY: remove-pre-commit-hook
remove-pre-commit-hook:
	rm -f "$(shell git rev-parse --git-dir)/hooks/pre-commit"
## }}}

## check {{{
## Fail when git working directory for the Make prerequisites has changed.
.PHONY: check
check: check-nose check-tox check-convert fail-when-git-dirty

.PHONY: check-tox
check-tox:
	tox

.PHONY: check-nose
check-nose:
	(nosetests3 $(NOSE_OPTIONS) || nosetests $(NOSE_OPTIONS))

.PHONY: fail-when-git-dirty
fail-when-git-dirty:
	git diff --quiet -- tests/data/

.PHONY: check-convert
check-convert:
	hlc tests/data/ms_dhcp_original.csv -q --from ms_dhcp --to json -o tests/data/ms_dhcp_gen.json
	hlc tests/data/ms_dhcp_source.json -q --from json --to json -o tests/data/ms_dhcp_gen2.json
	diff tests/data/ms_dhcp_gen.json tests/data/ms_dhcp_gen2.json
	hlc tests/data/ms_dhcp_original.csv -q --from ms_dhcp --ignore-fqdn-regex '(:?phone|android|privat)' --rename-csv-file tests/data/host_rename.csv -o tests/data/paedml_linux_gen.csv -t paedml_linux
	hlc tests/data/paedml_linux_gen.csv -q --from paedml_linux -o tests/data/paedml_linux_gen2.csv -t paedml_linux
	diff tests/data/paedml_linux_gen.csv tests/data/paedml_linux_gen2.csv

# Does not work on Travis, different versions. Using check-nose for now.
.PHONY: check-nose2
check-nose2:
	(nose2-3 --start-dir tests $(NOSE_OPTIONS) || nose2-3.4 --start-dir tests $(NOSE_OPTIONS))
## }}}

## development {{{

.PHONY: clean
clean:
	find . -name '*.py[co]' -delete
	rm -rf *.egg *.egg-info

.PHONY: distclean
distclean: clean
	rm -rf build dist dist_signed .coverage

.PHONY: build
build: setup.py
	"./$<" bdist_wheel sdist

.PHONY: release-versionbump
release-versionbump: hlc/_meta.py
	editor "$<"
	git commit --all --message="Release version $(shell ./setup.py --version)"

.PHONY: release-prepare
release-sign:
	mv dist dist_signed
	find dist_signed -type f -regextype posix-extended -regex '^.*(:?\.(:?tar\.gz|whl))$$' -print0 \
		| xargs --null --max-args=1 $(RELEASE_OPENPGP_CMD) --default-key "$(RELEASE_OPENPGP_FINGERPRINT)" --detach-sign --armor
	git tag --sign --local-user "$(RELEASE_OPENPGP_FINGERPRINT)" "v$(shell ./setup.py --version)"

.PHONY: release-prepare
release-prepare: check release-versionbump distclean build release-sign

.PHONY: pypi-register
pypi-register: build
	twine register -r "$(PYPI_REPO)" "$(shell find dist -type f -name '*.whl' | sort | head -n 1)"

.PHONY: pypi-register
pypi-upload: build
	twine upload -r "$(PYPI_REPO)" dist_signed/*

.PHONY: release
release: release-prepare pypi-upload

## }}}
