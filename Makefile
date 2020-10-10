lint:
	python -m isort scrapli_paramiko/
	python -m isort tests/
	python -m black scrapli_paramiko/
	python -m black tests/
	python -m pylama scrapli_paramiko/
	python -m pydocstyle scrapli_paramiko/
	python -m mypy scrapli_paramiko/

cov:
	python -m pytest \
	--cov=scrapli_paramiko \
	--cov-report html \
	--cov-report term \
	tests/

cov_unit:
	python -m pytest \
	--cov=scrapli_paramiko \
	--cov-report html \
	--cov-report term \
	tests/unit/

test:
	python -m pytest tests/

test_unit:
	python -m pytest tests/unit/

test_functional:
	python -m pytest tests/functional/
	python -m pytest examples/

.PHONY: docs
docs:
	rm -rf docs/scrapli_paramiko
	python -m pdoc \
	--html \
	--output-dir docs \
	scrapli_paramiko \
	--force
