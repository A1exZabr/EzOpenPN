UV ?= uv

.PHONY: unit lint content-check check

unit:
	$(UV) run pytest control/tests/unit -q

lint:
	$(UV) run ruff check .
	$(UV) run mypy control/src/ezopenpn

content-check:
	$(UV) run python tools/content_guard.py .

check: content-check lint
	$(UV) run pytest -q
