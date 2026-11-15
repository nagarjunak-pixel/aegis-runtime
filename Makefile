.PHONY: install lint typecheck test verify benchmark redteam ui-build serve clean

UV ?= uv

install:
	$(UV) sync --all-extras

lint:
	$(UV) run ruff check src tests
	$(UV) run ruff format --check src tests

typecheck:
	$(UV) run mypy src

test:
	$(UV) run pytest --cov=aegis --cov-report=term-missing

benchmark:
	$(UV) run aegis benchmark --transactions 200 --fault-rate 0.25

redteam:
	$(UV) run aegis redteam

ui-build:
	cd ui && npm install && npm run build

verify: lint typecheck test redteam benchmark

serve:
	$(UV) run aegis serve --host 127.0.0.1 --port 8000

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .hypothesis .coverage ui/dist .aegis_data
