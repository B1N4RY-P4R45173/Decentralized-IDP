.PHONY: setup test test-crypto demo net-up net-down net-logs net-clean docker-build docker-demo docker-test clean

COMPOSE = docker compose -p idp

setup:
	bash setup.sh

test:
	pytest tests/ -v --tb=short

test-crypto:
	pytest tests/test_sss.py tests/test_lagrange.py tests/test_hkdf.py -v

demo:
	NODE_TRANSPORT=local python simulate/run_demo.py

net-up:
	mkdir -p data ~/.decidp
	$(COMPOSE) build
	$(COMPOSE) up -d
	@echo ""
	@echo "All containers starting. Run 'make net-logs' to watch coordinator."
	@echo "When all nodes show ONLINE in 'python cli.py', you are ready."

net-down:
	$(COMPOSE) down

net-logs:
	$(COMPOSE) logs -f coordinator

net-clean:
	$(COMPOSE) down -v
	sudo rm -rf data/

docker-build:
	$(COMPOSE) build

docker-demo:
	$(COMPOSE) up --abort-on-container-exit demo

docker-test:
	$(COMPOSE) run --rm demo pytest tests/ -v

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
	sudo rm -rf data/
