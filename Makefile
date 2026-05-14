.PHONY: setup test test-crypto demo docker-build docker-demo docker-test clean

setup:
	bash setup.sh

test:
	pytest tests/ -v --tb=short

test-crypto:
	pytest tests/test_sss.py tests/test_lagrange.py tests/test_hkdf.py -v

demo:
	NODE_TRANSPORT=local python simulate/run_demo.py

docker-build:
	docker compose build

docker-demo:
	docker compose up --abort-on-container-exit demo

docker-test:
	docker compose run --rm demo pytest tests/ -v

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
	rm -rf data/
