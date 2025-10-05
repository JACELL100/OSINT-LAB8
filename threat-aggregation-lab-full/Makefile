.PHONY: venv install run-otx normalize

venv:
	python -m venv venv

install:
	. venv/bin/activate && pip install -r requirements.txt

run-otx:
	. venv/bin/activate && python -m src.collectors.otx_collector

normalize:
	. venv/bin/activate && python -m src.normalizers.stix_normalizer $(FILE)
