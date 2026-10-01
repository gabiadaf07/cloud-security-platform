.PHONY: test scan evidence terraform-test localstack-up localstack-verify localstack-down

test:
	python3 -m unittest discover -s tests -v

scan:
	python3 -m security_platform.scanners.terraform_scanner modules examples --fail-on HIGH
	python3 -m security_platform.scanners.kubernetes_scanner monitoring-platform/k8s --fail-on HIGH

evidence:
	python3 -m security_platform.compliance.evidence_collector

terraform-test:
	terraform -chdir=modules/aws-secure-backup init -backend=false
	terraform -chdir=modules/aws-secure-backup validate
	terraform -chdir=modules/aws-secure-backup test

localstack-up:
	./scripts/localstack-deploy.sh up

localstack-verify:
	./scripts/localstack-deploy.sh verify

localstack-down:
	./scripts/localstack-deploy.sh down
