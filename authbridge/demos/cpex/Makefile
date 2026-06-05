# CPEX demo Makefile — kind-cluster flow.
#
# End-to-end:
#
#   make deploy        # build images, load into kind, kubectl apply
#   make port-forward  # expose Keycloak (8081) + gateway (8082) on host
#   make scenarios     # run all 7 demo curl scenarios
#   make logs          # tail authbridge-cpex logs
#   make undeploy      # delete the cpex-demo namespace
#
# Prerequisites:
#   - kind cluster (we target `kagenti`; override KIND_CLUSTER)
#   - docker / podman
#   - kubectl
#   - HR_MCP_SRC pointing at a directory containing the hr-mcp
#     backend's Dockerfile + server.py + requirements.txt (default
#     looks for it at ../../../../cpex-mcp-servers/hr-mcp-server;
#     override on the command line if yours lives elsewhere)

KIND_CLUSTER ?= kagenti
NAMESPACE    ?= cpex-demo

# Image tags — local images, loaded into kind, never pushed to a
# registry. imagePullPolicy: Never in the Deployment manifests.
AUTHBRIDGE_IMAGE ?= authbridge-cpex:dev
HR_MCP_IMAGE     ?= hr-mcp:dev

# Source paths for the images. authbridge-cpex builds from the
# kagenti-extensions tree (this repo); hr-mcp is a FastAPI MCP
# server living in its own repository (override HR_MCP_SRC on the
# command line if it's not in the default location).
KAGENTI_ROOT := $(abspath $(CURDIR)/../../..)
HR_MCP_SRC   ?= $(KAGENTI_ROOT)/../cpex-mcp-servers/hr-mcp-server

.PHONY: help build-images load-images deploy port-forward scenarios logs undeploy preflight

.DEFAULT_GOAL := help

help:  ## Show this menu (default)
	@printf "\nCPEX demo — runs CPEX/APL policy on the kagenti AuthBridge\n"
	@printf "platform. Self-contained namespace: $(NAMESPACE).\n\n"
	@printf "Typical run:\n"
	@printf "  \033[1mmake deploy\033[0m\n"
	@printf "  \033[1mmake port-forward\033[0m   (in another terminal)\n"
	@printf "  \033[1mmake scenarios\033[0m\n\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-18s\033[0m %s\n", $$1, $$2}'

preflight:  ## Check that prerequisites are in place
	@command -v kind >/dev/null      || { echo "missing: kind";       exit 1; }
	@command -v kubectl >/dev/null   || { echo "missing: kubectl";    exit 1; }
	@command -v docker >/dev/null    || { echo "missing: docker";     exit 1; }
	@kind get clusters | grep -q '^$(KIND_CLUSTER)$$' || { echo "missing kind cluster: $(KIND_CLUSTER)"; exit 1; }
	@test -d "$(HR_MCP_SRC)" || { echo "missing: $(HR_MCP_SRC) (set HR_MCP_SRC=/path/to/hr-mcp-server)"; exit 1; }
	@echo "preflight OK"

build-images: preflight  ## Build authbridge-cpex + hr-mcp docker images
	@echo "[build] authbridge-cpex from $(KAGENTI_ROOT)"
	cd $(KAGENTI_ROOT) && docker build \
		-f cmd/authbridge-cpex/Dockerfile \
		--build-arg CPEX_FFI_VERSION=$$(cat cmd/authbridge-cpex/CPEX_FFI_VERSION | tr -d '[:space:]') \
		-t $(AUTHBRIDGE_IMAGE) .
	@echo "[build] hr-mcp from $(HR_MCP_SRC)"
	cd $(HR_MCP_SRC) && docker build -t $(HR_MCP_IMAGE) .

load-images: preflight  ## Load both images into the kind cluster
	kind load docker-image $(AUTHBRIDGE_IMAGE) --name $(KIND_CLUSTER)
	kind load docker-image $(HR_MCP_IMAGE)     --name $(KIND_CLUSTER)

apply:  ## kubectl apply the manifests (assumes images already loaded)
	kubectl apply -f k8s/00-namespace.yaml
	# Recreate the realm ConfigMap from the JSON file each time so
	# realm-export.json edits take effect on `make apply`.
	kubectl create configmap keycloak-realm \
		--namespace $(NAMESPACE) \
		--from-file=cpex-demo-realm.json=k8s/realm-export.json \
		--dry-run=client -o yaml | kubectl apply -f -
	# Same dynamic ConfigMap shape for cpex-policy.yaml so YAML
	# edits propagate without rewriting a manifest.
	kubectl create configmap cpex-policy \
		--namespace $(NAMESPACE) \
		--from-file=cpex.yaml=k8s/cpex-policy.yaml \
		--dry-run=client -o yaml | kubectl apply -f -
	kubectl apply -f k8s/10-keycloak.yaml
	kubectl apply -f k8s/20-hr-mcp.yaml
	kubectl apply -f k8s/30-authbridge-cpex.yaml

deploy: build-images load-images apply  ## Full bring-up: build, load, apply
	@echo
	@echo "Waiting for pods to become Ready..."
	kubectl -n $(NAMESPACE) wait --for=condition=Ready pod -l app.kubernetes.io/part-of=cpex-demo --timeout=120s
	@echo
	@printf "\033[1;32mDeploy complete.\033[0m Next:\n"
	@printf "  make port-forward   # in another terminal\n"
	@printf "  make scenarios\n"

port-forward:  ## Forward Keycloak (8081) + gateway (8082) to localhost
	@echo "Port-forwarding (Ctrl+C to stop)..."
	@echo "  Keycloak admin: http://localhost:8081  (admin/admin)"
	@echo "  Gateway:        http://localhost:8082"
	kubectl -n $(NAMESPACE) port-forward svc/keycloak 8081:8080 & \
	kubectl -n $(NAMESPACE) port-forward svc/authbridge-cpex 8082:8080 & \
	wait

scenarios:  ## Run all 7 demo curl scenarios (assumes port-forward up)
	@echo "[NOTE] Scenarios sourced from $(HR_MCP_SRC)/../scenarios — point at gateway :8082"
	GATEWAY=http://localhost:8082 \
	$(HR_MCP_SRC)/../scenarios/01-bob-allow.sh
	GATEWAY=http://localhost:8082 \
	$(HR_MCP_SRC)/../scenarios/02-alice-deny.sh
	GATEWAY=http://localhost:8082 \
	$(HR_MCP_SRC)/../scenarios/03-eve-redact.sh
	GATEWAY=http://localhost:8082 \
	$(HR_MCP_SRC)/../scenarios/04-alice-internal-allow.sh
	GATEWAY=http://localhost:8082 \
	$(HR_MCP_SRC)/../scenarios/05-alice-external-cedar-deny.sh
	GATEWAY=http://localhost:8082 \
	$(HR_MCP_SRC)/../scenarios/06-bob-apl-deny.sh
	GATEWAY=http://localhost:8082 \
	$(HR_MCP_SRC)/../scenarios/07-bob-pii-deny.sh

logs:  ## Tail authbridge-cpex logs
	kubectl -n $(NAMESPACE) logs -f deploy/authbridge-cpex

undeploy:  ## Tear down the demo
	-kubectl delete namespace $(NAMESPACE) --wait=false
