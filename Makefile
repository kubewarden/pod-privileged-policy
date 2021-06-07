.PHONY: build
build:
	npm run asbuild

test:
	npx asp

annotate:
	kwctl annotate -m metadata.yml -o policy.wasm ./build/optimized.wasm

e2e-tests:
	bats e2e.bats
