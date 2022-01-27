SOURCE_FILES := $(shell find . -type f -name '*.ts' -o -name '*.json' -o -name '*.js')

.PHONY: deps
deps:
	npm i assemblyscript

policy.wasm: $(SOURCE_FILES)
	npm run asbuild
	mv ./build/optimized.wasm policy.wasm

.PHONY: test
test:
	npx asp

annotated-policy.wasm: policy.wasm metadata.yml
	kwctl annotate -m metadata.yml -o annotated-policy.wasm policy.wasm

.PHONY: e2e-tests
e2e-tests: annotated-policy.wasm
	bats e2e.bats

.PHONY: clean
clean:
	rm *.wasm
