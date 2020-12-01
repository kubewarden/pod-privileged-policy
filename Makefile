HYPERFINE := $(shell command -v hyperfine 2> /dev/null)

.PHONY: build
build:
	npm run asbuild

test:
	npx asp

.PHONY: bench
bench: build
ifndef HYPERFINE
	cargo install hyperfine
endif
	@printf "\nAccepting policy\n"
	hyperfine --warmup 10 "cat assembly/__tests__/fixtures/privileged_container.json | wasmtime run --env TRUSTED_USERS="alice" --env TRUSTED_GROUPS="trusted-users,system:masters" build/optimized.wasm"

	@printf "\nRejecting policy\n"
	hyperfine --warmup 10 "cat assembly/__tests__/fixtures/privileged_container.json | wasmtime run --env TRUSTED_USERS="alice" --env TRUSTED_GROUPS="trusted-users,admins" build/optimized.wasm"

	@printf "\nOperation not relevant\n"
	hyperfine --warmup 10 "cat assembly/__tests__/fixtures/req_delete.json | wasmtime run --env TRUSTED_USERS="alice" --env TRUSTED_GROUPS="trusted-users,admins" build/optimized.wasm"
