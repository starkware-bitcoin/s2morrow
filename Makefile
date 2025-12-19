TARGET_DIR = target
PROVING_UTILS_REV=efbaeebfdce3463aa61e16d7d8e6069f03df0994

install-stwo-run-and-prove:
	cargo +nightly-2025-07-14 install \
		--git ssh://git@github.com/m-kus/proving-utils.git \
		--rev $(PROVING_UTILS_REV) \
		stwo_run_and_prove --force

falcon-execute:
	rm -rf $(TARGET_DIR)/execute/falcon \
		&& cd packages/falcon \
		&& scarb execute --arguments-file tests/data/args_512_1.json --print-resource-usage

falcon-args:
	python packages/falcon/scripts/generate_args.py --n 512 --num_signatures 1 > packages/falcon/tests/data/args_512_1.json
	python packages/falcon/scripts/generate_args.py --n 1024 --num_signatures 1 > packages/falcon/tests/data/args_1024_1.json

falcon-build:
	scarb --profile release build --package falcon

falcon-prove:
	stwo_run_and_prove \
		--program resources/simple_bootloader_compiled.json \
		--program_input packages/falcon/proving_task.json \
		--prover_params_json prover_params.json \
		--proofs_dir $(TARGET_DIR) \
		--proof-format cairo-serde \
		--verify

falcon-burn:
	scarb burn --package falcon \
		--arguments-file packages/falcon/tests/data/args_512_1.json \
		--output-file target/falcon.svg \
		--open-in-browser

sphincs-build:
	scarb --profile release build --package sphincs_plus --features blake_hash,sparse_addr

sphincs-build-sha2:
	scarb --profile release build --package sphincs_plus

sphincs-execute:
	rm -rf $(TARGET_DIR)/execute/sphincs_plus
	scarb --profile release execute \
		--no-build \
		--package sphincs_plus \
		--print-resource-usage \
		--arguments-file packages/sphincs-plus/tests/data/sha2_simple_128s.json

sphincs-burn: sphincs-build
	scarb burn --package sphincs_plus \
		--no-build \
		--output-file target/sphincs-plus.svg \
		--arguments-file packages/sphincs-plus/tests/data/sha2_simple_128s.json \
		--open-in-browser

sphincs-prove:
	stwo_run_and_prove \
		--program resources/simple_bootloader_compiled.json \
		--program_input packages/sphincs-plus/proving_task.json \
		--prover_params_json prover_params.json \
		--proofs_dir $(TARGET_DIR) \
		--proof-format cairo-serde \
		--verify
