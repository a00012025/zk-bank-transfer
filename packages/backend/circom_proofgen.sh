#!/bin/bash
set -e # Stop on error

if [ $# -ne 4 ]; then
    echo "Usage: $0 <circuit_name> <input_path> <build_dir> <is_local>"
    exit 1
fi
if [ -z "$RAPIDSNARK_BUILD_DIR" ]; then
    echo "RAPIDSNARK_BUILD_DIR env not set"
    exit 1
fi
rapidsnark_prover_path="${RAPIDSNARK_BUILD_DIR}/prover"
if [ ! -f "${rapidsnark_prover_path}" ]; then
    echo "Rapidsnark prover not found at ${rapidsnark_prover_path}"
    exit 1
fi

circuit_name=$1
input_path=$2
build_dir=$3
is_local=$4
input_filename=$(basename -- "$input_path")
input_filename="${input_filename%.*}"
prover_output_path="${build_dir}/../proofs"

zkey_path="${build_dir}/${circuit_name}.zkey"
circuit_cpp_bin="${build_dir}/${circuit_name}_cpp/${circuit_name}"
witness_path="${prover_output_path}/${input_filename}_${circuit_name}_witness.wtns"
proof_path="${prover_output_path}/${input_filename}_${circuit_name}_proof.json"
public_path="${prover_output_path}/${input_filename}_${circuit_name}_public.json"

if [ ! -f "${input_path}" ]; then
    echo "Input file not found at ${input_path}"
    exit 1
fi
if [ ! -f "${zkey_path}" ]; then
    echo "Circuit zkey not found at ${zkey_path}"
    exit 1
fi
if [ ! -f "${circuit_cpp_bin}" ]; then
    echo "Circuit binary not found at ${circuit_cpp_bin}"
    exit 1
fi
if [ ! -d "${prover_output_path}" ]; then
    mkdir -p "${prover_output_path}"
fi

echo "${circuit_cpp_bin} ${input_path} ${witness_path}"
"${circuit_cpp_bin}" "${input_path}" "${witness_path}"
status_c_wit=$?

echo "Finished C witness gen! Status: ${status_c_wit}"
if [ $status_c_wit -ne 0 ]; then
    echo "C based witness gen failed with status (might be on machine specs diff than compilation): ${status_c_wit}"
    exit 1
fi

if [ "$is_local" = "1" ]; then
    # DEFAULT SNARKJS PROVER (SLOW)
    NODE_OPTIONS='--max-old-space-size=644000' snarkjs groth16 prove "${zkey_path}" "${witness_path}" "${proof_path}" "${public_path}"
    status_prover=$?
    echo "✓ Finished slow proofgen! Status: ${status_prover}"
else
    # RAPIDSNARK PROVER (10x FASTER)
    echo "${rapidsnark_prover_path} ${zkey_path} ${witness_path} ${proof_path} ${public_path}"
    "${rapidsnark_prover_path}" "${zkey_path}" "${witness_path}" "${proof_path}" "${public_path}" | tee /dev/stderr
    status_prover=$?
    echo "✓ Finished rapid proofgen! Status: ${status_prover}"
fi

exit 0