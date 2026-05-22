#!/usr/bin/env sh
set -eu

if [ ! -f .env ]; then
	echo "missing .env; create it from .env.example first" >&2
	exit 2
fi

set -a
. ./.env
set +a

image="${MEOWGO_DOCKER_IMAGE:-meowgo}"

usage() {
	echo "usage: sh scripts/run_gpt2_bench.sh [meow|freivalds|meow_gpt2|freivalds_gpt2|all] [--range] [flags...]" >&2
	echo "" >&2
	echo "examples:" >&2
	echo "  sh scripts/run_gpt2_bench.sh meow --seq 1 --rho 1/2 --L 1 --linker qa_nizk --merkle multi" >&2
	echo "  sh scripts/run_gpt2_bench.sh meow --seq 1 --rho 1/2 --L 1 --linker qa_batch --merkle multi" >&2
	echo "  sh scripts/run_gpt2_bench.sh freivalds --seq 1 --compile" >&2
	echo "  sh scripts/run_gpt2_bench.sh all --range --from 0 --to 4 --compile" >&2
	exit 2
}

if [ "$#" -lt 1 ]; then
	usage
fi

target="$1"
shift

case "$target" in
	meow|meow_gpt2|freivalds|freivalds_gpt2|all)
		;;
	*)
		usage
		;;
esac

args=""
for arg in "$@"; do
	if [ -z "$args" ]; then
		args="$arg"
	else
		args="$args $arg"
	fi
done

docker build -t "$image" .

env_args="--env-file .env"
for key in \
	MEOW_GPT2_SEQ MEOW_GPT2_RHO MEOW_GPT2_L MEOW_GPT2_LINKER MEOW_GPT2_MERKLE MEOW_GPT2_ALL MEOW_GPT2_SEQ_FROM MEOW_GPT2_SEQ_TO MEOW_GPT2_ONLY_COMPILE MEOW_GPT2_OUTPUT_DIR \
	FREIVALDS_GPT2_SEQ FREIVALDS_GPT2_ALL FREIVALDS_GPT2_SEQ_FROM FREIVALDS_GPT2_SEQ_TO FREIVALDS_GPT2_ONLY_COMPILE FREIVALDS_GPT2_OUTPUT_DIR
do
	value="$(eval "printf '%s' \"\${$key:-}\"")"
	if [ -n "$value" ]; then
		env_args="$env_args -e $key=$value"
	fi
done

run_protocol() {
	protocol="$1"
	# shellcheck disable=SC2086
	docker run --rm $env_args \
		-v "$(pwd)/benchmark:/workspace/benchmark" \
		"$image" go run "./cmd/$protocol" $args
}

case "$target" in
	meow|meow_gpt2)
		run_protocol meow_gpt2
		;;
	freivalds|freivalds_gpt2)
		run_protocol freivalds_gpt2
		;;
	all)
		run_protocol meow_gpt2
		run_protocol freivalds_gpt2
		;;
esac
