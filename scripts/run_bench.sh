#!/usr/bin/env sh
set -eu

if [ ! -f .env ]; then
	echo "missing .env; create it from .env.example first" >&2
	exit 2
fi

set -a
. ./.env
set +a

image="${LAMP_DOCKER_IMAGE:-lamp}"

usage() {
	echo "usage: scripts/run_bench.sh [lamp|lamp_batch|freivalds|freivalds_batch|all] [--range] [flags...]" >&2
	echo "" >&2
	echo "examples:" >&2
	echo "  sh scripts/run_bench.sh lamp --repeat 3" >&2
	echo "  scripts/run_bench.sh lamp" >&2
	echo "  scripts/run_bench.sh lamp_batch" >&2
	echo "  scripts/run_bench.sh freivalds" >&2
	echo "  scripts/run_bench.sh freivalds_batch" >&2
	echo "  scripts/run_bench.sh all" >&2
	exit 2
}

if [ "$#" -lt 1 ]; then
	usage
fi

target="$1"
shift

# One RHO controls both LAMP variants. An explicit L (CLI or env) wins.
rho="${RHO:-${LAMP_RHO:-1/2}}"
explicit_l="${LAMP_L:-}"
expect_l=false
expect_rho=false
for arg in "$@"; do
	if [ "$expect_l" = true ]; then explicit_l="$arg"; expect_l=false; continue; fi
	if [ "$expect_rho" = true ]; then rho="$arg"; expect_rho=false; continue; fi
	case "$arg" in
		-L|--L) expect_l=true ;;
		-L=*|--L=*) explicit_l="${arg#*=}" ;;
		--rho=*|-rho=*) rho="${arg#*=}" ;;
		--rho|-rho) expect_rho=true ;;
	esac
done

case "$rho" in
	1/2) default_l=309 ;;
	1/4) default_l=189 ;;
	1/8) default_l=155 ;;
	*) echo "unsupported RHO: $rho" >&2; exit 2 ;;
esac

if [ -z "$explicit_l" ]; then
	explicit_l="$default_l"
fi
LAMP_RHO="$rho"
LAMP_BATCH_RHO="$rho"
LAMP_L="$explicit_l"
LAMP_BATCH_L="$explicit_l"
export LAMP_RHO LAMP_BATCH_RHO LAMP_L LAMP_BATCH_L

range=false
batch_range=false
args=""
matrix_dir="${LAMP_MATRIX_DIR:-matrices}"
repeat_override=""
expect_repeat=false
expect_matrix_dir=false
for arg in "$@"; do
	if [ "$expect_repeat" = true ]; then
		repeat_override="$arg"
		expect_repeat=false
		if [ -z "$repeat_override" ]; then
			echo "repeat requires a positive integer" >&2
			exit 2
		fi
		continue
	fi
	if [ "$expect_matrix_dir" = true ]; then
		matrix_dir="$arg"
		expect_matrix_dir=false
		continue
	fi
	case "$arg" in
		--repeat|-repeat)
			expect_repeat=true
			;;
		--repeat=*|-repeat=*)
			repeat_override="${arg#*=}"
			if [ -z "$repeat_override" ]; then
				echo "repeat requires a positive integer" >&2
				exit 2
			fi
			;;
		--matrix-dir|-matrix-dir)
			expect_matrix_dir=true
			;;
		--matrix-dir=*|-matrix-dir=*)
			matrix_dir="${arg#*=}"
			;;
		--range|--all)
			range=true
			;;
		--batch-range)
			batch_range=true
			;;
		*)
			if [ -z "$args" ]; then
				args="$arg"
			else
				args="$args $arg"
			fi
			;;
	esac
done
if [ "$expect_repeat" = true ]; then
	echo "repeat requires a positive integer" >&2
	exit 2
fi
if [ -n "$repeat_override" ]; then
	case "$repeat_override" in
		*[!0-9]*) echo "repeat requires a positive integer" >&2; exit 2 ;;
	esac
	if ! [ "$repeat_override" -ge 1 ] 2>/dev/null; then
		echo "repeat must be a positive integer" >&2
		exit 2
	fi
fi

if [ "$expect_matrix_dir" = true ] || [ -z "$matrix_dir" ]; then
	echo "matrix-dir requires a directory" >&2
	exit 2
fi

is_true() {
	case "${1:-}" in
		1|true|TRUE|yes|YES|on|ON) return 0 ;;
		*) return 1 ;;
	esac
}

flag_value() {
	wanted="$1"
	value="$2"
	shift 2
	want_value=false
	for arg in "$@"; do
		if [ "$want_value" = true ]; then
			value="$arg"
			want_value=false
			continue
		fi
		case "$arg" in
			"$wanted") want_value=true ;;
			"$wanted"=*) value="${arg#*=}" ;;
		esac
	done
	printf '%s\n' "$value"
}

case "$target" in
	lamp|lamp_batch|freivalds|freivalds_batch|all)
		;;
	*)
		usage
		;;
esac

mkdir -p "$matrix_dir"
matrix_dir="$(CDPATH= cd "$matrix_dir" && pwd)"
docker build -t "$image" .

env_args="--env-file .env"

for key in \
	LAMP_REPEAT LAMP_LOG_K LAMP_RHO LAMP_L LAMP_ALL LAMP_ONLY_COMPILE LAMP_OUTPUT_DIR LAMP_LOG_K_FROM LAMP_LOG_K_TO \
	LAMP_BATCH_REPEAT LAMP_BATCH_LOG_K LAMP_BATCH_RHO LAMP_BATCH_L LAMP_BATCH_SIZE LAMP_BATCH_ALL LAMP_BATCH_RANGE LAMP_BATCH_ONLY_COMPILE LAMP_BATCH_OUTPUT_DIR LAMP_BATCH_LOG_K_FROM LAMP_BATCH_LOG_K_TO LAMP_BATCH_FROM LAMP_BATCH_TO \
	FREIVALDS_REPEAT FREIVALDS_LOG_K FREIVALDS_ALL FREIVALDS_ONLY_COMPILE FREIVALDS_OUTPUT_DIR FREIVALDS_LOG_K_FROM FREIVALDS_LOG_K_TO \
	FREIVALDS_BATCH_REPEAT FREIVALDS_BATCH_LOG_K FREIVALDS_BATCH_SIZE FREIVALDS_BATCH_ALL FREIVALDS_BATCH_RANGE FREIVALDS_BATCH_ONLY_COMPILE FREIVALDS_BATCH_OUTPUT_DIR FREIVALDS_BATCH_LOG_K_FROM FREIVALDS_BATCH_LOG_K_TO FREIVALDS_BATCH_FROM FREIVALDS_BATCH_TO
do
	value="$(eval "printf '%s' \"\${$key:-}\"")"
	if [ -n "$value" ]; then
		env_args="$env_args -e $key=$value"
	fi
done

output_dir_for() {
	case "$1" in
		lamp)
			printf '%s\n' "${LAMP_OUTPUT_DIR:-benchmark/lamp}"
			;;
		lamp_batch)
			printf '%s\n' "${LAMP_BATCH_OUTPUT_DIR:-benchmark/lamp_batch}"
			;;
		freivalds)
			printf '%s\n' "${FREIVALDS_OUTPUT_DIR:-benchmark/freivalds}"
			;;
		freivalds_batch)
			printf '%s\n' "${FREIVALDS_BATCH_OUTPUT_DIR:-benchmark/freivalds_batch}"
			;;
	esac
}

run_process() {
	protocol="$1"
	append_results="$2"
	shift 2
	if [ -n "$repeat_override" ]; then set -- "$@" --repeat "$repeat_override"; fi
	# No CPU or memory limit is applied: the one benchmark process may use all
	# resources available to Docker. Calls stay sequential because no job is
	# backgrounded.
	# shellcheck disable=SC2086
	docker run --rm $env_args \
		-e BENCHMARK_APPEND_CSV="$append_results" \
		-e LAMP_MATRIX_SOURCE="${LAMP_MATRIX_SOURCE:-auto}" \
		-e LAMP_MATRIX_DIR=/workspace/matrices \
		-v "$(pwd)/benchmark:/workspace/benchmark" \
		-v "$matrix_dir:/workspace/matrices:ro" \
		"$image" "/usr/local/bin/$protocol" $args "$@"
}

run_protocol() {
	protocol="$1"
	output_dir="$(output_dir_for "$protocol")"
	if [ -n "$output_dir" ]; then
		mkdir -p "$output_dir"
	fi

	log_range="$range"
	protocol_batch_range="$batch_range"
	case "$protocol" in
		lamp)
			is_true "${LAMP_ALL:-false}" && log_range=true
			log_k="$(flag_value --K "${LAMP_LOG_K:-10}" $args)"
			log_from="$(flag_value --from "${LAMP_LOG_K_FROM:-7}" $args)"
			log_to="$(flag_value --to "${LAMP_LOG_K_TO:-13}" $args)"
			;;
		freivalds)
			is_true "${FREIVALDS_ALL:-false}" && log_range=true
			log_k="$(flag_value --K "${FREIVALDS_LOG_K:-10}" $args)"
			log_from="$(flag_value --from "${FREIVALDS_LOG_K_FROM:-7}" $args)"
			log_to="$(flag_value --to "${FREIVALDS_LOG_K_TO:-13}" $args)"
			;;
		lamp_batch)
			is_true "${LAMP_BATCH_ALL:-false}" && log_range=true
			is_true "${LAMP_BATCH_RANGE:-false}" && protocol_batch_range=true
			log_k="$(flag_value --K "${LAMP_BATCH_LOG_K:-7}" $args)"
			log_from="$(flag_value --from "${LAMP_BATCH_LOG_K_FROM:-7}" $args)"
			log_to="$(flag_value --to "${LAMP_BATCH_LOG_K_TO:-13}" $args)"
			batch_size="$(flag_value --batch "${LAMP_BATCH_SIZE:-5}" $args)"
			batch_from="$(flag_value --batch-from "${LAMP_BATCH_FROM:-1}" $args)"
			batch_to="$(flag_value --batch-to "${LAMP_BATCH_TO:-10}" $args)"
			;;
		freivalds_batch)
			is_true "${FREIVALDS_BATCH_ALL:-false}" && log_range=true
			is_true "${FREIVALDS_BATCH_RANGE:-false}" && protocol_batch_range=true
			log_k="$(flag_value --K "${FREIVALDS_BATCH_LOG_K:-7}" $args)"
			log_from="$(flag_value --from "${FREIVALDS_BATCH_LOG_K_FROM:-7}" $args)"
			log_to="$(flag_value --to "${FREIVALDS_BATCH_LOG_K_TO:-13}" $args)"
			batch_size="$(flag_value --batch "${FREIVALDS_BATCH_SIZE:-5}" $args)"
			batch_from="$(flag_value --batch-from "${FREIVALDS_BATCH_FROM:-1}" $args)"
			batch_to="$(flag_value --batch-to "${FREIVALDS_BATCH_TO:-10}" $args)"
			;;
	esac

	if [ "$log_range" = false ] && [ "$protocol_batch_range" = false ]; then
		if [ "$protocol" = lamp_batch ] || [ "$protocol" = freivalds_batch ]; then
			run_process "$protocol" false --all=false --batch-range=false
		else
			run_process "$protocol" false --all=false
		fi
		return
	fi

	if [ "$log_range" = false ]; then
		log_from="$log_k"
		log_to="$log_k"
	fi
	if [ "$protocol_batch_range" = false ]; then
		batch_from="${batch_size:-1}"
		batch_to="${batch_size:-1}"
	fi

	append_results=false
	current_log_k="$log_from"
	while [ "$current_log_k" -le "$log_to" ]; do
		if [ "$protocol" = lamp_batch ] || [ "$protocol" = freivalds_batch ]; then
			current_batch="$batch_from"
			while [ "$current_batch" -le "$batch_to" ]; do
				run_process "$protocol" "$append_results" --all=false --batch-range=false --K "$current_log_k" --batch "$current_batch"
				append_results=true
				current_batch=$((current_batch + 1))
			done
		else
			run_process "$protocol" "$append_results" --all=false --K "$current_log_k"
			append_results=true
		fi
		current_log_k=$((current_log_k + 1))
	done
}

case "$target" in
	lamp)
		run_protocol lamp
		;;
	lamp_batch)
		run_protocol lamp_batch
		;;
	freivalds)
		run_protocol freivalds
		;;
	freivalds_batch)
		run_protocol freivalds_batch
		;;
	all)
		run_protocol lamp
		run_protocol lamp_batch
		run_protocol freivalds
		run_protocol freivalds_batch
		;;
esac
