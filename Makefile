# Convenience wrapper around CMake / test / fuzz workflows.
# CMake is still the source of truth for the actual build.

BUILD_DIR   ?= build
CMAKE_FLAGS ?=
JOBS        ?= $(shell (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu || echo 4)
PORT        ?= 8081

.PHONY: help build vulnerable asan hardened rebuild clean run test exploit-check hardening-check fuzz docker docker-fuzz format

help:
	@echo "Damn Vulnerable Web Server -- Make targets"
	@echo ""
	@echo "  make build             configure + build (vulnerable, default)"
	@echo "  make vulnerable        alias for 'make build'"
	@echo "  make asan              rebuild with -DENABLE_ASAN=ON"
	@echo "  make hardened          rebuild with -DENABLE_HARDENING=ON"
	@echo "  make rebuild           blow away build/ and reconfigure"
	@echo "  make clean             remove build/"
	@echo ""
	@echo "  make run PORT=8081     run the server on \$$PORT serving ./serve"
	@echo ""
	@echo "  make test              run exploit regression + hardening tests"
	@echo "  make exploit-check     run exploit regression tests only"
	@echo "  make hardening-check   verify PIE flag behavior for both builds"
	@echo ""
	@echo "  make fuzz              build the AFL++ fuzz image and start fuzzing"
	@echo "  make docker            build the challenge server image"
	@echo "  make docker-fuzz       build the fuzzing image only"
	@echo ""
	@echo "  make format            apply .clang-format to all sources"

$(BUILD_DIR)/CMakeCache.txt:
	cmake -S . -B $(BUILD_DIR) $(CMAKE_FLAGS)

build vulnerable: $(BUILD_DIR)/CMakeCache.txt
	cmake --build $(BUILD_DIR) -j $(JOBS)

asan:
	cmake -S . -B $(BUILD_DIR) -DENABLE_ASAN=ON -DENABLE_HARDENING=OFF
	cmake --build $(BUILD_DIR) -j $(JOBS)

hardened:
	cmake -S . -B $(BUILD_DIR) -DENABLE_HARDENING=ON -DENABLE_ASAN=OFF
	cmake --build $(BUILD_DIR) -j $(JOBS)

rebuild: clean build

clean:
	rm -rf $(BUILD_DIR)

run: build
	$(BUILD_DIR)/damn_vulnerable_web_server ./serve $(PORT)

exploit-check: build
	python3 tests/exploit/run_all.py

hardening-check:
	python3 tests/test_hardening.py

test: exploit-check

fuzz: docker-fuzz
	mkdir -p fuzz_output
	docker run --rm -v $$(pwd)/fuzz_output:/src/fuzz/out vuln-server-fuzz

docker-fuzz:
	docker build -t vuln-server-fuzz -f docker/Dockerfile.fuzz .

docker:
	docker build -t vuln-server-serve -f docker/Dockerfile.serve .

format:
	@command -v clang-format >/dev/null || { echo "clang-format not installed"; exit 1; }
	find . -type f \( -name '*.cpp' -o -name '*.h' \) \
	    -not -path './build/*' \
	    -not -path './.git/*' \
	    -print0 | xargs -0 clang-format -i
