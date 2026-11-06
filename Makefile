CC ?= cc
PREFIX ?= /usr/local
DESTDIR ?=
BUILD ?= build
CPPFLAGS += -Iinclude
CFLAGS ?= -O2 -g
CFLAGS += -std=c17 -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong -fPIE
LDFLAGS += -Wl,-z,relro,-z,now,-z,noexecstack
STATIC ?= 0
ifeq ($(STATIC),1)
LDFLAGS += -static
else
LDFLAGS += -pie
endif
SOURCES := $(wildcard src/*.c)
OBJECTS := $(patsubst src/%.c,$(BUILD)/%.o,$(SOURCES))

.PHONY: all clean test test-all test-legacy check install package benchmark
all: $(BUILD)/cincta $(BUILD)/adversary

$(BUILD):
	mkdir -p $@

$(BUILD)/%.o: src/%.c include/cincta.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD)/cincta: $(OBJECTS)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

$(BUILD)/adversary: tests/adversary.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) -o $@

ifneq ($(strip $(TESTFLAGS)),)
# Backwards compatibility: TESTFLAGS targets the original suite only.
test: test-legacy
else
test: test-all
endif

test-legacy: all
	python3 tests/integration.py --binary $(BUILD)/cincta --helper $(BUILD)/adversary $(TESTFLAGS)

test-all: all
	BUILD=$(BUILD) sh scripts/test_all.sh $(or $(TEST_LABEL),native)

check: all
	PYTHONPYCACHEPREFIX=$(BUILD)/pycache python3 -m py_compile $(wildcard tests/*.py) $(wildcard scripts/*.py) $(wildcard examples/*.py)
	for script in scripts/*.sh; do sh -n "$$script" || exit; done

benchmark: all
	python3 scripts/benchmark.py --binary $(BUILD)/cincta

package: all
	sh scripts/package.sh $(BUILD)/cincta

install: $(BUILD)/cincta
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $< $(DESTDIR)$(PREFIX)/bin/cincta

clean:
	rm -rf $(BUILD)

-include $(OBJECTS:.o=.d)
