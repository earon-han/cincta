CC ?= cc
PREFIX ?= /usr/local
DESTDIR ?=
STATIC ?= 0
BUILD ?= $(if $(filter 1,$(STATIC)),build-static,build)
CPPFLAGS += -Iinclude
CFLAGS ?= -O2 -g
CFLAGS += -std=c17 -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong -fPIE
LDFLAGS += -Wl,-z,relro,-z,now,-z,noexecstack
ifeq ($(STATIC),1)
LDFLAGS += -static
else
LDFLAGS += -pie
endif
SOURCES := $(wildcard src/*.c)
OBJECTS := $(patsubst src/%.c,$(BUILD)/%.o,$(SOURCES))

.PHONY: all clean test test-all test-legacy check install package benchmark FORCE
all: $(BUILD)/cincta $(BUILD)/adversary

$(BUILD):
	mkdir -p $@

# Record effective compiler/linker options even when callers reuse BUILD.
# Keep the stamp unchanged for identical settings so incremental builds work.
$(BUILD)/.build-config: export CONFIG_CC := $(CC)
$(BUILD)/.build-config: export CONFIG_CPPFLAGS := $(CPPFLAGS)
$(BUILD)/.build-config: export CONFIG_CFLAGS := $(CFLAGS)
$(BUILD)/.build-config: export CONFIG_LDFLAGS := $(LDFLAGS)
$(BUILD)/.build-config: export CONFIG_STATIC := $(STATIC)
$(BUILD)/.build-config: FORCE | $(BUILD)
	@printf '%s\n' "CC=$$CONFIG_CC" "CPPFLAGS=$$CONFIG_CPPFLAGS" "CFLAGS=$$CONFIG_CFLAGS" "LDFLAGS=$$CONFIG_LDFLAGS" "STATIC=$$CONFIG_STATIC" > $@.tmp
	@cmp -s $@.tmp $@ && rm $@.tmp || mv $@.tmp $@

FORCE:

# Compare saved settings per output as well as timestamps: older make versions
# can observe the same timestamp for two builds that switch options quickly.
$(BUILD)/%.o: src/%.c include/cincta.h $(BUILD)/.build-config FORCE | $(BUILD)
	@if [ ! -f $@ ] || ! cmp -s $(BUILD)/.build-config $@.config || [ -n "$(filter-out FORCE $(BUILD)/.build-config,$?)" ]; then \
	  $(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@ && cp $(BUILD)/.build-config $@.config; \
	fi

$(BUILD)/cincta: $(OBJECTS) $(BUILD)/.build-config FORCE
	@if [ ! -f $@ ] || ! cmp -s $(BUILD)/.build-config $@.config || [ -n "$(filter-out FORCE $(BUILD)/.build-config,$?)" ]; then \
	  $(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o $@ && cp $(BUILD)/.build-config $@.config; \
	fi

$(BUILD)/adversary: tests/adversary.c $(BUILD)/.build-config FORCE | $(BUILD)
	@if [ ! -f $@ ] || ! cmp -s $(BUILD)/.build-config $@.config || [ -n "$(filter-out FORCE $(BUILD)/.build-config,$?)" ]; then \
	  $(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) -o $@ && cp $(BUILD)/.build-config $@.config; \
	fi

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

package:
	$(MAKE) BUILD=build-release STATIC=1 all
	sh scripts/package.sh build-release/cincta

install: $(BUILD)/cincta
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $< $(DESTDIR)$(PREFIX)/bin/cincta

clean:
	rm -rf $(BUILD)

-include $(OBJECTS:.o=.d)
