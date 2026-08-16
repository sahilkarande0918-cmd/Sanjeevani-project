# Sanjeevani build file.
#
# Compile flags, and why each one is here:
#   -O0                    no optimisation, so decompiled C stays readable
#   -no-pie                fixed load addresses, so patch addresses are stable
#   -fno-stack-protector   no random stack canary; a canary is a random value
#                          angr would have to treat as unknown, which makes the
#                          Phase 2 proof much harder for no benefit
#   -U_FORTIFY_SOURCE      stop glibc swapping strcpy/printf for "checked"
#                          versions that would defuse the very bugs we planted
#   -fcf-protection=none   drop endbr64 padding instructions, less noise
#   -g0                    no debug info (we strip anyway)

CC      := gcc
CFLAGS  := -O0 -no-pie -fno-stack-protector -U_FORTIFY_SOURCE -fcf-protection=none -g0
OUT     := corpus/out
NAMES   := stack_overflow off_by_one format_string

WRONG_NAMES := stack_overflow off_by_one

BROKEN  := $(addprefix $(OUT)/,$(addsuffix .broken,$(NAMES)))
FIXED   := $(addprefix $(OUT)/,$(addsuffix .fixed,$(NAMES)))
WRONG   := $(addprefix $(OUT)/,$(addsuffix .wrong,$(WRONG_NAMES)))

.PHONY: corpus verify-corpus clean setup model smoke deps

# One-time setup. `deps` is the only part needing root and is run separately.
setup:
	bash scripts/setup_python.sh
	bash scripts/setup_build.sh
	bash scripts/setup_downloads.sh

# Root-only step, kept separate so `make setup` never needs sudo.
deps:
	@echo "This step needs root. Run it yourself:"
	@echo "  sudo bash scripts/install_deps.sh"

model:
	bash scripts/fetch_model.sh

smoke:
	@for s in scripts/smoke_*.sh; do \
	  echo "=== $$s ==="; bash $$s || exit 1; echo; \
	done

corpus: $(BROKEN) $(FIXED) $(WRONG)
	@echo "corpus built -> $(OUT)/"

$(OUT)/%.wrong: corpus/wrong/%.c | $(OUT)
	$(CC) $(CFLAGS) -o $@ $<
	strip $@

$(OUT)/%.broken: corpus/%.c | $(OUT)
	$(CC) $(CFLAGS) -o $@ $<
	strip $@

$(OUT)/%.fixed: corpus/fixed/%.c | $(OUT)
	$(CC) $(CFLAGS) -o $@ $<
	strip $@

$(OUT):
	mkdir -p $(OUT)

# Acceptance check: every .broken must crash, every .fixed must survive.
verify-corpus: corpus
	@bash scripts/verify_corpus.sh

clean:
	rm -rf $(OUT)
