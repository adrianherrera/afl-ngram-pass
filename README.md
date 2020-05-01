# AFL N-Gram Branch Coverage

This is an LLVM-based implementation of the n-gram branch coverage proposed in
the paper ["Be Sensitive and Collaborative: Analzying Impact of Coverage Metrics
in Greybox Fuzzing"](https://www.usenix.org/system/files/raid2019-wang-jinghan.pdf),
by Jinghan Wang, et. al.

Note that the original implementation (available
[here](https://github.com/bitsecurerlab/afl-sensitive)) is built on top of AFL's
QEMU mode. This is essentially a port that uses LLVM vectorized instructions to
achieve the same results when compiling source code.

## Usage

Simply copy the source files from **either** `circular-buf` or `vectorized` into
AFL's `llvm_mode` directory and build `afl-clang-fast` as normal.

The size of `n` (i.e., the number of branches to remember) is an option that can
be specified in the `AFL_NGRAM_SIZE` environment variable.
