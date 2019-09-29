#ifndef LLVM_CONFIG_H
#define LLVM_CONFIG_H

/* n-gram n value. Note that n includes the current block, so it must be at
   least 1. */

#ifndef NGRAM_SIZE
#define NGRAM_SIZE 5
#endif

#define TUPLE_HISTORY_COUNT ((NGRAM_SIZE)-1)

#endif
