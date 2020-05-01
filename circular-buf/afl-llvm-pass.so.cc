/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.
*/

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"
#include "llvm-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

using namespace llvm;

namespace {

class AFLCoverage : public ModulePass {

public:
  static char ID;
  AFLCoverage() : ModulePass(ID) {}

  bool runOnModule(Module &M) override;

  // StringRef getPassName() const override {
  //  return "American Fuzzy Lop Instrumentation";
  // }
};

} // namespace

char AFLCoverage::ID = 0;

bool AFLCoverage::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *IntLocTy =
      IntegerType::getIntNTy(C, sizeof(PREV_LOC_T) * CHAR_BIT);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST
              " by <lszekeres@google.com, adrian.herrera@anu.edu.au,"
              " hendra.gunadi@anu.edu.au>\n");

  } else
    be_quiet = 1;

  /* Decide instrumentation ratio */

  char *inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");
  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, IntLocTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
      /* Initializer */ nullptr, "__afl_prev_loc",
      /* InsertBefore */ nullptr, GlobalVariable::GeneralDynamicTLSModel,
      /* AddressSpace */ 0, /* IsExternallyInitialized */ false);

  /* Decide the number of previous edges to maintain */

  char *ngram_size_str = getenv("AFL_NGRAM_SIZE");
  unsigned int ngram_size = 3;

  if (ngram_size_str) {
    if (sscanf(ngram_size_str, "%u", &ngram_size) != 1 || ngram_size < 2 ||
        ngram_size > MAX_NGRAM_SIZE) {
      FATAL(
          "Bad value of AFL_NGRAM_SIZE (must be between 2 and MAX_NGRAM_SIZE)");
    }
  }

  unsigned HistSize = ngram_size - 1;

  /* Pointer to a circular buffer containing the history of the last N block
     transitions (i.e., edges) traversed */
  GlobalVariable *AFLEdgeHistPtr = new GlobalVariable(
      M, IntLocTy->getPointerTo(), /* isConstant */ false,
      GlobalValue::ExternalLinkage, /* Initializer */ nullptr,
      "__afl_edge_hist_ptr", /* InsertBefore */ nullptr,
      GlobalVariable::GeneralDynamicTLSModel, /* AddressSpace */ 0,
      /* IsExternallyInitialized */ false);

  /* Index into the edge history circular buffer. Points to the oldest element
     in the buffer */
  GlobalVariable *AFLEdgeHistIdx = new GlobalVariable(
      M, IntLocTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
      /* Initializer */ nullptr, "__afl_edge_hist_idx",
      /* InsertBefore */ nullptr, GlobalVariable::GeneralDynamicTLSModel,
      /* AddressSpace */ 0, /* IsExternallyInitialized */ false);

  /* Accumulator for maintaining the rolling hash of the last N block
     transitions (i.e. edges). Because  all of the edges are xor-ed together,
     removing the oldest edge just involves an xor of the oldest value in the
     circular buffer */
  GlobalVariable *AFLPrevEdgeAcc = new GlobalVariable(
      M, IntLocTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
      /* Initializer */ nullptr, "__afl_prev_edge_acc",
      /* InsertBefore */ nullptr, GlobalVariable::GeneralDynamicTLSModel,
      /* AddressSpace */ 0, /* IsExternallyInitialized */ false);

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M)
    for (auto &BB : F) {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

      if (AFL_R(100) >= inst_ratio)
        continue;

      /* Make up cur_loc */

      unsigned int cur_loc = AFL_R(MAP_SIZE);
      ConstantInt *CurLoc = ConstantInt::get(IntLocTy, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Compute the current edge's hash */

      Value *CurEdge = IRB.CreateXor(CurLoc, PrevLoc);

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* The index into the bitmap is the current edge xor-ed with the
         accumulation of the previous N edges right-shifted by one */

      LoadInst *PrevEdgeAcc = IRB.CreateLoad(AFLPrevEdgeAcc);
      PrevEdgeAcc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      Value *PrevEdgeAccRightShift = IRB.CreateLShr(PrevEdgeAcc, (uint64_t)1);

      Value *MapPtrIdx = IRB.CreateGEP(
          MapPtr,
          IRB.CreateZExt(IRB.CreateXor(CurEdge, PrevEdgeAccRightShift), Int32Ty));

      /* Update bitmap */

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Get the edge to replace in the circular buffer. This edge is the oldest
         edge stored in the buffer */

      LoadInst *EdgeHistPtr = IRB.CreateLoad(AFLEdgeHistPtr);
      EdgeHistPtr->setMetadata(M.getMDKindID("nosanitize"),
                               MDNode::get(C, None));

      LoadInst *EdgeHistIdx = IRB.CreateLoad(AFLEdgeHistIdx);
      EdgeHistIdx->setMetadata(M.getMDKindID("nosanitize"),
                               MDNode::get(C, None));

      Value *EdgeHistPtrIdx = IRB.CreateGEP(EdgeHistPtr, EdgeHistIdx);

      LoadInst *OldestEdge = IRB.CreateLoad(EdgeHistPtrIdx);
      OldestEdge->setMetadata(M.getMDKindID("nosanitize"),
                              MDNode::get(C, None));

      /* Update the accumulation of the previous edges with the current edge */

      Value *NewPrevEdgeAcc = IRB.CreateXor(PrevEdgeAccRightShift, CurEdge);

      /* Remove the oldest edge from the accumulated previous edges. This can be
         done by right-shifting the oldest edge by the size of the history
         circular buffer (because this is the number of times that the previous
         edges have been shifted) and xor-ing the result with the accumulator */

      NewPrevEdgeAcc = IRB.CreateXor(
          NewPrevEdgeAcc, IRB.CreateLShr(OldestEdge, (uint64_t)HistSize));

      IRB.CreateStore(NewPrevEdgeAcc, AFLPrevEdgeAcc)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Store the current edge in edge history circular buffer, overwritting
         the oldest edge */

      IRB.CreateStore(CurEdge, EdgeHistPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Update the edge history circulr buffer index. Just use modulo to
         ensure that the index wraps around apppropriately */

      Value *NewEdgeHistIdx = IRB.CreateURem(
          IRB.CreateAdd(EdgeHistIdx, ConstantInt::get(IntLocTy, 1)),
          ConstantInt::get(IntLocTy, HistSize));

      IRB.CreateStore(NewEdgeHistIdx, AFLEdgeHistIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Set prev_loc to cur_loc */

      IRB.CreateStore(CurLoc, AFLPrevLoc)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;
    }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else
      OKF("Instrumented %u locations (%s mode, ratio %u%%).", inst_blocks,
          getenv("AFL_HARDEN")
              ? "hardened"
              : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN"))
                     ? "ASAN/MSAN"
                     : "non-hardened"),
          inst_ratio);
  }

  return true;
}

static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());
}

static RegisterStandardPasses
    RegisterAFLPass(PassManagerBuilder::EP_ModuleOptimizerEarly,
                    registerAFLPass);

static RegisterStandardPasses
    RegisterAFLPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                     registerAFLPass);
