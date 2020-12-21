#pragma once
#include <windows.h>
#include <mem/mem.h>
#include <mem/utils.h>
#include <mem/macros.h>

#include <mem/data_buffer.h>
#include <mem/slice.h>

#include <mem/init_function.h>

#include <mem/cmd_param.h>
#include <mem/cmd_param-inl.h>

#include <mem/pattern.h>
#include <mem/pattern_cache.h>

#include <mem/simd_scanner.h>
#include <mem/boyer_moore_scanner.h>

#include <mem/prot_flags.h>
#include <mem/protect.h>

#include <mem/module.h>
#include <mem/aligned_alloc.h>
#include <mem/execution_handler.h>

#include <mem/macros.h>

#include <vector>
#include <cstdio>
#include <algorithm>
#include <functional>
#include <atomic>
#include <chrono>
#include <fstream>

#include <CMemoryMap.hpp>

// google sparsehash
#include <sparsehash/dense_hash_set>
#include <sparsehash/sparse_hash_map>

// faster it seems https://github.com/martinus/robin-hood-hashing
#include <robin_hood/robin_hood.h>

// we keep a persistent map of opcodes we've hooked, to use them in grab_strings -> emulate_original
typedef robin_hood::unordered_map<size_t, uint16_t> t_addr_opcode_map;
t_addr_opcode_map addr_to_opcode;

typedef robin_hood::unordered_flat_set<const char*, robin_hood::hash<const char*>> t_string_set;
t_string_set seen_strings;

typedef robin_hood::unordered_flat_set<uint64_t, robin_hood::hash<uint64_t>> t_missing_hashes;
t_missing_hashes missing_hashes;


// https://github.com/fmtlib/fmt
#include <fmt/format.h>
#include <fmt/core.h>
#include <fmt/os.h>
#include <fmt/ostream.h>

class SpinLock
{
public:
    void lock() { while (lck.test_and_set(std::memory_order_acquire)) {} }

    void unlock() { lck.clear(std::memory_order_release); }

private:
    std::atomic_flag lck = ATOMIC_FLAG_INIT;
};

// fetch state from australia
typedef struct {
    size_t r15;
    size_t r14;
    size_t r13;
    size_t r12;
    size_t r11;
    size_t r10;
    size_t r9;
    size_t r8;
    size_t rdi;
    size_t rsi;
    size_t rbp;
    size_t rdx;
    size_t rcx;
    size_t rbx;
    size_t rax;
    size_t rip;
    size_t flags;
} CPU_STATE;

// some constants for our trampoline
constexpr size_t cavesize = 0x100;
const char cavenulls[cavesize] = { 0 };
size_t g_mainmodule = 0;
void* g_pTrampoline = nullptr;
SpinLock g_loglock;
SpinLock g_seenlock;
fmt::ostream* g_pOutfile = nullptr;
fmt::ostream* g_pOutstrs = nullptr;
CMemoryMap* g_memmap{ nullptr };

extern "C" void trampoline();

uint64_t fnv_hash(char* ptr);
bool cache_seen(size_t ptr);
bool valid_ascii(char c);
bool is_ptr_to_string(size_t ptr);
void grab_strings(CPU_STATE* cpustate);
void __fastcall emulate_original(CPU_STATE* cpustate);
int place_hash_hook(size_t addr);
extern "C" void hash_hook(CPU_STATE* cpustate);
DWORD WINAPI hookthread(LPVOID lpParam);
