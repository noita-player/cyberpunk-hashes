#include "main.h"

uint64_t fnv_hash(char* ptr) {
    uint64_t result = 0xCBF29CE484222325;
    char curchar = 0;
    while (*ptr) {
        curchar = *ptr;
        if (curchar == '/') {
            curchar = 0x5C; // '\' char
        }
        else if (curchar - 65 <= 0x19) {
            curchar += 32; // lowercase
        }
        ++ptr;
        result = 0x100000001B3 * (result ^ curchar);

        // skip repeated backslashes
        if (curchar == 0x5C) {
            while (*ptr == '/' || *ptr == '\\')
                ++ptr;
        }
    }
    return result;
}

// so that I may avoid demangling...
extern "C" void hash_hook(CPU_STATE* cpustate) {
    grab_strings(cpustate);
}

// midfunc hook of inlined hash start:
//         mov     r64, 0CBF29CE484222325h
int place_hash_hook(size_t addr) {
    // verify a relative access will even work
    size_t delta = (size_t)g_pTrampoline - addr;
    g_pOutfile->print("[place_hash_hook] hook @ {0:X} tramp @ {1:X} delta @ {2:X} tramp points to {3:X} tramp at {4:X}\n",
        addr, (size_t)g_pTrampoline, delta,
        *(size_t*)g_pTrampoline, (size_t)&trampoline);
    if (delta > 0xFFFFFFFF) {
        MessageBoxA(0, "hook failed due to mem map try again", "hook failed due to mem map try again", 0);
        g_pOutfile->print("[place_hash_hook] hook @ {0:X} tramp @ {1:X} delta @ {2:X}", addr, (size_t)g_pTrampoline, delta);
        g_pOutfile->close();
        exit(0);
    }
    
    // if we haven't, store the original opcode for the hook to emulate
    if (addr_to_opcode.find(addr) == addr_to_opcode.end())
        addr_to_opcode[addr] = *(uint16_t*)addr;
    
    // make writable
    DWORD oldprot = 0;
    if (0 == VirtualProtect((LPVOID)addr, 10, PAGE_EXECUTE_READWRITE, &oldprot)) {
        MessageBoxA(0, "failed to make hook writable", "failed to make hook writable", 0);
    }

    // call [ptr]
    unsigned char instrs[10] = { 0 };
    memset(instrs, 0x90, 10);

    instrs[0] = 0xff; // call qword ptr [
    instrs[1] = 0x15;

    // calculate relative call from game to our dll, it's relative to the address after this instruction (6 bytes)
    int32_t relative_loc = (int32_t) (((size_t)g_pTrampoline) - addr - 6);
    // little endian
    instrs[2] = relative_loc & 0xff;
    instrs[3] = (relative_loc >> 8) & 0xff;
    instrs[4] = (relative_loc >> 16) & 0xff;
    instrs[5] = (relative_loc >> 24) & 0xff;

    memcpy((void*)addr, instrs, sizeof(instrs));

    // restore perms
    if (0 == VirtualProtect((LPVOID)addr, 10, oldprot, &oldprot)) {
        MessageBoxA(0, "faled to restore perms", "failed to restore perms", 0);
    }
    return 0;
}

// have we already handled this string? if so, skip it
bool cache_seen(size_t ptr) {
    bool result = false;
    auto charptr = (const char*)ptr;
    g_seenlock.lock();
    if (seen_strings.find(charptr) != seen_strings.end()) {
        result = true;
    }
    else {
        seen_strings.insert((const char*)(charptr)); // perfperf: strdup...
    }

    g_seenlock.unlock();
    return result;
}

// insert the found string or skip it
void insert_string(size_t ptr) {
    g_loglock.lock();
    if (!cache_seen(ptr)) {
        auto fnv = fnv_hash((char*)ptr);
        // we will have multiple threads trying to write, synchronize them (perfbug?)
        g_pOutstrs->print("--st{0}--fnv--{1}--ed\n", (const char*)ptr, fnv);
        //g_pOutfile->flush();
        //g_memmap->time_idx = g_memmap->time_idx;
        if (missing_hashes.contains(fnv)) {
            MessageBoxA(0, "missing_hashes.contains(fnv)", "missing_hashes.contains(fnv)", 0);
        }
    }
    g_loglock.unlock();
}

bool valid_ascii(char c) {
    // space to ~
    return c > 0x1F && c < 0x7F;
}

bool is_ptr_to_string(size_t ptr) {
#define MAX_STRLEN 0x300
    if (g_memmap->time_idx % 100 == 99) {
        g_pOutfile->print("avg lookup: {0} ms, {1} vq calls\n", g_memmap->avg_lookup(), g_memmap->num_regions);
    }
    // not a valid ptr
    if (!g_memmap->valid_pointer(ptr, 4)) return false;
    

    char* iter = (char*)ptr;
    uint32_t iterpos = 0;
    while ( valid_ascii(*(iter+iterpos)) ) {
        iterpos++;

        if (iterpos > MAX_STRLEN)
            return false;
    }

    // throw out strings that end in some non-ascii shit for now
    if (*(iter + iterpos) != 0)
        return false;

    // arbitrary limit to track less garbage strings
    if (iterpos <= 8 || iterpos > MAX_STRLEN) {
        return false;
    }

    return true;
}

// modify the cpustate as if the originally hooked instruction actually ran
void __fastcall emulate_original(CPU_STATE* cpustate) {
    auto find_rip = addr_to_opcode.find(cpustate->rip);
    if (find_rip == addr_to_opcode.end()) {
        MessageBoxA(0, "hook called from unknown RIP", "hook called from unknown RIP", 0);
        exit(0);
    }

    uint16_t opcode = (*find_rip).second;

#define HANDLE_REG(reg,op) \
    case op: \
        *(&(cpustate->reg)) = 0xCBF29CE484222325; \
        break

    switch (opcode) {
        HANDLE_REG(rax, 0xB848);
        HANDLE_REG(rbx, 0xBB48);
        HANDLE_REG(rcx, 0xB948);
        HANDLE_REG(rdx, 0xBA48);
        HANDLE_REG(rdi, 0xBF48);
        HANDLE_REG(rsi, 0xBE48);
        HANDLE_REG(r8,  0xB849);
        HANDLE_REG(r9,  0xB949);
        HANDLE_REG(r10, 0xBA49);
        HANDLE_REG(r11, 0xBB49);
        HANDLE_REG(r12, 0xBC49); // not actually used 1.0.4
        HANDLE_REG(r13, 0xBD49);
        HANDLE_REG(r14, 0xBE49);
        HANDLE_REG(r15, 0xBF49);
    default:
        auto errstrpp = fmt::format("unhandled opcode: {0:X} at {1:X}", opcode, cpustate->rip);
        auto errstr   = errstrpp.c_str();
        MessageBoxA(0, errstr, errstr, 0);
        exit(0);
        break;
    }
}

#define GRAB_REG(x) if (cpustate->x != 0 && cpustate->x > 0x1000 && is_ptr_to_string(cpustate->x)) { insert_string(cpustate->x); }
void __fastcall grab_strings(CPU_STATE* cpustate) {
    /* debug crashes 
    g_loglock.lock();
    g_pOutfile->print("grab_strings via {0:x} - rel: {1:x}\n", cpustate->rip,
        cpustate->rip-g_mainmodule);
    g_pOutfile->flush();
    g_loglock.unlock();
    */

    // string pointer could be in any reg
    GRAB_REG(rax);
    GRAB_REG(rbx);
    GRAB_REG(rcx);
    GRAB_REG(rdx);
    GRAB_REG(rsi);
    GRAB_REG(rdi);
    GRAB_REG(r8);
    GRAB_REG(r9);
    GRAB_REG(r10);
    GRAB_REG(r11);
    GRAB_REG(r12);
    GRAB_REG(r13);
    GRAB_REG(r14);
    GRAB_REG(r15);

    auto check_instr = [](size_t rip) {
        // in certain cases the string is loaded after the hashing constant is mov'd
        // let's do this instead of adding a disassembler
        size_t next_instr = rip;
        // if it's a `lea r64, rel32` instr...
        if (*(uint8_t*)(next_instr) == 0x48) {
            // calculate the rel32 location, bugbug: if it occurs earlier in mem, will break, should not atm
            size_t strloc = (next_instr + 7) + (size_t) * (uint32_t*)(next_instr + 2);
            // save it off
            if (is_ptr_to_string(strloc)) {
                insert_string(strloc);
            }
        }
    };

    check_instr(cpustate->rip + 10);
    check_instr(cpustate->rip - 13); // ff 14 xx xx xx xx + 48 8d 05 ae 1f b6 02

    emulate_original(cpustate);
}


DWORD WINAPI hookthread(LPVOID lpParam) {
    // reduce memory shuffling
    seen_strings.reserve(500'000);
    missing_hashes.reserve(500'000);

    // load hashes we're looking for
    std::ifstream missinghashesfile("missinghashes.txt");
    if (!missinghashesfile.is_open()) {
        MessageBoxA(0, "missinghashes.txt missing, place next to dll", "missinghashes.txt missing, place next to dll", 0);
        exit(0);
    }
    uint64_t curhash = 0;
    while (missinghashesfile >> curhash) {
        missing_hashes.insert(curhash);
    }

    auto outfile = new fmt::ostream("hooklog.txt", fmt::detail::ostream_params());
    auto outstrs = new fmt::ostream("hookstrings.txt", fmt::detail::ostream_params());
    g_pOutfile = outfile;
    g_pOutstrs = outstrs;
    
    outfile->print("init with {0} missing hashes\n", missing_hashes.size());

    // populate the memory map - this is effectively a nop since we've moved from update() to on-check updating
    auto t1 = std::chrono::high_resolution_clock::now();
    g_memmap = new CMemoryMap();
    auto t2 = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
    outfile->print("[perf] memorymap cold init took: {0}ms\n", duration);
    auto avg_t1 = std::chrono::high_resolution_clock::now();
    auto iters = 100;
    for (int i = 0; i < iters; i++) {
        g_memmap->update();
    }
    auto avg_t2 = std::chrono::high_resolution_clock::now();
    auto avg_duration = std::chrono::duration_cast<std::chrono::microseconds>(avg_t2 - avg_t1) / iters;
    outfile->print("[perf] memorymap hot update took: {0}ms on average over {1} iters\n", avg_duration.count(), iters);


    mem::module main_module = mem::module::main();
    g_mainmodule = (size_t)GetModuleHandle(0);
    // mov     rcx, 0CBF29CE484222325h
    mem::pattern pat_hashinit ("4? ? 25 23 22 84 E4 9C F2 CB");
    mem::default_scanner scanner(pat_hashinit);

    main_module.enum_segments([&](mem::region range, mem::prot_flags prot) {
        auto range_start = range.start.as<std::uintptr_t>();
        auto range_end   = range.start.add(range.size).as<std::uintptr_t>();
        outfile->print("Scanning {0}{1}{2} segment {3:x} => {4:x}\n",
            (prot & mem::prot_flags::R) ? 'R' : '-', 
            (prot & mem::prot_flags::W) ? 'W' : '-',
            (prot & mem::prot_flags::X) ? 'X' : '-', 
            range_start, 
            range_end
        );

        // we need to write a 64bit pointer into an unused cave somewhere, within 32bit relative distance of the hooks.
        if (prot & mem::prot_flags::X && g_pTrampoline == nullptr) {
            
            auto addr_codecave = range.start.add(range.size).as<std::uintptr_t>();
            if (memcmp((void*)addr_codecave, cavenulls, cavesize) != 0) {
                outfile->print("WARNING WARNING WARNING WARNING WARNING - code cave is not nulled, did the game change?\n");
            }

            DWORD oldprot = 0;
            VirtualProtect((void*)addr_codecave, cavesize, PAGE_EXECUTE_READWRITE, &oldprot);
            uint64_t* cave = (uint64_t*)addr_codecave;
            *cave = (uint64_t) &trampoline;
            VirtualProtect((void*)addr_codecave, cavesize, oldprot, &oldprot);

            g_pTrampoline = (void*)addr_codecave;

            outfile->print("wrote codecave @ {0:X}\n", addr_codecave);
        }

        // we scan for every mov of the hashing constant and hook it
        uint64_t num_hits = 0;
        scanner(range, [&](mem::pointer address) {
            ++num_hits;
            uintptr_t address_raw = address.as<std::uintptr_t>();

            outfile->print("Found hashing func at {0:x}\n", address_raw);

            place_hash_hook(address_raw);
            return false;
        });
        outfile->print("TOTAL HOOKS: {}\n", num_hits);
        return false;
     });

    outfile->flush();
    return S_OK;
}

// compat with snazz's loader 
__declspec(dllexport) void SetupHooks(void) {
    printf("SetupHooks called\n");
}
extern "C" __declspec(dllexport) void DirectInput8Create() {
    printf("DirectInput8Create called\n");
}
extern "C" __declspec(dllexport) void DllEntryPoint() {
    printf("DllEntryPoint called\n");
}
BOOLEAN WINAPI DllMain(IN HINSTANCE hDllHandle,
    IN DWORD     nReason,
    IN LPVOID    Reserved)
{   
    HANDLE hThread = 0;
    switch (nReason)
    {
    case DLL_PROCESS_ATTACH:
        hThread = CreateThread(NULL, 0, hookthread, 0, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}