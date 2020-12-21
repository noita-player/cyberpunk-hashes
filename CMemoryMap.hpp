#pragma once
#include <chrono>
#include <atomic>
#include <windows.h>

// https://github.com/lh3/cgranges
#include <IITree.hpp>
#include <robin_hood/robin_hood.h>

#define READABLE(prot) (prot & PAGE_READWRITE || prot & PAGE_READONLY || prot & PAGE_EXECUTE_READWRITE)

/*
    alternative to isbadreadptr
    regions of [low, high) memory in an interval tree for fast search
    [perf] memorymap cold init took: 14351ms
    [perf] memorymap hot update took: 13499ms on average over 100 iters
*/
class CMemoryMap
{
public:
    IITree<size_t, size_t> *valid_ranges;
    typedef robin_hood::unordered_flat_set<size_t, robin_hood::hash<size_t>> t_bad_ptrs;
    t_bad_ptrs bad_ptrs;

    std::atomic_flag lck = ATOMIC_FLAG_INIT;
    size_t num_regions = 0;
    
#define TIME_IDX_MAX 100
    std::chrono::microseconds time_list[TIME_IDX_MAX];
    size_t time_idx = 0;
    
    CMemoryMap() {
        this->update();
    };
    ~CMemoryMap() {
        MessageBoxA(NULL, "should not happen", "should not happen", NULL);
    }

    void lock() { while (lck.test_and_set(std::memory_order_acquire)) {} };
    void unlock() { lck.clear(std::memory_order_release); };

    bool valid_pointer(size_t ptr, size_t size) {
        bool result = false;
        // we want to include the spinlock, intentionally
        auto t1 = std::chrono::high_resolution_clock::now();
        lock();

        // do the check
        if (this->cached_query(ptr, size))
            result = true; 

        // keep a ringbuffer of N time measurements to log periodically
        auto t2 = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1);
        time_list[time_idx] = duration;
        time_idx = (time_idx + 1) % TIME_IDX_MAX;
        if (time_idx == 0) num_regions = 0;

        unlock();
        return result;
    };

    // ptr is either in a known valid range, fast lookup, done.
    // or it is a known bad ptr, fast lookup, done.
    // or we need to virtualquery and add its region as a valid range, SLOW.
    bool cached_query(size_t ptr, size_t size) {
        bool result = false;
        MEMORY_BASIC_INFORMATION region;
        if (valid_ranges->any_overlap(ptr, ptr+size)) {
            result = true;
        }
        else {
            // don't spam virtualquery for known bad ptrs
            //auto bad_iter = bad_ptrs.find(ptr);
            if (!bad_ptrs.contains(ptr)) {
                auto res = VirtualQuery((void*)ptr, &region, sizeof(region));
                if (res == 0 || !READABLE(region.Protect)) {
                    bad_ptrs.insert(ptr);
                } else {
                    num_regions++;
                    valid_ranges->add(
                        (size_t)region.BaseAddress,
                        (size_t)(((size_t)region.BaseAddress) + region.RegionSize),
                        ptr);
                    valid_ranges->index();
                    result = true;
                }
            }
        }

        return result;
    };

    // currently just reinitializes the sets, used to walk entire memmap
    void update() {
        valid_ranges = new IITree<size_t, size_t>();
        valid_ranges->add(0x41414141, 0x41414142, 0);
        valid_ranges->index();
        bad_ptrs.clear();
        return;

        // old shit, in case we ever want to go back to 15sec mem map updates
        lock();
        num_regions = 0;
        valid_ranges = new IITree<size_t, size_t>();
        char* address = nullptr;
        MEMORY_BASIC_INFORMATION region;

        while (VirtualQuery(address, &region, sizeof(region)))
        {
            ++num_regions;
            if (region.Protect == PAGE_READWRITE || 
                region.Protect == PAGE_READONLY || 
                region.Protect == PAGE_EXECUTE_READWRITE) 
                valid_ranges->add((size_t)address, (size_t)(address + region.RegionSize), 0);
            address += region.RegionSize;
        }
        unlock();
    };

    long long avg_lookup() {
        std::chrono::microseconds duration_sum {0};
        for (int i = 0; i < TIME_IDX_MAX; i++) {
            duration_sum += time_list[i];
        }
        return duration_sum.count() / TIME_IDX_MAX;
    }
};

