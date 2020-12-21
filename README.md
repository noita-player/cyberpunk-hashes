# hashing hook
we've got over 1mb of missing file hashes right now. snazz's code hooks one location where filenames are hashed, however there's a bunch more.

there's a function in cyberpunk that partially looks like this:
```
.text:00000001400C2580 48 83 EC 28                                         sub     rsp, 28h
.text:00000001400C2584 49 B8 25 23 22 84 E4 9C F2 CB                       mov     r8, 0CBF29CE484222325h
.text:00000001400C258E 48 8D 05 13 9C 13 03                                lea     rax, aBaseCharacters_7 ; "base/characters/base_entities/woman_big"...
.text:00000001400C2595 B2 62                                               mov     dl, 62h
.text:00000001400C2597 49 B9 B3 01 00 00 00 01 00 00                       mov     r9, 100000001B3h
```

it's the fnv hash used throughout the program for fast string lookup. sometimes it's used via a discrete function call, other times it's inlined.

so this hooks every mov of the constant `0CBF29CE484222325h`, the strategy used is:

* write a pointer to `trampoline.w` at the end of the .text section, so a relative call can call that pointer.
* search and replace `mov     reg, 0CBF29CE484222325h` with `call [that_pointer]` - 407 times in current build
* log string to file

important note, because this is a midfunction hook, we have to preserve registers (including SSE and rflags). that code's in trampoline.w and fairly brittle.

in our hook, we iterate all general purpose registers and try to find the string that's getting hashed...

because of that, one of the problems right now is that we need to determine if a register points to valid memory. IsBadReadPtr uses an exception handler which is very slow, and angers their crash handler if no debugger attached. that can be better. so we have CMemoryMap, where I tried two schemes - very slow update() to construct a fast lookup, takes ~15sec to run. alternatively, we can sparsely update the memory map for each pointer. I've seen perf between <1ms and >800ms, very hard to measure... but the game runs...

## todo

- [x] trampoline.w working for most (all?) hook locations
- [ ] need to validate more than the first few bytes of pointers, periodic crashes there

## build / usage

build release for x64, use Snazz's bink2w64.dll to load this, log written to hooklog.txt & hookstrings.txt

### thanks
* [brick's mem library for pattern scanning](https://github.com/0x1F9F1/mem)
* [fmtlib for better output](https://github.com/fmtlib/fmt)
* [cgranges interval tree for fast memory map lookup](https://github.com/lh3/cgranges)
* [robin-hood-hashing for performant hashmaps](https://github.com/martinus/robin-hood-hashing)
* [google sparsehash for the same](https://github.com/sparsehash/sparsehash-c11)