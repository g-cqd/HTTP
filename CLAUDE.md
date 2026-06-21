Goal: HTTP server from scratch, in Swift

Tech Stack: HTTP1,2,3
Closest to the hardware, linux is not a priority at all, swift idiomatic, meaningful dsl, minimal api surface
Performance requirements: 200k rps, Minimal Memory and Allocation, Failsafe, reliable
Possible framework usage: github(apple/*,swiftlang/*) - no Swift nio reliance

Swift stack: swift 6.4, macos floor 15.6, ios floor 18, strict memory, strict concurrency, lifetime experimental, strictest settings on all packages and subpackages, no force unwrap, no force casting, avoid as Any

TDD driven: red then green

1 file per type, max line per file 400 unless justification

use swift format with strictest rules, use swift lint for additional rules and strictness

tests should leverage parametrized tests, backtick function names, and remove the suite decorator when unnecessary

we can omit return statement when possible

avoid double allocation, or extra allocation, avoid paying the copy-on-write tax

privilege zero copy and multithreading, use span and rawspan and prefer native apis and non-copy-bytes-manipulating apis (with lifetime)
