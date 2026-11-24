//
//  AemiTestKitReexports.swift
//  HTTPTestSupport
//
//  Re-exports the shared deterministic test primitives from `AemiTestKit` (`Allocations`,
//  `AsyncGate`, `ThreadGate`, `ConstrainedStack`, `DepthSweep`, `SeededRNG`, `Seed`,
//  `TestClock`, `AsyncEventProbe`, `TaskProviderSpy`, `ByteMutator`, `deallocationProbe`, etc.)
//  while keeping HTTP-specific test doubles (`DribblingConnection`, `HangingConnection`,
//  `SynthesizedUploadConnection`, `SharedDevTLSIdentity`, `RealNetworkPermits`, `Oracles`)
//  locally in `HTTPTestSupport`.
//

@_exported public import AemiTestKit
