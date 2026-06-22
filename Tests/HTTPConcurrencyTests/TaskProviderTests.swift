//
//  TaskProviderTests.swift
//  HTTPConcurrencyTests
//
//  The shipped default `LiveTaskProvider` forwards transparently to `Task.init` for both the
//  non-throwing and throwing operation forms, regardless of role.
//

import HTTPConcurrency
import Testing

@Suite("LiveTaskProvider")
struct TaskProviderTests {

    @Test
    func `runs a non-throwing operation and returns its value`() async {
        let provider = LiveTaskProvider()
        let task = provider.task { 41 + 1 }
        #expect(await task.value == 42)
    }

    @Test
    func `forwards a throwing operation's error`() async {
        let provider = LiveTaskProvider()
        let task: Task<Int, any Error> = provider.task { throw CancellationError() }
        await #expect(throws: CancellationError.self) { try await task.value }
    }

    @Test
    func `runs regardless of role`() async {
        let provider = LiveTaskProvider()
        let task = provider.task(role: .observation) { "ok" }
        #expect(await task.value == "ok")
    }
}
