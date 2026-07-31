//
//  FileResponder+Autoindex.swift
//  HTTPServer
//
//  Opt-in directory autoindex for ``FileResponder`` (off by default). Renders a traversal-safe HTML
//  listing of one directory — name, size, mtime — HTML-escaping every entry name so a crafted filename
//  cannot inject markup (XSS). Dotfiles are omitted. Only reached when `autoindex` is enabled and the
//  directory has no `index.html`.
//
//  The listing is read from the ALREADY-VERIFIED directory descriptor (`fdopendir` on a duplicate of it,
//  `fstatat(AT_SYMLINK_NOFOLLOW)` per entry), never by re-opening a pathname, so it cannot be redirected
//  by a concurrent rename and cannot follow a symlink out of the root (CWE-59, CWE-367). Only regular
//  files and directories are listed: a symlink, FIFO, or device node is not servable, so advertising one
//  would only be a broken link.
//
//  Standards: fdopendir()/readdir()/fstatat() per POSIX.1-2017 (IEEE Std 1003.1-2017).
//

internal import HTTPCore

#if canImport(Darwin)
    internal import Darwin
#elseif canImport(Glibc)
    internal import Glibc
#endif

extension FileResponder {
    /// One rendered directory entry.
    typealias Entry = (name: String, isDirectory: Bool, size: Int, modified: Int)

    /// A `200` HTML listing of `directory` (the head only for a HEAD request).
    func autoindexResponse(
        _ directory: OpenedDirectory,
        requestPath: String,
        omitBody: Bool
    ) -> ServerResponse {
        let html = Self.renderAutoindex(requestPath: requestPath, entries: Self.entries(directory))
        let body = Array(html.utf8)
        var head = HTTPResponse(status: .ok)
        _ = head.headerFields.setValue("text/html; charset=utf-8", for: .contentType)
        _ = head.headerFields.setValue(String(body.count), for: .contentLength)
        return ServerResponse(head, body: omitBody ? [] : body)
    }

    /// The non-hidden regular-file and directory entries of `directory`, sorted by name.
    ///
    /// `fdopendir` takes ownership of the descriptor it is given and `closedir` closes it, so it is handed
    /// a duplicate — the ``OpenedDirectory`` keeps owning its own.
    private static func entries(_ directory: OpenedDirectory) -> [Entry] {
        let copy = POSIXFile.duplicate(directory.descriptor)
        guard copy >= 0 else {
            return []
        }
        guard let stream = fdopendir(copy) else {
            POSIXFile.release(copy)
            return []
        }
        defer { closedir(stream) }
        var entries: [Entry] = []
        while let record = readdir(stream) {
            guard let entry = Self.entry(record, in: directory) else {
                continue
            }
            entries.append(entry)
        }
        return entries.sorted { $0.name < $1.name }
    }

    /// One listable entry for `record`, or nil for a dotfile or anything that is not servable.
    private static func entry(
        _ record: UnsafeMutablePointer<dirent>,
        in directory: OpenedDirectory
    ) -> Entry? {
        // `d_name` is a NUL-terminated fixed-size array; an entry whose name is not valid UTF-8 yields
        // nil here and is skipped rather than mangled into the listing.
        let text = withUnsafeBytes(of: &record.pointee.d_name) { raw -> String? in
            raw.baseAddress.flatMap {
                String(validatingCString: $0.assumingMemoryBound(to: CChar.self))
            }
        }
        guard let text, !text.isEmpty, !text.hasPrefix(".") else {
            return nil
        }
        var info = stat()
        let probed = text.withCString {
            fstatat(directory.descriptor, $0, &info, AT_SYMLINK_NOFOLLOW)
        }
        guard probed == 0 else {
            return nil
        }
        let kind = info.st_mode & S_IFMT
        guard kind == S_IFREG || kind == S_IFDIR else {
            return nil  // a symlink, FIFO, or device node is not servable — never advertise it
        }
        return (text, kind == S_IFDIR, Int(info.st_size), POSIXFile.modificationTime(of: info))
    }

    /// Renders the listing as an HTML document, escaping every entry name (XSS-safe).
    private static func renderAutoindex(requestPath: String, entries: [Entry]) -> String {
        let title = htmlEscaped(requestPath)
        var html = "<!DOCTYPE html>\n"
        html += "<html><head><meta charset=\"utf-8\"><title>Index of \(title)</title></head>\n"
        html += "<body><h1>Index of \(title)</h1>\n"
        html += "<table><tr><th>Name</th><th>Size</th><th>Last modified</th></tr>\n"
        for entry in entries {
            let display = entry.isDirectory ? entry.name + "/" : entry.name
            let href = htmlEscaped(join(requestPath, display))
            let name = htmlEscaped(display)
            let size = entry.isDirectory ? "-" : String(entry.size)
            html += "<tr><td><a href=\"\(href)\">\(name)</a></td>"
            html += "<td>\(size)</td><td>\(HTTPDate.imfFixdate(entry.modified))</td></tr>\n"
        }
        html += "</table></body></html>\n"
        return html
    }

    /// Joins a request path and an entry name with exactly one slash.
    private static func join(_ requestPath: String, _ name: String) -> String {
        requestPath.hasSuffix("/") ? requestPath + name : requestPath + "/" + name
    }

    /// HTML-escapes `&`, `<`, `>`, `"` so a crafted filename cannot inject markup (XSS).
    private static func htmlEscaped(_ string: String) -> String {
        var out = ""
        out.reserveCapacity(string.count)
        for character in string {
            switch character {
                case "&":
                    out += "&amp;"
                case "<":
                    out += "&lt;"
                case ">":
                    out += "&gt;"
                case "\"":
                    out += "&quot;"
                default:
                    out.append(character)
            }
        }
        return out
    }
}
