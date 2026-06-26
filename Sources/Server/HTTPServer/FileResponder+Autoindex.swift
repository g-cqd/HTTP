//
//  FileResponder+Autoindex.swift
//  HTTPServer
//
//  Opt-in directory autoindex for ``FileResponder`` (off by default). Renders a traversal-safe HTML
//  listing of one directory — name, size, mtime — HTML-escaping every entry name so a crafted filename
//  cannot inject markup (XSS). Dotfiles are omitted. Only reached when `autoindex` is enabled and the
//  directory has no `index.html`.
//

internal import Foundation
internal import HTTPCore

extension FileResponder {
    /// A `200` HTML listing of `directory` (the head only for a HEAD request).
    func autoindexResponse(
        _ directory: String,
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

    /// The non-hidden entries of `directory`, sorted by name (each with kind, size, mtime).
    private static func entries(
        _ directory: String
    ) -> [(name: String, isDirectory: Bool, size: Int, modified: Int)] {
        let manager = FileManager.default
        guard let names = try? manager.contentsOfDirectory(atPath: directory) else {
            return []
        }
        var entries: [(name: String, isDirectory: Bool, size: Int, modified: Int)] = []
        for name in names.sorted() where !name.hasPrefix(".") {
            let full = directory + "/" + name
            var isDirectory: ObjCBool = false
            guard manager.fileExists(atPath: full, isDirectory: &isDirectory) else {
                continue
            }
            let attributes = try? manager.attributesOfItem(atPath: full)
            let size = (attributes?[.size] as? Int) ?? 0
            let date = attributes?[.modificationDate] as? Date
            let modified = Int(date?.timeIntervalSince1970 ?? 0)
            entries.append((name, isDirectory.boolValue, size, modified))
        }
        return entries
    }

    /// Renders the listing as an HTML document, escaping every entry name (XSS-safe).
    private static func renderAutoindex(
        requestPath: String,
        entries: [(name: String, isDirectory: Bool, size: Int, modified: Int)]
    ) -> String {
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
