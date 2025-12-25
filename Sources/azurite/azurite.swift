import ArgumentParser
import Foundation

@main
struct Azurite: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "azurite",
        abstract: "A Copper archive management tool",
        discussion: """
            Azurite is a command-line tool for creating and managing Copper archives.
            """,
        version: "1.0.0",
        subcommands: [
            Create.self,
            Add.self,
            Extract.self,
            List.self,
            Remove.self,
            Compact.self,
            Info.self
        ]
    )
}

// MARK: - Create Command

extension Azurite {
    struct Create: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Create a new Copper archive"
        )
        
        @Argument(help: "Path to the archive file to create")
        var archivePath: String
        
        @Argument(help: "Files to add to the archive")
        var files: [String] = []
        
        @Option(name: .shortAndLong, help: "Compression algorithm (none, zlib, gzip, lz4, zstd)")
        var compression: String = "none"
        
        @Option(name: .shortAndLong, help: "Encryption algorithm (none, aes256)")
        var encryption: String = "none"
        
        @Option(name: .shortAndLong, help: "Encryption key (if using encryption)")
        var key: String?
        
        func run() throws {
            // Parse compression algorithm
            let compressionAlgo: CopperCompressionAlgorithm
            switch compression.lowercased() {
            case "none": compressionAlgo = .none
            case "zlib": compressionAlgo = .zlib
            case "gzip": compressionAlgo = .gzip
            case "lz4": compressionAlgo = .lz4
            case "zstd": compressionAlgo = .zstd
            default:
                print("Error: Invalid compression algorithm '\(compression)'")
                throw ExitCode.validationFailure
            }
            
            // Parse encryption algorithm
            let encryptionAlgo: CopperEncryptionAlgorithm
            switch encryption.lowercased() {
            case "none": encryptionAlgo = .none
            case "aes256": encryptionAlgo = .aes256
            default:
                print("Error: Invalid encryption algorithm '\(encryption)'")
                throw ExitCode.validationFailure
            }
            
            // Get encryption key if needed
            var encryptionKey: Data?
            if encryptionAlgo != .none {
                guard let keyString = key else {
                    print("Error: Encryption key required when using encryption")
                    throw ExitCode.validationFailure
                }
                encryptionKey = keyString.data(using: .utf8)
            }
            
            // Create archive
            print("Creating archive at \(archivePath)...")
            var archive = CopperArchive.createNew(
                compressionAlgorithm: compressionAlgo,
                encryptionAlgorithm: encryptionAlgo,
                encryptionKey: encryptionKey
            )
            
            // Add files if provided
            if !files.isEmpty {
                print("Adding \(files.count) file(s)...")
                for file in files {
                    do {
                        try archive.addFile(at: file)
                        print("  Added: \(file)")
                    } catch {
                        print("  Failed: \(file): \(error)")
                    }
                }
            }
            
            // Write archive to disk
            try archive.writeToFile(path: archivePath)
            print("Archive created successfully")
        }
    }
}

// MARK: - Add Command

extension Azurite {
    struct Add: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Add files to an existing archive"
        )
        
        @Argument(help: "Path to the archive file")
        var archivePath: String
        
        @Argument(help: "Files to add to the archive")
        var files: [String]
        
        @Option(name: .shortAndLong, help: "Encryption key (if archive is encrypted)")
        var key: String?
        
        func run() throws {
            let encryptionKey = key?.data(using: .utf8)
            
            // Open archive
            print("Opening archive at \(archivePath)...")
            var archive = try CopperArchive.open(path: archivePath, encryptionKey: encryptionKey)
            
            // Reopen for writing
            guard let handle = FileHandle(forWritingAtPath: archivePath) else {
                print("Error: Cannot open archive for writing")
                throw ExitCode.failure
            }
            archive.fileHandle = handle
            
            // Add files
            print("Adding \(files.count) file(s)...")
            for file in files {
                do {
                    try archive.addFile(at: file)
                    print("  Added: \(file)")
                } catch {
                    print("  Failed: \(file): \(error)")
                }
            }
            
            // Save changes
            try archive.save()
            try handle.close()
            
            print("Files added successfully")
        }
    }
}

// MARK: - Extract Command

extension Azurite {
    struct Extract: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Extract files from an archive"
        )
        
        @Argument(help: "Path to the archive file")
        var archivePath: String
        
        @Option(name: .shortAndLong, help: "Output directory (default: current directory)")
        var output: String = "."
        
        @Option(name: .shortAndLong, help: "Specific file to extract (if not provided, extracts all)")
        var file: String?
        
        @Option(name: .shortAndLong, help: "Encryption key (if archive is encrypted)")
        var key: String?
        
        func run() throws {
            let encryptionKey = key?.data(using: .utf8)
            
            // Open archive
            print("Opening archive at \(archivePath)...")
            let archive = try CopperArchive.open(path: archivePath, encryptionKey: encryptionKey)
            
            if let filename = file {
                // Extract single file
                print("Extracting \(filename)...")
                let outputPath = (output as NSString).appendingPathComponent(filename)
                try archive.extractFile(filename: filename, toPath: outputPath)
                print("Extracted to \(outputPath)")
            } else {
                // Extract all files
                print("Extracting all files to \(output)...")
                try archive.extractAll(toDirectory: output)
                print("Extracted \(archive.totalFiles()) file(s)")
            }
        }
    }
}

// MARK: - List Command

extension Azurite {
    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "List files in an archive"
        )
        
        @Argument(help: "Path to the archive file")
        var archivePath: String
        
        @Option(name: .shortAndLong, help: "Encryption key (if archive is encrypted)")
        var key: String?
        
        @Flag(name: .shortAndLong, help: "Show detailed information")
        var verbose: Bool = false
        
        func run() throws {
            let encryptionKey = key?.data(using: .utf8)
            
            // Open archive
            let archive = try CopperArchive.open(path: archivePath, encryptionKey: encryptionKey)
            
            if verbose {
                print("Archive: \(archivePath)")
                print("Files: \(archive.totalFiles())")
                
                if archive.compressionEnabled {
                    let algo = archive.compressionAlgorithm
                    print("Compression: \(algo)")
                }
                
                if archive.encryptionEnabled {
                    let algo = archive.encryptionAlgorithm
                    print("Encryption: \(algo)")
                }
                
                print("")
            }
            
            // Get current user name
            let username = ProcessInfo.processInfo.environment["USER"] ?? "user"
            
            // List files in eza-style format
            for entry in archive.fileEntries {
                let date = Date(timeIntervalSince1970: TimeInterval(entry.timestamp))
                let formatter = DateFormatter()
                formatter.dateFormat = "EEE MMM dd HH:mm:ss yyyy"
                let dateString = formatter.string(from: date)
                
                let perms = formatPermissions(entry.permissions)
                let size = formatSize(entry.length)
                
                print("\(perms) \(username) \(size) \(dateString) -- \(entry.filename)")
            }
        }
        
        private func formatPermissions(_ perms: UInt16) -> String {
            // Archives don't store directories separately, so always file
            var result = "."
            
            // Owner permissions
            result += (perms & 0o400) != 0 ? "r" : "-"
            result += (perms & 0o200) != 0 ? "w" : "-"
            result += (perms & 0o100) != 0 ? "x" : "-"
            
            // Group permissions
            result += (perms & 0o040) != 0 ? "r" : "-"
            result += (perms & 0o020) != 0 ? "w" : "-"
            result += (perms & 0o010) != 0 ? "x" : "-"
            
            // Other permissions
            result += (perms & 0o004) != 0 ? "r" : "-"
            result += (perms & 0o002) != 0 ? "w" : "-"
            result += (perms & 0o001) != 0 ? "x" : "-"
            
            return result
        }
        
        private func formatSize(_ bytes: UInt64) -> String {
            if bytes < 1024 {
                return String(format: "%3d B", bytes)
            }
            
            let kb = Double(bytes) / 1024.0
            if kb < 1024.0 {
                return String(format: "%3.0f KB", kb)
            }
            
            let mb = kb / 1024.0
            if mb < 1024.0 {
                return String(format: "%3.1f MB", mb)
            }
            
            let gb = mb / 1024.0
            return String(format: "%3.1f GB", gb)
        }
        
        private func formatBytes(_ bytes: UInt64) -> String {
            let kb = Double(bytes) / 1024.0
            let mb = kb / 1024.0
            let gb = mb / 1024.0
            
            if gb >= 1.0 {
                return String(format: "%.2f GB", gb)
            } else if mb >= 1.0 {
                return String(format: "%.2f MB", mb)
            } else if kb >= 1.0 {
                return String(format: "%.2f KB", kb)
            } else {
                return "\(bytes) B"
            }
        }
    }
}

// MARK: - Remove Command

extension Azurite {
    struct Remove: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Remove files from an archive"
        )
        
        @Argument(help: "Path to the archive file")
        var archivePath: String
        
        @Argument(help: "Files to remove from the archive")
        var files: [String]
        
        @Option(name: .shortAndLong, help: "Encryption key (if archive is encrypted)")
        var key: String?
        
        func run() throws {
            let encryptionKey = key?.data(using: .utf8)
            
            // Open archive
            print("Opening archive at \(archivePath)...")
            var archive = try CopperArchive.open(path: archivePath, encryptionKey: encryptionKey)
            
            // Remove files
            print("Removing \(files.count) file(s)...")
            for file in files {
                do {
                    try archive.removeFile(filename: file)
                    print("  Removed: \(file)")
                } catch {
                    print("  Failed: \(file): \(error)")
                }
            }
            
            // Save changes
            try archive.save()
            
            print("Files removed successfully")
        }
    }
}

// MARK: - Compact Command

extension Azurite {
    struct Compact: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Compact an archive to eliminate fragmentation"
        )
        
        @Argument(help: "Path to the archive file")
        var archivePath: String
        
        @Option(name: .shortAndLong, help: "Encryption key (if archive is encrypted)")
        var key: String?
        
        func run() throws {
            let encryptionKey = key?.data(using: .utf8)
            
            // Open archive
            print("Opening archive at \(archivePath)...")
            var archive = try CopperArchive.open(path: archivePath, encryptionKey: encryptionKey)
            
            // Reopen for writing
            guard let handle = FileHandle(forWritingAtPath: archivePath) else {
                print("Error: Cannot open archive for writing")
                throw ExitCode.failure
            }
            archive.fileHandle = handle
            
            // Compact
            print("Compacting archive...")
            try archive.compactArchive()
            try handle.close()
            
            print("Archive compacted successfully")
        }
    }
}

// MARK: - Info Command

extension Azurite {
    struct Info: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Show detailed information about an archive"
        )
        
        @Argument(help: "Path to the archive file")
        var archivePath: String
        
        @Option(name: .shortAndLong, help: "Encryption key (if archive is encrypted)")
        var key: String?
        
        func run() throws {
            let encryptionKey = key?.data(using: .utf8)
            
            // Open archive
            let archive = try CopperArchive.open(path: archivePath, encryptionKey: encryptionKey)
            
            let date = Date(timeIntervalSince1970: TimeInterval(archive.header.timestamp))
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
            let dateString = formatter.string(from: date)
            
            // Calculate total size
            var totalSize: UInt64 = 0
            for entry in archive.fileEntries {
                totalSize += entry.length
            }
            
            print("Archive Information")
            print(String(repeating: "=", count: 80))
            print("Path: \(archivePath)")
            print("Version: \(CopperHeader.version)")
            print("Created: \(dateString)")
            print("Files: \(archive.totalFiles())")
            print("Total Size: \(formatBytes(totalSize))")
            
            print("\nCompression: ", terminator: "")
            if archive.compressionEnabled {
                print("\(archive.compressionAlgorithm)")
            } else {
                print("None")
            }
            
            print("Encryption: ", terminator: "")
            if archive.encryptionEnabled {
                print("\(archive.encryptionAlgorithm)")
            } else {
                print("None")
            }
            
            print("\nOffsets:")
            print("  File Entry Section: \(archive.header.fileEntryOffset)")
            print("  Data Section: \(archive.header.dataOffset)")
            
            if !archive.freeSpaces.isEmpty {
                print("\nFree Spaces: \(archive.freeSpaces.count)")
                var totalFree: UInt64 = 0
                for space in archive.freeSpaces {
                    totalFree += space.length
                }
                print("  Total Free: \(formatBytes(totalFree))")
            }
        }
        
        private func formatBytes(_ bytes: UInt64) -> String {
            let kb = Double(bytes) / 1024.0
            let mb = kb / 1024.0
            let gb = mb / 1024.0
            
            if gb >= 1.0 {
                return String(format: "%.2f GB", gb)
            } else if mb >= 1.0 {
                return String(format: "%.2f MB", mb)
            } else if kb >= 1.0 {
                return String(format: "%.2f KB", kb)
            } else {
                return "\(bytes) B"
            }
        }
    }
}