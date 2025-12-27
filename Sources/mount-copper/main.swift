import ArgumentParser
import Copper
import Foundation
import Cfuse
#if os(Linux)
import Glibc
#else
import Darwin
#endif

// Global reference to the archive for C callbacks
// REVIEW: Global state makes testing difficult and limits this to a single mount per process.
// Consider passing context via fuse_init or using a singleton manager that maps paths/IDs to instances.
nonisolated(unsafe) var globalContext: MountContext?

class MountContext {
    var archive: CopperArchive
    var entryMap: [String: CopperFileEntry] = [:]
    var dirMap: [String: Set<String>] = [:]
    let uid: uid_t = getuid()
    let gid: gid_t = getgid()
    let tempDir: URL
    
    // REVIEW: Coarse-grained locking. Consider read/write locks or finer-grained locking for better concurrency.
    // Using a concurrent queue allows multiple readers but exclusive writers (barrier).
    private let queue = DispatchQueue(label: "com.azurite.mount", attributes: .concurrent)
    
    init(archive: CopperArchive, tempDir: URL) {
        self.archive = archive
        self.tempDir = tempDir
        buildDirectoryStructure()
    }
    
    func getEntry(_ path: String) -> CopperFileEntry? {
        queue.sync { entryMap[path] }
    }
    
    func setEntry(_ path: String, entry: CopperFileEntry) {
        queue.sync(flags: .barrier) { 
            entryMap[path] = entry 
        }
    }
    
    func removeEntry(_ path: String) {
        queue.sync(flags: .barrier) { 
            _ = entryMap.removeValue(forKey: path) 
        }
    }
    
    func getDirChildren(_ path: String) -> Set<String>? {
        queue.sync { dirMap[path] }
    }
    
    func isDir(_ path: String) -> Bool {
        queue.sync { path == "/" || dirMap[path] != nil }
    }
    
    func addDirChild(parent: String, child: String) {
        queue.sync(flags: .barrier) {
            if dirMap[parent] == nil { dirMap[parent] = [] }
            _ = dirMap[parent]?.insert(child)
        }
    }
    
    func removeDirChild(parent: String, child: String) {
        queue.sync(flags: .barrier) {
            _ = dirMap[parent]?.remove(child)
        }
    }
    
    func createDir(_ path: String) {
        queue.sync(flags: .barrier) {
            if dirMap[path] == nil { dirMap[path] = [] }
        }
    }
    
    func removeDir(_ path: String) {
        queue.sync(flags: .barrier) {
            _ = dirMap.removeValue(forKey: path)
        }
    }
    
    // Helper to execute a block with exclusive access to archive
    func withArchive<T>(_ block: (inout CopperArchive) throws -> T) rethrows -> T {
        try queue.sync(flags: .barrier) {
            try block(&archive)
        }
    }
    
    // Helper to execute a block with shared access to archive (if CopperArchive was thread-safe for reads, which it isn't fully due to file handle seeking)
    // Since CopperArchive uses a shared file handle and seeks, we must use exclusive lock for any archive operation.
    
    private func buildDirectoryStructure() {
        // Root directory
        dirMap["/"] = []

        for entry in archive.fileEntries {
            let fullPath = "/" + entry.filename
            entryMap[fullPath] = entry

            // Add to parent directory
            let components = entry.filename.split(separator: "/")
            
            // Handle directories in path
            var currentPath = ""
            for (index, component) in components.enumerated() {
                let parentPath = currentPath.isEmpty ? "/" : currentPath
                let name = String(component)
                
                // Add to parent's list
                if dirMap[parentPath] == nil {
                    dirMap[parentPath] = []
                }
                dirMap[parentPath]?.insert(name)
                
                // Update current path
                if currentPath == "/" {
                    currentPath += name
                } else {
                    currentPath += "/" + name
                }
                
                // If this is a directory (not the last component), ensure it exists in dirMap
                if index < components.count - 1 {
                    if dirMap[currentPath] == nil {
                        dirMap[currentPath] = []
                    }
                }
            }
        }
    }
}

@main
struct MountCopper: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mount-copper",
        abstract: "Mount a Copper archive as a FUSE filesystem"
    )

    @Argument(help: "Path to the Copper archive")
    var archivePath: String

    @Argument(help: "Mount point directory")
    var mountPoint: String

    @Option(name: .shortAndLong, help: "Encryption key (if archive is encrypted)")
    var key: String?

    @Flag(name: .shortAndLong, help: "Run in foreground (debug mode)")
    var foreground: Bool = false

    func run() throws {
        // Resolve paths
        let archiveURL = URL(fileURLWithPath: archivePath).standardized
        let absoluteArchiveURL = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent(archivePath).standardized
        // Use absolute path if possible, otherwise fallback to what we had (though standardized usually handles it)
        let finalArchiveURL = archivePath.hasPrefix("/") ? archiveURL : absoluteArchiveURL
        
        let mountURL = URL(fileURLWithPath: mountPoint).standardized

        // Check if mount point exists
        var isDir: ObjCBool = false
        if !FileManager.default.fileExists(atPath: mountURL.path, isDirectory: &isDir) {
            try FileManager.default.createDirectory(at: mountURL, withIntermediateDirectories: true)
        } else if !isDir.boolValue {
            throw ValidationError("Mount point must be a directory")
        }
        
        // Create temp dir
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("azurite-mount-\(UUID().uuidString)")
        try? FileManager.default.removeItem(at: tempDir)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        // Get salt from archive if it exists
        let salt = try? CopperArchive.getSalt(from: finalArchiveURL.path)

        // Derive key if needed
        let encryptionKey = try key.map { try CopperEncryptionAlgorithm.deriveKey(from: $0, salt: salt) }

        // Open archive
        print("Opening archive \(finalArchiveURL.path)...")
        let archive = try CopperArchive.open(path: finalArchiveURL.path, encryptionKey: encryptionKey)
        
        // Setup global state
        globalContext = MountContext(archive: archive, tempDir: tempDir)

        // Initialize FUSE operations
        var ops = fuse_operations()
        
        // getattr
        ops.getattr = { (path, statbuf, fi) -> Int32 in
            guard let path = path, let statbuf = statbuf else { return -EFAULT }
            guard let context = globalContext else { return -EFAULT }
            let pathStr = String(cString: path)
            
            memset(statbuf, 0, MemoryLayout<stat>.size)
            
            // FIX: Accessing globalDirMap without a lock is not thread-safe.
            if context.isDir(pathStr) {
                // DOCUMENT: 0o755 (rwxr-xr-x) - Standard directory permissions.
                statbuf.pointee.st_mode = S_IFDIR | 0o755
                statbuf.pointee.st_nlink = 2
                statbuf.pointee.st_uid = context.uid
                statbuf.pointee.st_gid = context.gid
                return 0
            }
            
            // Check temp file first for most up-to-date info (e.g. if being written)
            let tempFile = context.tempDir.appendingPathComponent(pathStr)
            var tempStat = stat()
            if stat(tempFile.path, &tempStat) == 0 {
                statbuf.pointee = tempStat
                // Ensure it looks like a regular file
                // DOCUMENT: 0o644 (rw-r--r--) - Standard file permissions.
                statbuf.pointee.st_mode = S_IFREG | 0o644 
                statbuf.pointee.st_uid = context.uid
                statbuf.pointee.st_gid = context.gid
                return 0
            }
            
            // FIX: Accessing globalEntryMap without a lock is not thread-safe.
            if let entry = context.getEntry(pathStr) {
                statbuf.pointee.st_mode = S_IFREG | mode_t(entry.permissions)
                statbuf.pointee.st_nlink = 1
                statbuf.pointee.st_size = off_t(entry.length)
                statbuf.pointee.st_mtim = timespec(tv_sec: Int(entry.timestamp), tv_nsec: 0)
                statbuf.pointee.st_uid = context.uid
                statbuf.pointee.st_gid = context.gid
                return 0
            }
            
            return -ENOENT
        }
        
        // readdir
        ops.readdir = { (path, buf, filler, offset, fi, flags) -> Int32 in
            guard let path = path, let buf = buf, let filler = filler else { return -EFAULT }
            guard let context = globalContext else { return -EFAULT }
            let pathStr = String(cString: path)
            
            _ = filler(buf, ".", nil, 0, fuse_fill_dir_flags(0))
            _ = filler(buf, "..", nil, 0, fuse_fill_dir_flags(0))
            
            // FIX: Accessing globalDirMap without a lock is not thread-safe.
            if let children = context.getDirChildren(pathStr) {
                for child in children {
                    _ = filler(buf, child, nil, 0, fuse_fill_dir_flags(0))
                }
                return 0
            }
            
            return -ENOENT
        }
        
        // open
        ops.open = { (path, fi) -> Int32 in
            guard let path = path else { return -EFAULT }
            guard let context = globalContext else { return -EFAULT }
            let pathStr = String(cString: path)
            
            // FIX: Accessing globalEntryMap without a lock is not thread-safe.
            guard let entry = context.getEntry(pathStr) else { return -ENOENT }
            
            // Extract to temp file
            // REVIEW: Extracting the entire file to a temporary directory on open can be slow for large files and consumes disk space.
            // Consider implementing direct read from archive or block-based caching.
            let tempFile = context.tempDir.appendingPathComponent(pathStr)
            
            // Lock to prevent concurrent extraction of same file or archive seeking
            // archiveLock.lock()
            // defer { archiveLock.unlock() }
            
            if !FileManager.default.fileExists(atPath: tempFile.path) {
                do {
                    // Ensure parent dir exists in temp
                    let parentDir = tempFile.deletingLastPathComponent()
                    try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
                    
                    // Extract
                    try context.withArchive { archive in
                        try archive.extractFile(filename: entry.filename, toPath: tempFile.path)
                    }
                } catch {
                    print("Error extracting \(pathStr): \(error)")
                    return -EIO
                }
            }
            
            return 0
        }
        
        // read
        ops.read = { (path, buf, size, offset, fi) -> Int32 in
            guard let path = path, let buf = buf else { return -EFAULT }
            guard let context = globalContext else { return -EFAULT }
            let pathStr = String(cString: path)
            
            let tempFile = context.tempDir.appendingPathComponent(pathStr)
            
            guard let handle = FileHandle(forReadingAtPath: tempFile.path) else {
                return -EIO
            }
            defer { try? handle.close() }
            
            do {
                try handle.seek(toOffset: UInt64(offset))
                guard let data = try handle.read(upToCount: Int(size)) else {
                    return 0 // EOF
                }
                
                _ = data.withUnsafeBytes { ptr in
                    memcpy(buf, ptr.baseAddress!, data.count)
                }
                
                return Int32(data.count)
            } catch {
                return -EIO
            }
        }

        // access
        ops.access = { (path, mask) -> Int32 in
            return 0
        }
        
        // utimens
        ops.utimens = { (path, tv, fi) -> Int32 in
            return 0
        }

        // chmod
        ops.chmod = { (path, mode, fi) -> Int32 in
            return 0
        }

        // chown
        ops.chown = { (path, uid, gid, fi) -> Int32 in
            return 0
        }
        
        // flush
        ops.flush = { (path, fi) -> Int32 in
            return 0
        }

        // create
        ops.create = { (path, mode, fi) -> Int32 in
            guard let path = path else { return -EFAULT }
            guard let context = globalContext else { return -EFAULT }
            let pathStr = String(cString: path)
            // print("DEBUG: create \(pathStr)")
            let name = String(pathStr.dropFirst()) // Remove leading /
            
            let tempFile = context.tempDir.appendingPathComponent(pathStr)
            
            // Ensure parent directory exists in temp
            let parentDir = tempFile.deletingLastPathComponent()
            try? FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
            
            // Create empty temp file
            if !FileManager.default.createFile(atPath: tempFile.path, contents: nil, attributes: [.posixPermissions: mode]) {
                // print("DEBUG: create failed for \(tempFile.path)")
                return -EACCES
            }
            
            // Update maps
            var entry = CopperFileEntry()
            entry.filename = name
            entry.filenameLength = UInt16(name.utf8.count)
            entry.permissions = UInt16(mode)
            entry.timestamp = UInt64(Date().timeIntervalSince1970)
            entry.length = 0
            
            // FIX: Accessing globalEntryMap without a lock is not thread-safe.
            context.setEntry(pathStr, entry: entry)
            
            // Update parent dir
            let parentPath = (pathStr as NSString).deletingLastPathComponent
            // FIX: Accessing globalDirMap without a lock is not thread-safe.
            context.addDirChild(parent: parentPath, child: (pathStr as NSString).lastPathComponent)
            
            return 0
        }

        // unlink
        ops.unlink = { (path) -> Int32 in
            guard let path = path else { return -EFAULT }
            guard let context = globalContext else { return -EFAULT }
            let pathStr = String(cString: path)
            let name = String(pathStr.dropFirst())
            
            // archiveLock.lock()
            // defer { archiveLock.unlock() }
            
            do {
                try context.withArchive { archive in
                    try archive.removeFile(filename: name)
                    try archive.save()
                }
                
                context.removeEntry(pathStr)
                
                // Update parent dir
                let parentPath = (pathStr as NSString).deletingLastPathComponent
                let fileName = (pathStr as NSString).lastPathComponent
                context.removeDirChild(parent: parentPath, child: fileName)
                
                // Remove temp file
                let tempFile = context.tempDir.appendingPathComponent(pathStr)
                try? FileManager.default.removeItem(at: tempFile)
                
                return 0
            } catch {
                print("Unlink error: \(error)")
                return -ENOENT
            }
        }

        // write
        ops.write = { (path, buf, size, offset, fi) -> Int32 in
            guard let path = path, let buf = buf else { return -EFAULT }
            guard let context = globalContext else { return -EFAULT }
            let pathStr = String(cString: path)
            let tempFile = context.tempDir.appendingPathComponent(pathStr)
            
            guard let handle = FileHandle(forWritingAtPath: tempFile.path) else {
                return -EIO
            }
            defer { try? handle.close() }
            
            do {
                try handle.seek(toOffset: UInt64(offset))
                let data = Data(bytes: buf, count: Int(size))
                try handle.write(contentsOf: data)
                return Int32(size)
            } catch {
                return -EIO
            }
        }
        
        // release (close)
        ops.release = { (path, fi) -> Int32 in
            guard let path = path, let fi = fi else { return -EFAULT }
            guard let context = globalContext else { return -EFAULT }
            let pathStr = String(cString: path)
            let name = String(pathStr.dropFirst())
            
            // Check if opened for write
            let flags = fi.pointee.flags
            if (flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR {
                let tempFile = context.tempDir.appendingPathComponent(pathStr)
                
                if FileManager.default.fileExists(atPath: tempFile.path) {
                    // archiveLock.lock()
                    // defer { archiveLock.unlock() }
                    
                    do {
                        // REVIEW: Re-compressing and re-encrypting the entire file on close is inefficient for small edits.
                        // Also, this operation might be slow and block the release callback.
                        try context.withArchive { archive in
                            try archive.addFile(at: tempFile.path, archiveName: name)
                            try archive.save()
                            
                            // Update entry map from archive
                            if let index = archive.findFileEntry(filename: name) {
                                let entry = archive.fileEntries[index]
                                // FIX: Accessing globalEntryMap without a lock is not thread-safe.
                                context.setEntry(pathStr, entry: entry)
                            }
                        }
                    } catch {
                        print("Save error: \(error)")
                        return -EIO
                    }
                }
            }
            return 0
        }
        
        // mkdir
        ops.mkdir = { (path, mode) -> Int32 in
            guard let path = path else { return -EFAULT }
            guard let context = globalContext else { return -EFAULT }
            let pathStr = String(cString: path)
            
            // FIX: Accessing globalDirMap without a lock is not thread-safe.
            if context.isDir(pathStr) {
                return -EEXIST
            }
            
            context.createDir(pathStr)
            
            // Add to parent
            let parentPath = (pathStr as NSString).deletingLastPathComponent
            let dirName = (pathStr as NSString).lastPathComponent
            context.addDirChild(parent: parentPath, child: dirName)
            
            return 0
        }
        
        // rmdir
        ops.rmdir = { (path) -> Int32 in
            guard let path = path else { return -EFAULT }
            guard let context = globalContext else { return -EFAULT }
            let pathStr = String(cString: path)
            
            if let children = context.getDirChildren(pathStr), !children.isEmpty {
                return -ENOTEMPTY
            }
            
            context.removeDir(pathStr)
            
            // Remove from parent
            let parentPath = (pathStr as NSString).deletingLastPathComponent
            let dirName = (pathStr as NSString).lastPathComponent
            context.removeDirChild(parent: parentPath, child: dirName)
            
            return 0
        }
        
        // truncate
        ops.truncate = { (path, size, fi) -> Int32 in
             guard let path = path else { return -EFAULT }
             guard let context = globalContext else { return -EFAULT }
             let pathStr = String(cString: path)
             let tempFile = context.tempDir.appendingPathComponent(pathStr)
             
             if !FileManager.default.fileExists(atPath: tempFile.path) {
                 // Extract logic (duplicated from open)
                 if let entry = context.getEntry(pathStr) {
                     // archiveLock.lock()
                     do {
                         let parentDir = tempFile.deletingLastPathComponent()
                         try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
                         try context.withArchive { archive in
                             try archive.extractFile(filename: entry.filename, toPath: tempFile.path)
                         }
                     } catch {
                         // archiveLock.unlock()
                         return -EIO
                     }
                     // archiveLock.unlock()
                 } else {
                     return -ENOENT
                 }
             }
             
             do {
                 let handle = try FileHandle(forWritingTo: tempFile)
                 try handle.truncate(atOffset: UInt64(size))
                 try handle.close()
                 
                 // Update entry map size immediately
                 if var entry = context.getEntry(pathStr) {
                     entry.length = UInt64(size)
                     context.setEntry(pathStr, entry: entry)
                 }
                 
                 return 0
             } catch {
                 return -EIO
             }
        }
        
        // rename
        ops.rename = { (oldPath, newPath, flags) -> Int32 in
            guard let oldPath = oldPath, let newPath = newPath else { return -EFAULT }
            guard let context = globalContext else { return -EFAULT }
            let oldPathStr = String(cString: oldPath)
            let newPathStr = String(cString: newPath)
            let oldName = String(oldPathStr.dropFirst())
            let newName = String(newPathStr.dropFirst())
            
            // FIX: Accessing globalDirMap without a lock is not thread-safe.
            if context.isDir(oldPathStr) {
                // TODO: Implement directory renaming.
                return -ENOSYS // Not supported yet
            }
            
            // archiveLock.lock()
            // defer { archiveLock.unlock() }
            
            do {
                try context.withArchive { archive in
                    guard let index = archive.findFileEntry(filename: oldName) else {
                        throw CopperError.fileNotFound(oldName)
                    }
                    
                    // Update entry
                    archive.fileEntries[index].filename = newName
                    try archive.save()
                }
                
                // Update maps
                // FIX: Accessing globalEntryMap without a lock is not thread-safe.
                if var entry = context.getEntry(oldPathStr) {
                    entry.filename = newName
                    context.setEntry(newPathStr, entry: entry)
                    context.removeEntry(oldPathStr)
                }
                
                // Update parent dirs
                let oldParent = (oldPathStr as NSString).deletingLastPathComponent
                let oldFileName = (oldPathStr as NSString).lastPathComponent
                // FIX: Accessing globalDirMap without a lock is not thread-safe.
                context.removeDirChild(parent: oldParent, child: oldFileName)
                
                let newParent = (newPathStr as NSString).deletingLastPathComponent
                let newFileName = (newPathStr as NSString).lastPathComponent
                context.addDirChild(parent: newParent, child: newFileName)
                
                // Move temp file if exists
                let oldTemp = context.tempDir.appendingPathComponent(oldPathStr)
                let newTemp = context.tempDir.appendingPathComponent(newPathStr)
                if FileManager.default.fileExists(atPath: oldTemp.path) {
                    try? FileManager.default.moveItem(at: oldTemp, to: newTemp)
                }
                
                return 0
            } catch {
                return -EIO
            }
        }

        // Run FUSE
        print("Mounting at \(mountURL.path)...")
        
        // Prepare arguments
        var args = [CommandLine.arguments[0], mountURL.path]
        if foreground {
            args.append("-f")
        }
        
        // Convert args to C-compatible format
        let argc = Int32(args.count)
        var argv = args.map { strdup($0) }
        argv.append(nil) // Null terminator
        
        let ret = fuse_main_swift(argc, &argv, &ops, nil)
        
        // Cleanup
        for ptr in argv { free(ptr) }
        try? FileManager.default.removeItem(at: tempDir)
        
        if ret != 0 {
            throw ExitCode(ret)
        }
    }
}
