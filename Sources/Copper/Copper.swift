// Copper is a custom archive format designed by me for personal use.
// It supports optional compression and encryption, and is optimized for fast access and integrity verification.

// Copper Archive format

// Header section
// MAGIC        4 bytes
// VERSION      1 byte
// LENGTH       8 bytes     // total length of the header section
// FLAGS        8 bytes     // Compression, Encryption, etc.
// TIMESTAMP    8 bytes     // UNIX EPOCH archive creation time
// COMP_ALGO    1 byte      // Compression algorithm used (see implementation for codes)
// ENC_ALGO     1 byte      // Encryption algorithm used (see implementation for codes)
// ENC_KEY_HASH 32 bytes    // SHA-256 hash of the encryption key (if encryption is used, else all zeros. we never store the key itself, only its hash for verification)
// FE_OFFSET    8 bytes     // offset to the start of the file entry section
// DATA_OFFSET  8 bytes     // offset to the start of the file data section
// SALT         32 bytes    // Random salt used for key derivation
// RESERVED     32 bytes    // reserved for future use
// HEADER_HASH  32 bytes    // SHA-256 hash of the header section (excluding this field)

// File Entry Section
// Note: If encryption is enabled, the entire file entry section (including LENGTH and COUNT) is encrypted
// LENGTH       8 bytes  // length of this file entry section
// COUNT        8 bytes  // number of files in this archive
// For each file:
//   FILENAME_LENGTH    2 bytes
//   FILENAME           variable bytes
//   OFFSET             8 bytes  // offset of file data from start of archive
//   LENGTH             8 bytes  // length of file data in bytes, this will be the length of the compressed/encrypted data if those options are used
//   TIMESTAMP          8 bytes // UNIX EPOCH file creation time (used to restore timestamps)
//   PERMISSIONS        2 bytes // file permissions (used to restore permissions, same as UNIX FILE PERMISSIONS, 16 bits is actually more than the 12 bits but we use 16 for alignment)
//   HASH               32 bytes // SHA-256 hash of the file data

// File Data Section
// For each file:
//   DATA               variable bytes
// END_MARKER    16 bytes // fixed value to indicate end of archive

// Note: All multi-byte fields are stored in little-endian to ensure platform compatibility.
// Note: Compression and encryption are optional and can be indicated in the FLAGS field.
// ... Add as needed
// Note: ...

import Crypto
import Czlib
import Foundation

// DOCUMENT: Consider moving version and magic number to a configuration struct or static constants within CopperHeader to avoid global namespace pollution.
public let COPPER_VERSION_CURRENT: UInt8 = 1
public let COPPER_MAGIC_NUMBER: [UInt8] = [0x43, 0x4F, 0x50, 0x52]  // 'COPR'

public enum CopperCompressionAlgorithm: UInt8 {
    case none = 0
    case zlib = 1
}

public enum CopperEncryptionAlgorithm: UInt8 {
    case none = 0
    case aes256 = 1
    // impl as needed
    // aes256 is probably sufficient for most use cases
}

public enum CopperFlags: UInt64 {
    case none = 0
    case compressed = 1  // 1 << 0
    case encrypted = 2  // 1 << 1

}

// Archive structure and limits.
// Update These if theres any breaking changes to the format.
public struct CopperConstants {
    public static let headerLength: UInt64 = 175
    public static let endMarkerLength = 16
    public static let fileEntryHeaderLength = 16
    public static let aesGcmNonceSize = 12
    public static let aesGcmTagSize = 16
    public static let aesGcmOverhead = aesGcmNonceSize + aesGcmTagSize
    public static let hashSize = 32
    public static let keySize = 32
    public static let saltSize = 32
    public static let reservedSize = 32
    public static let fileEntryFixedSize = 58
    // DOCUMENT: 32KB chunk size for streaming operations.
    public static let defaultChunkSize = 32768
    // DOCUMENT: 1MB buffer size for file operations.
    public static let defaultBufferSize = 1024 * 1024
    public static let maxDecompressedSize = 256 * 1024 * 1024
    public static let defaultPermissions: UInt16 = 0o644
}

public struct CopperHeader {
    public static let magic: [UInt8] = COPPER_MAGIC_NUMBER
    public static let version: UInt8 = COPPER_VERSION_CURRENT
    public static let headerLength: UInt64 = CopperConstants.headerLength
    public var flags: UInt64 = 0
    public var timestamp: UInt64 = 0
    public var compressionAlgorithm: UInt8 = 0
    public var encryptionAlgorithm: UInt8 = 0
    public var encryptionKeyHash: [UInt8] = Array(repeating: 0, count: CopperConstants.hashSize)
    public var fileEntryOffset: UInt64 = 0
    public var dataOffset: UInt64 = 0
    public var salt: [UInt8] = Array(repeating: 0, count: CopperConstants.saltSize)
    public var reserved: [UInt8] = Array(repeating: 0, count: CopperConstants.reservedSize)
    public var headerHash: [UInt8] = Array(repeating: 0, count: CopperConstants.hashSize)
    
    public init() {}
}

public struct CopperFileEntry {
    public var filenameLength: UInt16 = 0
    public var filename: String = ""
    public var offset: UInt64 = 0
    public var length: UInt64 = 0
    public var timestamp: UInt64 = 0
    public var permissions: UInt16 = 0
    public var hash: [UInt8] = Array(repeating: 0, count: CopperConstants.hashSize)
    
    public init() {}
}

public struct CopperFreeSpace {
    public var offset: UInt64
    public var length: UInt64
}

public struct CopperArchive {
    public var header: CopperHeader
    public var fileEntries: [CopperFileEntry]
    public var fileData: UInt64 = 0  // ptr to file data section in file
    public var endMarker: [UInt8] = Array(repeating: 0x45, count: CopperConstants.endMarkerLength)  // 'EEEEEEEEEEEEEEEE'

    // This marks the end of the archive format.
    // Below are runtime properties, not part of the archive format.

    public var filePath: String = ""  // path to the archive file on disk
    public var fileHandle: FileHandle? = nil  // file handle for reading/writing

    public var encryptionKey: Data? = nil  // encryption key used for encrypting/decrypting files

    public var freeSpaces: [CopperFreeSpace] = []  // Track freed spaces in the data section for reuse

    // Maps archive filenames to source file paths (for writing archives)
    public var sourceFilePaths: [String: String] = [:]

    public var compressionEnabled: Bool {
        return (header.flags & CopperFlags.compressed.rawValue) != 0
    }

    public var encryptionEnabled: Bool {
        return (header.flags & CopperFlags.encrypted.rawValue) != 0
    }

    public var compressionAlgorithm: CopperCompressionAlgorithm {
        return CopperCompressionAlgorithm(rawValue: header.compressionAlgorithm) ?? .none
    }

    public var encryptionAlgorithm: CopperEncryptionAlgorithm {
        return CopperEncryptionAlgorithm(rawValue: header.encryptionAlgorithm) ?? .none
    }

    // Below are some utility functions as needed

    public func totalFiles() -> UInt64 {
        return UInt64(fileEntries.count)
    }

    /// Find a file entry by filename, returns the index if found
    public func findFileEntry(filename: String) -> Int? {
        return fileEntries.firstIndex(where: { $0.filename == filename })
    }

    mutating func findSpaceForData(length: UInt64) -> UInt64? {
        // Find a suitable space for new data of given length in the archive
        // Strategy: Best-fit algorithm - find the smallest free space that fits
        // This minimizes fragmentation by preserving larger spaces for larger files.

        // Sort free spaces by length (ascending) to find the smallest sufficient space
        freeSpaces.sort { $0.length < $1.length }

        // Look for a free space that fits
        for (index, freeSpace) in freeSpaces.enumerated() {
            if freeSpace.length >= length {
                let allocatedOffset = freeSpace.offset

                if freeSpace.length == length {
                    // Exact fit - remove this free space
                    freeSpaces.remove(at: index)
                } else {
                    // Partial fit - shrink the free space
                    freeSpaces[index].offset += length
                    freeSpaces[index].length -= length
                }

                return allocatedOffset
            }
        }

        // No suitable free space found, allocate at the end
        // Find the end of the last file
        var endOfData = header.dataOffset
        for entry in fileEntries {
            let entryEnd = entry.offset + entry.length
            if entryEnd > endOfData {
                endOfData = entryEnd
            }
        }

        return endOfData
    }

    // MARK: - File Management

    /// Remove a file from the archive and mark its space as free
    public mutating func removeFile(filename: String) throws {
        guard let index = fileEntries.firstIndex(where: { $0.filename == filename }) else {
            throw CopperError.fileNotFound(filename)
        }

        let entry = fileEntries[index]

        // Mark the space as free
        // TODO: For better security, we should optionally overwrite the data with zeros before marking as free.
        let freedSpace = CopperFreeSpace(offset: entry.offset, length: entry.length)
        freeSpaces.append(freedSpace)

        // Merge adjacent free spaces to reduce fragmentation
        mergeAdjacentFreeSpaces()

        // Remove the entry
        fileEntries.remove(at: index)
    }

    /// Merge adjacent free spaces to reduce fragmentation
    mutating func mergeAdjacentFreeSpaces() {
        guard freeSpaces.count > 1 else { return }

        // Sort by offset
        freeSpaces.sort { $0.offset < $1.offset }

        var merged: [CopperFreeSpace] = []
        var current = freeSpaces[0]

        for i in 1..<freeSpaces.count {
            let next = freeSpaces[i]

            // Check if current and next are adjacent
            if current.offset + current.length == next.offset {
                // Merge them
                current.length += next.length
            } else {
                // Not adjacent, save current and move to next
                merged.append(current)
                current = next
            }
        }

        // Don't forget the last one
        merged.append(current)

        freeSpaces = merged
    }

    /// Relocate file data from one offset to another within the data section
    /// This reads from the old offset and writes to the new offset using a buffer
    mutating func relocateFileData(from oldOffset: UInt64, length: UInt64, to newOffset: UInt64)
        throws
    {
        guard let handle = fileHandle else {
            throw CopperError.readError("File handle not available")
        }

        // Validate offsets
        guard oldOffset >= header.dataOffset && newOffset >= header.dataOffset else {
            throw CopperError.invalidOffset
        }
        
        if oldOffset == newOffset { return }

        let bufferSize = CopperConstants.defaultBufferSize // 1 MB buffer
        var bytesRemaining = length
        
        if newOffset < oldOffset {
            // Moving data "left" (to lower offset) - Copy forward
            var currentReadOffset = oldOffset
            var currentWriteOffset = newOffset
            
            while bytesRemaining > 0 {
                let bytesToRead = min(UInt64(bufferSize), bytesRemaining)
                
                handle.seek(toFileOffset: currentReadOffset)
                guard let data = try handle.read(upToCount: Int(bytesToRead)) else {
                    throw CopperError.readError("Failed to read data at offset \(currentReadOffset)")
                }
                
                guard data.count == Int(bytesToRead) else {
                    throw CopperError.readError("Read \(data.count) bytes but expected \(bytesToRead)")
                }
                
                handle.seek(toFileOffset: currentWriteOffset)
                try handle.write(contentsOf: data)
                
                currentReadOffset += bytesToRead
                currentWriteOffset += bytesToRead
                bytesRemaining -= bytesToRead
            }
        } else {
            // Moving data "right" (to higher offset) - Copy backward to handle overlap
            // We need to start from the end of the block
            var currentReadOffset = oldOffset + length
            var currentWriteOffset = newOffset + length
            
            while bytesRemaining > 0 {
                let bytesToRead = min(UInt64(bufferSize), bytesRemaining)
                
                // Calculate start of this chunk
                let chunkReadStart = currentReadOffset - bytesToRead
                let chunkWriteStart = currentWriteOffset - bytesToRead
                
                handle.seek(toFileOffset: chunkReadStart)
                guard let data = try handle.read(upToCount: Int(bytesToRead)) else {
                    throw CopperError.readError("Failed to read data at offset \(chunkReadStart)")
                }
                
                guard data.count == Int(bytesToRead) else {
                    throw CopperError.readError("Read \(data.count) bytes but expected \(bytesToRead)")
                }
                
                handle.seek(toFileOffset: chunkWriteStart)
                try handle.write(contentsOf: data)
                
                currentReadOffset -= bytesToRead
                currentWriteOffset -= bytesToRead
                bytesRemaining -= bytesToRead
            }
        }
        
        try handle.synchronize()
    }

    /// Compact the archive by moving all files forward to eliminate gaps
    /// This eliminates all free spaces and makes the archive contiguous
    public mutating func compactArchive() throws {
        guard let handle = fileHandle else {
            throw CopperError.writeError("File handle not available")
        }

        // Sort entries by current offset
        var sortedEntries = fileEntries.sorted { $0.offset < $1.offset }

        // Start writing files right after the data section begins
        var currentWriteOffset = header.dataOffset

        for i in 0..<sortedEntries.count {
            let entry = sortedEntries[i]

            // If the file is already at the correct position, skip relocation
            if entry.offset == currentWriteOffset {
                currentWriteOffset += entry.length
                continue
            }

            // Move the file data
            // REVIEW: If newOffset overlaps with oldOffset, this might corrupt data if not handled carefully.
            // Since we are compacting (moving to lower offsets), and we iterate by sorted offset,
            // we are moving data "left". If we read the whole chunk into memory (as relocateFileData currently does), it's safe.
            // But if we switch to buffered reading/writing, we must ensure we don't overwrite data we haven't read yet.
            try relocateFileData(from: entry.offset, length: entry.length, to: currentWriteOffset)

            // Update the entry with new offset
            sortedEntries[i].offset = currentWriteOffset

            // Update the write position for next file
            currentWriteOffset += entry.length
        }

        // Update the file entries with new offsets
        for updatedEntry in sortedEntries {
            if let index = fileEntries.firstIndex(where: { $0.filename == updatedEntry.filename }) {
                fileEntries[index].offset = updatedEntry.offset
            }
        }

        // Clear all free spaces since archive is now compact
        freeSpaces.removeAll()

        // Truncate the file to remove any unused space at the end
        let endOfData = currentWriteOffset
        let endMarkerOffset = endOfData

        // Write the end marker
        handle.seek(toFileOffset: endMarkerOffset)
        try handle.write(contentsOf: Data(endMarker))

        // Truncate file to final size
        try handle.truncate(atOffset: endMarkerOffset + UInt64(CopperConstants.endMarkerLength))
        try handle.synchronize()
    }

    /// Update a file in the archive with new data
    /// If the new data fits in the old space, it reuses it; otherwise it relocates the file
    public mutating func updateFile(filename: String, newData: Data, newHash: [UInt8]) throws {
        guard let index = fileEntries.firstIndex(where: { $0.filename == filename }) else {
            throw CopperError.fileNotFound(filename)
        }

        guard let handle = fileHandle else {
            throw CopperError.writeError("File handle not available")
        }

        let oldEntry = fileEntries[index]
        let newLength = UInt64(newData.count)

        // Check if new data fits in the current space
        if newLength <= oldEntry.length {
            // Fits in current location - reuse the space
            handle.seek(toFileOffset: oldEntry.offset)
            try handle.write(contentsOf: newData)
            try handle.synchronize()

            // Update entry metadata
            fileEntries[index].length = newLength
            fileEntries[index].hash = newHash
            fileEntries[index].timestamp = UInt64(Date().timeIntervalSince1970)

            // If there's leftover space, mark it as free
            // REVIEW: This can lead to high fragmentation if files are frequently updated with slightly smaller data.
            if newLength < oldEntry.length {
                let leftoverOffset = oldEntry.offset + newLength
                let leftoverLength = oldEntry.length - newLength
                freeSpaces.append(CopperFreeSpace(offset: leftoverOffset, length: leftoverLength))
                mergeAdjacentFreeSpaces()
            }
        } else {
            // Doesn't fit - need to relocate

            // Mark old space as free
            freeSpaces.append(CopperFreeSpace(offset: oldEntry.offset, length: oldEntry.length))
            mergeAdjacentFreeSpaces()

            // Find new space
            guard let newOffset = findSpaceForData(length: newLength) else {
                throw CopperError.insufficientSpace
            }

            // Write data to new location
            handle.seek(toFileOffset: newOffset)
            try handle.write(contentsOf: newData)
            try handle.synchronize()

            // Update entry with new location and metadata
            fileEntries[index].offset = newOffset
            fileEntries[index].length = newLength
            fileEntries[index].hash = newHash
            fileEntries[index].timestamp = UInt64(Date().timeIntervalSince1970)
        }
    }
}

public enum CopperError: Error {
    case fileNotFound(String)
    case insufficientSpace
    case invalidOffset
    case readError(String)
    case writeError(String)
    case corruptedArchive(String)
    case compressionError(String)
    case decompressionError(String)
    case encryptionError(String)
}

// MARK: - Compression Helpers

extension CopperCompressionAlgorithm {
    /// Compress data using the specified algorithm
    func compress(_ data: Data) throws -> Data {
        switch self {
        case .none:
            return data
        case .zlib:
            return try compressWithZlib(data)
        }
    }

    /// Compress data using system zlib
    private func compressWithZlib(_ data: Data) throws -> Data {
        // Estimate compressed size (worst case: original size + 0.1% + 12 bytes)
        let maxCompressedSize = data.count + data.count / 1000 + 12
        // Consider using a streaming approach or chunked compression to reduce memory footprint.
        // REVIEW: Allocating a large buffer based on input size can be problematic for large files.
        var compressedData = Data(count: maxCompressedSize)
        var compressedSize = UInt(maxCompressedSize)

        let result = data.withUnsafeBytes { (sourcePtr: UnsafeRawBufferPointer) -> Int32 in
            compressedData.withUnsafeMutableBytes {
                (destPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                compress2(
                    destPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    &compressedSize,
                    sourcePtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    UInt(data.count),
                    Z_BEST_COMPRESSION  // Level 9 - maximum compression
                )
            }
        }

        guard result == Z_OK else {
            throw CopperError.compressionError("zlib compression failed with code \(result)")
        }

        compressedData.count = Int(compressedSize)
        return compressedData
    }

    /// Decompress data using the specified algorithm
    func decompress(_ data: Data, uncompressedSize: Int) throws -> Data {
        // Define a reasonable limit for in-memory decompression to prevent Zip bombs
        let maxAllowedSize = CopperConstants.maxDecompressedSize // 256 MB
        
        if uncompressedSize > maxAllowedSize {
             throw CopperError.compressionError("Uncompressed size \(uncompressedSize) exceeds limit of \(maxAllowedSize) bytes")
        }
        
        switch self {
        case .none:
            return data
        case .zlib:
            return try decompressWithZlib(data, uncompressedSize: uncompressedSize, limit: maxAllowedSize)
        }
    }

    /// Decompress data using system zlib
    private func decompressWithZlib(_ data: Data, uncompressedSize: Int, limit: Int) throws -> Data {
        // If uncompressedSize is 0 or very large, use streaming decompression to avoid large contiguous allocation
        // This mitigates the risk of DoS via large allocation requests
        if uncompressedSize == 0 || uncompressedSize > 10 * 1024 * 1024 { // 10 MB
            return try decompressWithZlibStreaming(data, limit: limit)
        }

        // REVIEW: Allocating memory based on uncompressedSize from the archive header is a potential DoS vector (Zip bomb).
        // Although `maxAllowedSize` is checked above, allocating the full buffer upfront is still risky if multiple threads do this.
        // FIX: Validate uncompressedSize against a reasonable limit or available memory.
        var decompressedData = Data(count: uncompressedSize)
        var decompressedSize = UInt(uncompressedSize)

        let result = data.withUnsafeBytes { (sourcePtr: UnsafeRawBufferPointer) -> Int32 in
            decompressedData.withUnsafeMutableBytes {
                (destPtr: UnsafeMutableRawBufferPointer) -> Int32 in
                uncompress(
                    destPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    &decompressedSize,
                    sourcePtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    UInt(data.count)
                )
            }
        }

        guard result == Z_OK else {
            let errorMsg: String
            switch result {
            case Z_MEM_ERROR:
                errorMsg = "zlib decompression failed: insufficient memory"
            case Z_BUF_ERROR:
                errorMsg = "zlib decompression failed: output buffer too small"
            case Z_DATA_ERROR:
                errorMsg =
                    "zlib decompression failed: input data corrupted or invalid format. This archive may have been created with SWCompression library. Please recreate the archive."
            default:
                errorMsg = "zlib decompression failed with code \(result)"
            }
            throw CopperError.compressionError(errorMsg)
        }

        guard Int(decompressedSize) == uncompressedSize else {
            throw CopperError.compressionError(
                "Decompressed size mismatch: expected \(uncompressedSize), got \(decompressedSize)")
        }

        return decompressedData
    }

    /// Decompress using streaming API when uncompressed size is unknown
    private func decompressWithZlibStreaming(_ data: Data, limit: Int) throws -> Data {
        var stream = z_stream()
        stream.zalloc = nil
        stream.zfree = nil
        stream.opaque = nil

        var result = data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) -> Int32 in
            stream.avail_in = UInt32(data.count)
            stream.next_in = UnsafeMutablePointer(
                mutating: ptr.baseAddress?.assumingMemoryBound(to: UInt8.self))
            return inflateInit_(&stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        }

        guard result == Z_OK else {
            throw CopperError.compressionError("zlib init failed with code \(result)")
        }

        defer { inflateEnd(&stream) }

        var decompressedData = Data()
        let chunkSize = CopperConstants.defaultChunkSize  // 32KB chunks
        var outBuffer = [UInt8](repeating: 0, count: chunkSize)

        repeat {
            outBuffer.withUnsafeMutableBytes { bufferPtr in
                stream.avail_out = UInt32(chunkSize)
                stream.next_out = bufferPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
            }

            result = inflate(&stream, Z_NO_FLUSH)

            guard result == Z_OK || result == Z_STREAM_END else {
                throw CopperError.compressionError("zlib inflate failed with code \(result)")
            }

            let have = chunkSize - Int(stream.avail_out)
            decompressedData.append(contentsOf: outBuffer[0..<have])
            
            if decompressedData.count > limit {
                throw CopperError.compressionError("Decompressed data exceeds limit of \(limit) bytes")
            }

        } while result != Z_STREAM_END

        return decompressedData
    }
}

// MARK: - Encryption

extension CopperEncryptionAlgorithm {
    /// Encrypt data using the specified encryption algorithm
    /// Returns the encrypted data with nonce/IV prepended
    func encrypt(_ data: Data, key: Data) throws -> Data {
        switch self {
        case .none:
            return data
        case .aes256:
            return try encryptWithAES256GCM(data, key: key)
        }
    }

    /// Decrypt data using the specified encryption algorithm
    /// Expects nonce/IV to be prepended to the ciphertext
    func decrypt(_ data: Data, key: Data) throws -> Data {
        switch self {
        case .none:
            return data
        case .aes256:
            return try decryptWithAES256GCM(data, key: key)
        }
    }

    /// Encrypt data using AES-256-GCM (Galois/Counter Mode)
    /// GCM provides authenticated encryption, protecting against tampering
    private func encryptWithAES256GCM(_ data: Data, key: Data) throws -> Data {
        // Verify key is 32 bytes (256 bits)
        guard key.count == CopperConstants.keySize else {
            throw CopperError.encryptionError("AES-256 requires a 32-byte (256-bit) key")
        }

        // Create a symmetric key from the provided data
        let symmetricKey = SymmetricKey(data: key)

        // Generate a random nonce (12 bytes is standard for GCM)
        let nonce = AES.GCM.Nonce()

        // Encrypt the data
        let sealedBox = try AES.GCM.seal(data, using: symmetricKey, nonce: nonce)

        // Combine nonce + ciphertext + tag
        // AES.GCM.SealedBox.combined already includes nonce + ciphertext + tag
        guard let combined = sealedBox.combined else {
            throw CopperError.encryptionError("Failed to create combined encrypted data")
        }

        return combined
    }

    /// Decrypt data using AES-256-GCM
    private func decryptWithAES256GCM(_ data: Data, key: Data) throws -> Data {
        // Verify key is 32 bytes (256 bits)
        guard key.count == CopperConstants.keySize else {
            throw CopperError.encryptionError("AES-256 requires a 32-byte (256-bit) key")
        }

        // Create a symmetric key from the provided data
        let symmetricKey = SymmetricKey(data: key)

        // The data should contain: nonce (12 bytes) + ciphertext + tag (16 bytes)
        // Minimum size: 12 + 0 + 16 = 28 bytes
        guard data.count >= CopperConstants.aesGcmOverhead else {
            throw CopperError.encryptionError(
                "Encrypted data too short (minimum \(CopperConstants.aesGcmOverhead) bytes required)")
        }

        // Create sealed box from combined data
        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.SealedBox(combined: data)
        } catch {
            throw CopperError.encryptionError("Failed to parse encrypted data: \(error.localizedDescription)")
        }

        // Decrypt and authenticate
        do {
            let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
            return decryptedData
        } catch {
            throw CopperError.encryptionError("Decryption failed - wrong key or corrupted data")
        }
    }

    /// Derive a 256-bit encryption key from a password using HKDF
    /// This provides better security than using the password directly
    public static func deriveKey(from password: String, salt: Data? = nil) throws -> Data {
        guard let passwordData = password.data(using: .utf8) else {
            throw CopperError.encryptionError("Failed to convert password to data")
        }

        // Use provided salt or generate a random one
        // For Copper archives, we'll use a deterministic salt based on the magic number
        // This allows the same password to always produce the same key
        // This requires changing the archive format or how the key is stored/retrieved.
        // REVIEW: Using a deterministic salt reduces security against rainbow table attacks.
        // FIX: Generate a random salt, store it in the archive header, and use it for key derivation.
        let usedSalt = salt ?? Data(COPPER_MAGIC_NUMBER + [0x45, 0x4E, 0x43])  // 'COPR' + 'ENC'

        // Create input key material from password
        let inputKeyMaterial = SymmetricKey(data: passwordData)

        // Derive a 256-bit key using HKDF with SHA-256
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: usedSalt,
            info: Data("copper-archive-encryption".utf8),
            outputByteCount: CopperConstants.keySize  // 256 bits
        )

        return derivedKey.withUnsafeBytes { Data($0) }
    }
}

// MARK: - Helper Extensions

extension Data {
    /// Compute SHA-256 hash of data
    func sha256Hash() -> [UInt8] {
        let hash = SHA256.hash(data: self)
        return Array(hash)
    }

    /// Append a UInt8 value
    mutating func appendUInt8(_ value: UInt8) {
        append(value)
    }

    /// Append a UInt16 value in little-endian format
    mutating func appendUInt16(_ value: UInt16) {
        var littleEndian = value.littleEndian
        append(Data(bytes: &littleEndian, count: MemoryLayout<UInt16>.size))
    }

    /// Append a UInt64 value in little-endian format
    mutating func appendUInt64(_ value: UInt64) {
        var littleEndian = value.littleEndian
        append(Data(bytes: &littleEndian, count: MemoryLayout<UInt64>.size))
    }

    /// Append a byte array
    mutating func appendBytes(_ bytes: [UInt8]) {
        append(contentsOf: bytes)
    }

    /// Read a UInt16 from the specified offset in little-endian format
    func readUInt16(at offset: Int) -> UInt16 {
        let bytes = self[offset..<offset + 2]
        return bytes.withUnsafeBytes { buffer in
            UInt16(littleEndian: buffer.loadUnaligned(as: UInt16.self))
        }
    }

    /// Read a UInt64 from the specified offset in little-endian format
    func readUInt64(at offset: Int) -> UInt64 {
        let bytes = self[offset..<offset + 8]
        return bytes.withUnsafeBytes { buffer in
            UInt64(littleEndian: buffer.loadUnaligned(as: UInt64.self))
        }
    }
}

extension UnsafeRawBufferPointer {
    /// Load a value from an unaligned pointer
    func loadUnaligned<T>(as type: T.Type) -> T {
        assert(MemoryLayout<T>.size <= self.count)
        let buffer = UnsafeMutableRawBufferPointer.allocate(
            byteCount: MemoryLayout<T>.size, alignment: MemoryLayout<T>.alignment)
        defer { buffer.deallocate() }
        buffer.copyBytes(from: self)
        return buffer.load(as: T.self)
    }
}

extension CopperHeader {
    /// Serialize header to binary data in little-endian format
    func serialize() -> Data {
        var data = Data()

        // MAGIC - 4 bytes
        data.appendBytes(CopperHeader.magic)

        // VERSION - 1 byte
        data.appendUInt8(CopperHeader.version)

        // LENGTH - 8 bytes
        data.appendUInt64(CopperHeader.headerLength)

        // FLAGS - 8 bytes
        data.appendUInt64(flags)

        // TIMESTAMP - 8 bytes
        data.appendUInt64(timestamp)

        // COMP_ALGO - 1 byte
        data.appendUInt8(compressionAlgorithm)

        // ENC_ALGO - 1 byte
        data.appendUInt8(encryptionAlgorithm)

        // ENC_KEY_HASH - 32 bytes
        data.appendBytes(encryptionKeyHash)

        // FE_OFFSET - 8 bytes
        data.appendUInt64(fileEntryOffset)

        // DATA_OFFSET - 8 bytes
        data.appendUInt64(dataOffset)
        
        // SALT - 32 bytes (Added in V2)
        data.appendBytes(salt)

        // RESERVED - 32 bytes
        data.appendBytes(reserved)

        // HEADER_HASH - 32 bytes (computed over everything except this field)
        let headerDataWithoutHash = data
        let hash = headerDataWithoutHash.sha256Hash()
        data.appendBytes(hash)

        return data
    }
}

extension CopperFileEntry {
    /// Serialize file entry to binary data in little-endian format
    func serialize() -> Data {
        var data = Data()

        // FILENAME_LENGTH - 2 bytes
        data.appendUInt16(filenameLength)

        // FILENAME - variable bytes (UTF-8 encoded)
        if let filenameData = filename.data(using: .utf8) {
            data.append(filenameData)
        }

        // OFFSET - 8 bytes
        data.appendUInt64(offset)

        // LENGTH - 8 bytes
        data.appendUInt64(length)

        // TIMESTAMP - 8 bytes
        data.appendUInt64(timestamp)

        // PERMISSIONS - 2 bytes
        data.appendUInt16(permissions)

        // HASH - 32 bytes
        data.appendBytes(hash)

        return data
    }
}

extension CopperArchive {

    // MARK: - Archive Creation

    /// Initialize a new empty archive
    public static func createNew(
        compressionAlgorithm: CopperCompressionAlgorithm = .none,
        encryptionAlgorithm: CopperEncryptionAlgorithm = .none,
        encryptionKey: Data? = nil,
        salt: Data? = nil
    ) -> CopperArchive {
        var header = CopperHeader()
        header.timestamp = UInt64(Date().timeIntervalSince1970)
        header.compressionAlgorithm = compressionAlgorithm.rawValue
        header.encryptionAlgorithm = encryptionAlgorithm.rawValue
        header.fileEntryOffset = CopperHeader.headerLength
        
        // Generate random salt if not provided
        if let providedSalt = salt {
            header.salt = Array(providedSalt)
        } else {
            header.salt = (0..<CopperConstants.saltSize).map { _ in UInt8.random(in: 0...255) }
        }

        // Set flags based on algorithms
        if compressionAlgorithm != .none {
            header.flags |= CopperFlags.compressed.rawValue
        }
        if encryptionAlgorithm != .none {
            header.flags |= CopperFlags.encrypted.rawValue
        }

        // Hash encryption key if provided
        if let key = encryptionKey {
            header.encryptionKeyHash = key.sha256Hash()
        }

        var archive = CopperArchive(header: header, fileEntries: [])
        archive.encryptionKey = encryptionKey

        return archive
    }

    /// Add a file to the archive from a file path
    public mutating func addFile(at filePath: String, archiveName: String? = nil) throws {
        let fileManager = FileManager.default
        var isDirectory: ObjCBool = false

        // REVIEW: Time-of-check to time-of-use (TOCTOU) race condition. File could be removed or changed between check and open.
        guard fileManager.fileExists(atPath: filePath, isDirectory: &isDirectory) else {
            throw CopperError.readError("File does not exist at \(filePath)")
        }

        if isDirectory.boolValue {
            throw CopperError.readError("Use addPath() for directories")
        }

        let fileURL = URL(fileURLWithPath: filePath)

        // REVIEW: Reading the entire file to compute hash before adding is inefficient for large files.
        // Consider computing hash while compressing/writing if possible, or using a faster hash if integrity check speed is critical.
        // Compute hash of UNCOMPRESSED file data (for integrity verification)
        // Stream read for hash to avoid loading large files into memory just for checking
        guard let readHandle = FileHandle(forReadingAtPath: filePath) else {
             throw CopperError.readError("Cannot read file at \(filePath)")
        }
        
        var hasher = SHA256()
        let bufferSize = CopperConstants.defaultBufferSize
        var fileSize: UInt64 = 0
        
        while true {
            let data = try readHandle.read(upToCount: bufferSize)
            if let data = data, !data.isEmpty {
                hasher.update(data: data)
                fileSize += UInt64(data.count)
            } else {
                break
            }
        }
        let hash = Array(hasher.finalize())
        
        // Close handle to reset for later reading if needed
        try? readHandle.close()

        // Get file attributes
        guard let attributes = try? fileManager.attributesOfItem(atPath: filePath) else {
            throw CopperError.readError("Cannot read file attributes at \(filePath)")
        }

        let modificationDate = attributes[.modificationDate] as? Date ?? Date()
        // REVIEW: Magic number 0o644. Use a constant or proper permission handling.
        let posixPermissions = attributes[.posixPermissions] as? UInt16 ?? CopperConstants.defaultPermissions

        // Use provided archive name or file name
        let name = archiveName ?? fileURL.lastPathComponent

        // Check if file already exists in archive
        if let existingIndex = findFileEntry(filename: name) {
            let existingEntry = fileEntries[existingIndex]

            // Compare hashes - if identical, skip adding
            if existingEntry.hash == hash {
                // File hasn't changed, skip it
                return
            }

            // File has changed, mark old space as free and update entry
            if fileHandle != nil && existingEntry.offset > 0 {
                let freedSpace = CopperFreeSpace(
                    offset: existingEntry.offset, length: existingEntry.length)
                freeSpaces.append(freedSpace)
            }
        }

        // Create file entry (compression happens later during write)
        var entry = CopperFileEntry()
        entry.filename = name
        entry.filenameLength = UInt16(name.utf8.count)
        entry.offset = 0  // Will be set during writeToFile or when adding to existing archive
        entry.length = fileSize  // Will be updated with compressed size during write
        entry.timestamp = UInt64(modificationDate.timeIntervalSince1970)
        entry.permissions = posixPermissions
        entry.hash = hash  // Hash of UNCOMPRESSED data

        // If we have an active file handle (modifying existing archive), compress and write now
        // Or if we have a file path but no handle (e.g. opened archive), open it temporarily
        var handleToClose: FileHandle? = nil
        var activeHandle = fileHandle
        
        if activeHandle == nil && !self.filePath.isEmpty {
             // Open for updating
             // print("DEBUG: Opening \(self.filePath) for updating in addFile")
             activeHandle = FileHandle(forUpdatingAtPath: self.filePath)
             // if activeHandle == nil { print("DEBUG: Failed to open handle in addFile") }
             handleToClose = activeHandle
             // We don't set self.fileHandle here to avoid side effects on other methods expecting it to be nil/closed
        }

        if let handle = activeHandle {
            // Re-read file data for writing
            // Note: We still read full file here because we need to know compressed size 
            // before allocating space. To fix this, we would need to compress to a temp file.
            guard let fileData = try? Data(contentsOf: fileURL) else {
                throw CopperError.readError("Cannot read file at \(filePath)")
            }
            
            // Compress data if needed
            var dataToStore: Data
            if compressionEnabled && compressionAlgorithm != .none {
                dataToStore = try compressionAlgorithm.compress(fileData)
            } else {
                dataToStore = fileData
            }

            // Encrypt data if needed (after compression)
            if encryptionEnabled && encryptionAlgorithm != .none {
                guard let key = encryptionKey else {
                    throw CopperError.encryptionError("Encryption enabled but no key provided")
                }
                dataToStore = try encryptionAlgorithm.encrypt(dataToStore, key: key)
            }

            entry.length = UInt64(dataToStore.count)

            // Find space for data
            guard let offset = findSpaceForData(length: UInt64(dataToStore.count)) else {
                throw CopperError.insufficientSpace
            }

            entry.offset = offset

            // Write data immediately
            // print("DEBUG: Seeking to \(offset) for writing data")
            if #available(macOS 10.15.4, iOS 13.4, watchOS 6.2, tvOS 13.4, *) {
                try handle.seek(toOffset: offset)
            } else {
                handle.seek(toFileOffset: offset)
            }
            // print("DEBUG: Writing \(dataToStore.count) bytes")
            try handle.write(contentsOf: dataToStore)
            try handle.synchronize()
        } else {
            // For new archives, track source path for deferred compression/writing
            sourceFilePaths[name] = filePath
        }
        
        if let h = handleToClose {
            try? h.close()
        }

        // Add or update entry
        if let existingIndex = findFileEntry(filename: name) {
            // Replace existing entry
            fileEntries[existingIndex] = entry
        } else {
            // Add new entry
            fileEntries.append(entry)
        }
    }

    /// Add a path (file or directory) to the archive, recursively if it's a directory
    public mutating func addPath(at path: String, baseDir: String? = nil) throws {
        let fileManager = FileManager.default
        var isDirectory: ObjCBool = false

        guard fileManager.fileExists(atPath: path, isDirectory: &isDirectory) else {
            throw CopperError.readError("Path does not exist at \(path)")
        }

        if !isDirectory.boolValue {
            // It's a file, add it directly
            let archiveName: String?
            if let base = baseDir {
                // Compute relative path from base directory
                let basePath = (base as NSString).standardizingPath
                let fullPath = (path as NSString).standardizingPath
                if fullPath.hasPrefix(basePath) {
                    let relativePath = String(fullPath.dropFirst(basePath.count))
                    archiveName =
                        relativePath.hasPrefix("/")
                        ? String(relativePath.dropFirst()) : relativePath
                } else {
                    archiveName = (path as NSString).lastPathComponent
                }
            } else {
                archiveName = nil
            }
            try addFile(at: path, archiveName: archiveName)
            return
        }

        // It's a directory, recursively add all contents
        let dirName = (path as NSString).lastPathComponent
        let enumerator = fileManager.enumerator(atPath: path)

        while let relativePath = enumerator?.nextObject() as? String {
            let fullPath = (path as NSString).appendingPathComponent(relativePath)
            var isSubDir: ObjCBool = false

            guard fileManager.fileExists(atPath: fullPath, isDirectory: &isSubDir) else {
                continue
            }

            // Skip directories themselves (we only store files)
            if isSubDir.boolValue {
                continue
            }

            // Prepend directory name to preserve structure
            let archiveName = (dirName as NSString).appendingPathComponent(relativePath)
            try addFile(at: fullPath, archiveName: archiveName)
        }
    }

    /// Add multiple paths (files or directories) to the archive
    public mutating func addPaths(_ paths: [String]) throws {
        for path in paths {
            try addPath(at: path)
        }
    }

    /// Write the complete archive to disk
    public mutating func writeToFile(path: String) throws {
        let fileManager = FileManager.default

        // Create parent directory if needed
        let directory = (path as NSString).deletingLastPathComponent
        if !directory.isEmpty && !fileManager.fileExists(atPath: directory) {
            try fileManager.createDirectory(atPath: directory, withIntermediateDirectories: true)
        }

        // Create/overwrite file
        _ = fileManager.createFile(atPath: path, contents: nil)

        guard let handle = FileHandle(forWritingAtPath: path) else {
            throw CopperError.writeError("Cannot open file for writing at \(path)")
        }

        self.fileHandle = handle
        self.filePath = path

        defer {
            try? handle.close()
        }

        // Calculate offsets
        let headerSize = CopperHeader.headerLength
        let fileEntrySize = calculateFileEntrySectionSize()
        // If encryption is enabled, the file entry section will be larger due to nonce + tag
        let actualFileEntrySize = encryptionEnabled ? fileEntrySize + UInt64(CopperConstants.aesGcmOverhead) : fileEntrySize

        header.fileEntryOffset = headerSize
        header.dataOffset = headerSize + actualFileEntrySize
        
        // Write placeholder header
        try handle.write(contentsOf: header.serialize())
        
        // Write placeholder file entry section to reserve space
        try handle.write(contentsOf: Data(count: Int(actualFileEntrySize)))

        // Write data section sequentially
        var currentOffset = header.dataOffset
        let compressionAlgo = compressionAlgorithm
        let shouldCompress = compressionEnabled && compressionAlgo != .none
        let shouldEncrypt = encryptionEnabled && encryptionAlgorithm != .none
        
        for i in 0..<fileEntries.count {
            guard let sourcePath = sourceFilePaths[fileEntries[i].filename] else {
                continue  // Already written or no source
            }

            // REVIEW: Reading entire source file into memory.
            // FIX: For now we still read into memory because encryption/compression APIs used here are not streaming.
            // To fix this properly, we need to implement chunked processing for compression and encryption.
            guard let fileData = try? Data(contentsOf: URL(fileURLWithPath: sourcePath)) else {
                throw CopperError.readError("Cannot read source file at \(sourcePath)")
            }

            // Apply compression first (if enabled)
            var processedData = fileData
            if shouldCompress {
                processedData = try compressionAlgo.compress(processedData)
            }

            // Apply encryption after compression (if enabled)
            if shouldEncrypt {
                guard let key = encryptionKey else {
                    throw CopperError.encryptionError("Encryption enabled but no key provided")
                }
                processedData = try encryptionAlgorithm.encrypt(processedData, key: key)
            }

            // Write processed data
            handle.seek(toFileOffset: currentOffset)
            try handle.write(contentsOf: processedData)
            
            // Update entry
            fileEntries[i].offset = currentOffset
            fileEntries[i].length = UInt64(processedData.count)
            
            currentOffset += UInt64(processedData.count)
            print("+[\(i+1)/\(fileEntries.count)] \(fileEntries[i].filename)")
        }
        

        // Write end marker
        try handle.write(contentsOf: Data(endMarker))
        
        // Rewrite header with correct timestamp
        header.timestamp = UInt64(Date().timeIntervalSince1970)
        handle.seek(toFileOffset: 0)
        try handle.write(contentsOf: header.serialize())

        // Rewrite file entry section with correct offsets/lengths
        handle.seek(toFileOffset: header.fileEntryOffset)
        try writeFileEntrySection(to: handle)

        try handle.synchronize()
    }

    /// Calculate the total size of the file entry section
    private func calculateFileEntrySectionSize() -> UInt64 {
        // LENGTH (8) + COUNT (8) + sum of all entry sizes
        var totalSize: UInt64 = UInt64(CopperConstants.fileEntryHeaderLength)

        for entry in fileEntries {
            // FILENAME_LENGTH (2) + FILENAME (variable) + OFFSET (8) + LENGTH (8) +
            // TIMESTAMP (8) + PERMISSIONS (2) + HASH (32)
            totalSize += 2 + UInt64(entry.filename.utf8.count) + UInt64(CopperConstants.fileEntryFixedSize)
        }

        return totalSize
    }

    /// Write the file entry section to the file handle
    private func writeFileEntrySection(to handle: FileHandle) throws {
        var data = Data()

        // LENGTH - 8 bytes (will be calculated)
        let sectionSize = calculateFileEntrySectionSize()
        data.appendUInt64(sectionSize)

        // COUNT - 8 bytes
        data.appendUInt64(UInt64(fileEntries.count))

        // Write each file entry
        for entry in fileEntries {
            data.append(entry.serialize())
        }

        // Encrypt file entry section if encryption is enabled
        let finalData: Data
        if encryptionEnabled {
            guard let key = encryptionKey else {
                throw CopperError.encryptionError("Archive is encrypted but no key provided")
            }
            finalData = try encryptionAlgorithm.encrypt(data, key: key)
        } else {
            finalData = data
        }

        try handle.write(contentsOf: finalData)
    }

    /// Write the file data section to the file handle
    private mutating func writeFileDataSection(to handle: FileHandle) throws {
        // This method is now only used by save() or other methods if needed, 
        // but writeToFile handles its own data writing.
        // However, if we are just updating metadata, we don't rewrite data section.
        // If we are compacting, we use compactArchive().
        
        // The original implementation used compressedDataCache or sourceFilePaths.
        // Since we removed compressedDataCache and writeToFile handles sourceFilePaths,
        // this method might be redundant or needs to be adapted for other use cases.
        // For now, we'll leave it empty or remove it if not used.
        // But wait, if we add files to an existing archive, we use addFile which writes immediately.
        // So this method was only for writeToFile.
        // So we can remove it or leave it as a stub/deprecated.
    }

    /// Add multiple files to the archive at once
    public mutating func addFiles(filePaths: [String]) throws {
        for filePath in filePaths {
            try addFile(at: filePath)
        }
    }

    // MARK: - Archive Reading

    /// Open and parse an existing Copper archive from disk
    public static func open(path: String, encryptionKey: Data? = nil) throws -> CopperArchive {
        let fileManager = FileManager.default

        guard fileManager.fileExists(atPath: path) else {
            throw CopperError.fileNotFound(path)
        }

        guard let handle = FileHandle(forReadingAtPath: path) else {
            throw CopperError.readError("Cannot open file for reading at \(path)")
        }

        // Read Magic (4) + Version (1) + Length (8) = 13 bytes
        guard let preamble = try handle.read(upToCount: 13) else {
            throw CopperError.readError("Cannot read header preamble")
        }
        
        let magic = Array(preamble[0..<4])
        guard magic == COPPER_MAGIC_NUMBER else { throw CopperError.corruptedArchive("Invalid magic number") }
        
        // let version = preamble[4] // Not used here, but parsed in parseHeader
        let headerLength = preamble.readUInt64(at: 5)
        
        // Read full header
        handle.seek(toFileOffset: 0)
        guard let headerData = try handle.read(upToCount: Int(headerLength)) else {
            throw CopperError.readError("Cannot read header")
        }

        let header = try parseHeader(from: headerData)

        // Verify encryption key if needed
        if header.encryptionAlgorithm != CopperEncryptionAlgorithm.none.rawValue {
            guard let key = encryptionKey else {
                throw CopperError.readError("Encryption key required but not provided")
            }

            let providedKeyHash = key.sha256Hash()
            guard providedKeyHash == header.encryptionKeyHash else {
                throw CopperError.readError("Incorrect encryption key")
            }
        }

        // Seek to file entry section
        handle.seek(toFileOffset: header.fileEntryOffset)


        // Determine if file entry section is encrypted
        let isEncrypted = header.encryptionAlgorithm != CopperEncryptionAlgorithm.none.rawValue


        // Read file entry section
        // First, we need to determine how much to read
        // If encrypted, we need to read until the data section offset
        // If not encrypted, we can read the length field first
        let fileEntrySectionData: Data
        
        if isEncrypted {
            // Read entire encrypted file entry section (from FE_OFFSET to DATA_OFFSET)
            let encryptedLength = header.dataOffset - header.fileEntryOffset
            // REVIEW: Reading potentially large encrypted section into memory.
            guard let encryptedData = try handle.read(upToCount: Int(encryptedLength)) else {
                throw CopperError.readError("Cannot read encrypted file entry section")
            }
            
            // Decrypt the file entry section
            guard let key = encryptionKey else {
                throw CopperError.encryptionError("Archive is encrypted but no key provided")
            }
            let encAlgo = CopperEncryptionAlgorithm(rawValue: header.encryptionAlgorithm) ?? .none
            fileEntrySectionData = try encAlgo.decrypt(encryptedData, key: key)
        } else {
            // Read unencrypted length header
            guard let lengthData = try handle.read(upToCount: CopperConstants.fileEntryHeaderLength) else {
                throw CopperError.readError("Cannot read file entry section header")
            }
            
            let sectionLength = lengthData.readUInt64(at: 0)
            
            // Read the rest of the section
            guard let remainingData = try handle.read(upToCount: Int(sectionLength) - CopperConstants.fileEntryHeaderLength) else {
                throw CopperError.readError("Cannot read file entry section data")
            }
            
            fileEntrySectionData = lengthData + remainingData
        }

        // Parse the (now decrypted) file entry section
        let _ = fileEntrySectionData.readUInt64(at: 0)
        let fileCount = fileEntrySectionData.readUInt64(at: 8)

        // Parse all file entries from the decrypted data
        var fileEntries: [CopperFileEntry] = []
        var offset = CopperConstants.fileEntryHeaderLength  // Skip LENGTH and COUNT fields

        for _ in 0..<fileCount {
            let entry = try parseFileEntryFromData(fileEntrySectionData, offset: &offset)
            fileEntries.append(entry)
        }

        // Close handle for now (will reopen if needed for operations)
        try handle.close()

        var archive = CopperArchive(header: header, fileEntries: fileEntries)
        archive.filePath = path
        archive.encryptionKey = encryptionKey

        return archive
    }

    /// Parse header from binary data
    private static func parseHeader(from data: Data) throws -> CopperHeader {
        // We don't check against CopperHeader.headerLength constant because it might vary by version.
        // We rely on the LENGTH field in the data.
        
        var offset = 0

        // MAGIC - 4 bytes
        let magic = Array(data[offset..<offset + 4])
        guard magic == COPPER_MAGIC_NUMBER else {
            throw CopperError.corruptedArchive("Invalid magic number")
        }
        offset += 4

        // VERSION - 1 byte
        let version = data[offset]
        guard version <= COPPER_VERSION_CURRENT else {
            throw CopperError.corruptedArchive("Unsupported version: \(version)")
        }
        offset += 1

        // LENGTH - 8 bytes
        let headerLength = data.readUInt64(at: offset)
        offset += 8
        
        guard data.count >= Int(headerLength) else {
            throw CopperError.corruptedArchive("Header data too short")
        }

        // FLAGS - 8 bytes
        let flags = data.readUInt64(at: offset)
        offset += 8

        // TIMESTAMP - 8 bytes
        let timestamp = data.readUInt64(at: offset)
        offset += 8

        // COMP_ALGO - 1 byte
        let compressionAlgorithm = data[offset]
        offset += 1

        // ENC_ALGO - 1 byte
        let encryptionAlgorithm = data[offset]
        offset += 1

        // ENC_KEY_HASH - 32 bytes
        let encryptionKeyHash = Array(data[offset..<offset + CopperConstants.hashSize])
        offset += CopperConstants.hashSize

        // FE_OFFSET - 8 bytes
        let fileEntryOffset = data.readUInt64(at: offset)
        offset += 8

        // DATA_OFFSET - 8 bytes
        let dataOffset = data.readUInt64(at: offset)
        offset += 8
        
        // SALT - 32 bytes
        let salt = Array(data[offset..<offset+CopperConstants.saltSize])
        offset += CopperConstants.saltSize

        // RESERVED - 32 bytes
        let reserved = Array(data[offset..<offset + CopperConstants.reservedSize])
        offset += CopperConstants.reservedSize

        // HEADER_HASH - 32 bytes
        let headerHash = Array(data[offset..<offset + CopperConstants.hashSize])

        // Verify header hash
        let headerDataWithoutHash = data[0..<offset]
        let computedHash = headerDataWithoutHash.sha256Hash()
        guard computedHash == headerHash else {
            throw CopperError.corruptedArchive("Header hash mismatch, Archive may be corrupted")
        }

        var header = CopperHeader()
        header.flags = flags
        header.timestamp = timestamp
        header.compressionAlgorithm = compressionAlgorithm
        header.encryptionAlgorithm = encryptionAlgorithm
        header.encryptionKeyHash = encryptionKeyHash
        header.fileEntryOffset = fileEntryOffset
        header.dataOffset = dataOffset
        header.salt = salt
        header.reserved = reserved
        header.headerHash = headerHash

        return header
    }
    
    /// Get the salt from an archive header without opening the full archive
    public static func getSalt(from path: String) throws -> Data? {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: path) else {
            throw CopperError.fileNotFound(path)
        }
        
        guard let handle = FileHandle(forReadingAtPath: path) else {
            throw CopperError.readError("Cannot open file at \(path)")
        }
        defer { try? handle.close() }
        
        // Read preamble
        guard let preamble = try handle.read(upToCount: 13) else {
            throw CopperError.readError("Cannot read header preamble")
        }
        
        let headerLength = preamble.readUInt64(at: 5)
        
        // Read full header
        handle.seek(toFileOffset: 0)
        guard let headerData = try handle.read(upToCount: Int(headerLength)) else {
            throw CopperError.readError("Cannot read header")
        }
        
        let header = try parseHeader(from: headerData)
        return Data(header.salt)
    }

    /// Parse a single file entry from a data buffer
    private static func parseFileEntryFromData(_ data: Data, offset: inout Int) throws -> CopperFileEntry {
        // FILENAME_LENGTH - 2 bytes
        guard offset + 2 <= data.count else {
            throw CopperError.readError("Cannot read filename length")
        }
        let filenameLength = data.readUInt16(at: offset)
        offset += 2

        // FILENAME - variable bytes
        guard offset + Int(filenameLength) <= data.count else {
            throw CopperError.readError("Cannot read filename")
        }
        let filenameData = data[offset..<offset + Int(filenameLength)]
        guard let filename = String(data: filenameData, encoding: .utf8) else {
            throw CopperError.corruptedArchive("Invalid filename encoding")
        }
        offset += Int(filenameLength)

        // Read the rest of the entry (OFFSET, LENGTH, TIMESTAMP, PERMISSIONS, HASH)
        // Total: 8 + 8 + 8 + 2 + 32 = 58 bytes
        guard offset + CopperConstants.fileEntryFixedSize <= data.count else {
            throw CopperError.readError("Cannot read file entry data")
        }

        // OFFSET - 8 bytes
        let fileOffset = data.readUInt64(at: offset)
        offset += 8

        // LENGTH - 8 bytes
        let length = data.readUInt64(at: offset)
        offset += 8

        // TIMESTAMP - 8 bytes
        let timestamp = data.readUInt64(at: offset)
        offset += 8

        // PERMISSIONS - 2 bytes
        let permissions = data.readUInt16(at: offset)
        offset += 2

        // HASH - 32 bytes
        let hash = Array(data[offset..<offset + CopperConstants.hashSize])
        offset += CopperConstants.hashSize

        var entry = CopperFileEntry()
        entry.filenameLength = filenameLength
        entry.filename = filename
        entry.offset = fileOffset
        entry.length = length
        entry.timestamp = timestamp
        entry.permissions = permissions
        entry.hash = hash

        return entry
    }

    /// Parse a single file entry from the file handle
    private static func parseFileEntry(from handle: FileHandle) throws -> CopperFileEntry {
        // FILENAME_LENGTH - 2 bytes
        guard let lengthData = try handle.read(upToCount: 2) else {
            throw CopperError.readError("Cannot read filename length")
        }
        let filenameLength = lengthData.readUInt16(at: 0)

        // FILENAME - variable bytes
        guard let filenameData = try handle.read(upToCount: Int(filenameLength)) else {
            throw CopperError.readError("Cannot read filename")
        }
        guard let filename = String(data: filenameData, encoding: .utf8) else {
            throw CopperError.corruptedArchive("Invalid filename encoding")
        }

        // Read the rest of the entry (OFFSET, LENGTH, TIMESTAMP, PERMISSIONS, HASH)
        // Total: 8 + 8 + 8 + 2 + 32 = 58 bytes
        guard let entryData = try handle.read(upToCount: CopperConstants.fileEntryFixedSize) else {
            throw CopperError.readError("Cannot read file entry data")
        }

        var offset = 0

        // OFFSET - 8 bytes
        let fileOffset = entryData.readUInt64(at: offset)
        offset += 8

        // LENGTH - 8 bytes
        let length = entryData.readUInt64(at: offset)
        offset += 8

        // TIMESTAMP - 8 bytes
        let timestamp = entryData.readUInt64(at: offset)
        offset += 8

        // PERMISSIONS - 2 bytes
        let permissions = entryData.readUInt16(at: offset)
        offset += 2

        // HASH - 32 bytes
        let hash = Array(entryData[offset..<offset + CopperConstants.hashSize])

        var entry = CopperFileEntry()
        entry.filenameLength = filenameLength
        entry.filename = filename
        entry.offset = fileOffset
        entry.length = length
        entry.timestamp = timestamp
        entry.permissions = permissions
        entry.hash = hash

        return entry
    }

    /// Shift the entire data section by a given amount
    private mutating func shiftDataSection(by shiftAmount: Int64, handle: FileHandle) throws {
        // Find end of data (excluding end marker)
        var endOfData = header.dataOffset
        for entry in fileEntries {
            let entryEnd = entry.offset + entry.length
            if entryEnd > endOfData {
                endOfData = entryEnd
            }
        }
        
        let dataLength = endOfData - header.dataOffset
        if dataLength == 0 { return }
        
        let oldStart = header.dataOffset
        let newStart = UInt64(Int64(oldStart) + shiftAmount)
        
        let bufferSize = CopperConstants.defaultBufferSize // 1 MB
        var bytesRemaining = dataLength
        
        if shiftAmount > 0 {
            // Moving right (expand) - Copy backward
            var currentReadOffset = oldStart + dataLength
            var currentWriteOffset = newStart + dataLength
            
            while bytesRemaining > 0 {
                let bytesToRead = min(UInt64(bufferSize), bytesRemaining)
                let chunkReadStart = currentReadOffset - bytesToRead
                let chunkWriteStart = currentWriteOffset - bytesToRead
                
                handle.seek(toFileOffset: chunkReadStart)
                guard let data = try handle.read(upToCount: Int(bytesToRead)) else {
                    throw CopperError.readError("Failed to read data during shift")
                }
                
                handle.seek(toFileOffset: chunkWriteStart)
                try handle.write(contentsOf: data)
                
                currentReadOffset -= bytesToRead
                currentWriteOffset -= bytesToRead
                bytesRemaining -= bytesToRead
            }
        } else {
            // Moving left (shrink) - Copy forward
            var currentReadOffset = oldStart
            var currentWriteOffset = newStart
            
            while bytesRemaining > 0 {
                let bytesToRead = min(UInt64(bufferSize), bytesRemaining)
                
                handle.seek(toFileOffset: currentReadOffset)
                guard let data = try handle.read(upToCount: Int(bytesToRead)) else {
                    throw CopperError.readError("Failed to read data during shift")
                }
                
                handle.seek(toFileOffset: currentWriteOffset)
                try handle.write(contentsOf: data)
                
                currentReadOffset += bytesToRead
                currentWriteOffset += bytesToRead
                bytesRemaining -= bytesToRead
            }
        }
        
        // Update all offsets
        for i in 0..<fileEntries.count {
            fileEntries[i].offset = UInt64(Int64(fileEntries[i].offset) + shiftAmount)
        }
        
        for i in 0..<freeSpaces.count {
            freeSpaces[i].offset = UInt64(Int64(freeSpaces[i].offset) + shiftAmount)
        }
    }

    /// Save changes to an existing archive (updates header and file entry section)
    /// This is more efficient than rewriting the entire archive when only metadata changes
    public mutating func save() throws {
        guard !filePath.isEmpty else {
            throw CopperError.writeError(
                "Archive path not set. Use writeToFile() to create new archive.")
        }

        // print("DEBUG: Opening \(filePath) for updating in save")
        guard let handle = FileHandle(forUpdatingAtPath: filePath) else {
            throw CopperError.writeError("Cannot open archive for writing at \(filePath)")
        }

        self.fileHandle = handle

        defer {
            try? handle.close()
        }

        // Recalculate offsets in case file entries changed
        let headerSize = CopperHeader.headerLength
        let fileEntrySize = calculateFileEntrySectionSize()
        // If encryption is enabled, the file entry section will be larger due to nonce + tag
        let actualFileEntrySize = encryptionEnabled ? fileEntrySize + UInt64(CopperConstants.aesGcmOverhead) : fileEntrySize

        let oldDataOffset = header.dataOffset
        let newDataOffset = headerSize + actualFileEntrySize
        
        if newDataOffset != oldDataOffset {
            let shiftAmount = Int64(newDataOffset) - Int64(oldDataOffset)
            try shiftDataSection(by: shiftAmount, handle: handle)
            header.dataOffset = newDataOffset
        }

        header.fileEntryOffset = headerSize
        header.timestamp = UInt64(Date().timeIntervalSince1970)

        // Rewrite header
        handle.seek(toFileOffset: 0)
        let headerData = header.serialize()
        try handle.write(contentsOf: headerData)

        // Rewrite file entry section
        handle.seek(toFileOffset: header.fileEntryOffset)
        try writeFileEntrySection(to: handle)
        
        // If we shifted, we need to rewrite the end marker at the new position
        // Find end of data
        var endOfData = header.dataOffset
        for entry in fileEntries {
            let entryEnd = entry.offset + entry.length
            if entryEnd > endOfData {
                endOfData = entryEnd
            }
        }
        
        handle.seek(toFileOffset: endOfData)
        try handle.write(contentsOf: Data(endMarker))
        try handle.truncate(atOffset: endOfData + UInt64(CopperConstants.endMarkerLength))

        try handle.synchronize()
    }

    /// Extract a file from the archive to disk
    public func extractFile(filename: String, toPath: String) throws {
        guard let entry = fileEntries.first(where: { $0.filename == filename }) else {
            throw CopperError.fileNotFound(filename)
        }

        guard let handle = FileHandle(forReadingAtPath: filePath) else {
            throw CopperError.readError("Cannot open archive at \(filePath)")
        }

        defer {
            try? handle.close()
        }
        
        // Create parent directory if needed
        let fileManager = FileManager.default
        let directory = (toPath as NSString).deletingLastPathComponent
        if !directory.isEmpty && !fileManager.fileExists(atPath: directory) {
            try fileManager.createDirectory(atPath: directory, withIntermediateDirectories: true)
        }
        
        // Create output file
        _ = fileManager.createFile(atPath: toPath, contents: nil)
        guard let outHandle = FileHandle(forWritingAtPath: toPath) else {
            throw CopperError.writeError("Cannot open output file at \(toPath)")
        }
        defer { try? outHandle.close() }

        if encryptionEnabled {
            // Encrypted: Must read full file into memory (limitation of AES-GCM)
            handle.seek(toFileOffset: entry.offset)
            guard let storedData = try handle.read(upToCount: Int(entry.length)) else {
                throw CopperError.readError("Cannot read file data for \(filename)")
            }
            
            guard let key = encryptionKey else {
                throw CopperError.encryptionError("Archive is encrypted but no key provided")
            }
            
            let decryptedData = try encryptionAlgorithm.decrypt(storedData, key: key)
            
            // Decompress if needed
            let finalData: Data
            if compressionEnabled {
                finalData = try compressionAlgorithm.decompress(decryptedData, uncompressedSize: 0)
            } else {
                finalData = decryptedData
            }
            
            // Verify hash
            let computedHash = finalData.sha256Hash()
            guard computedHash == entry.hash else {
                throw CopperError.corruptedArchive("File hash mismatch for \(filename)")
            }
            
            try outHandle.write(contentsOf: finalData)
            
        } else if compressionEnabled {
            // Compressed but not encrypted: Stream decompression
            handle.seek(toFileOffset: entry.offset)
            
            // Initialize zlib stream
            var stream = z_stream()
            stream.zalloc = nil
            stream.zfree = nil
            stream.opaque = nil
            
            guard inflateInit_(&stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
                throw CopperError.compressionError("zlib init failed")
            }
            defer { inflateEnd(&stream) }
            
            let inBufferSize = CopperConstants.defaultChunkSize
            let outBufferSize = CopperConstants.defaultChunkSize
            var outBuffer = Data(count: outBufferSize)
            
            var bytesRead: UInt64 = 0
            var hasher = SHA256()
            
            while bytesRead < entry.length {
                let bytesToRead = min(UInt64(inBufferSize), entry.length - bytesRead)
                guard let chunk = try handle.read(upToCount: Int(bytesToRead)) else {
                    throw CopperError.readError("Unexpected end of file")
                }
                bytesRead += UInt64(chunk.count)
                
                // Feed to zlib
                try chunk.withUnsafeBytes { (inPtr: UnsafeRawBufferPointer) in
                    stream.avail_in = UInt32(chunk.count)
                    stream.next_in = UnsafeMutablePointer(mutating: inPtr.baseAddress?.assumingMemoryBound(to: UInt8.self))
                    
                    repeat {
                        try outBuffer.withUnsafeMutableBytes { (outPtr: UnsafeMutableRawBufferPointer) in
                            stream.avail_out = UInt32(outBufferSize)
                            stream.next_out = outPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                            
                            let ret = inflate(&stream, Z_NO_FLUSH)
                            if ret != Z_OK && ret != Z_STREAM_END {
                                throw CopperError.compressionError("zlib inflate failed: \(ret)")
                            }
                            
                            let have = outBufferSize - Int(stream.avail_out)
                            if have > 0 {
                                // Use the pointer to create data to avoid overlapping access
                                let outputChunk = Data(bytes: outPtr.baseAddress!, count: have)
                                try outHandle.write(contentsOf: outputChunk)
                                hasher.update(data: outputChunk)
                            }
                        }
                    } while stream.avail_out == 0
                }
            }
            
            // Verify hash
            let computedHash = Array(hasher.finalize())
            guard computedHash == entry.hash else {
                throw CopperError.corruptedArchive("File hash mismatch for \(filename)")
            }
            
        } else {
            // Neither encrypted nor compressed: Stream copy
            handle.seek(toFileOffset: entry.offset)
            var bytesRemaining = entry.length
            let bufferSize = CopperConstants.defaultBufferSize
            var hasher = SHA256()
            
            while bytesRemaining > 0 {
                let bytesToRead = min(UInt64(bufferSize), bytesRemaining)
                guard let data = try handle.read(upToCount: Int(bytesToRead)) else {
                    throw CopperError.readError("Unexpected end of file")
                }
                
                try outHandle.write(contentsOf: data)
                hasher.update(data: data)
                bytesRemaining -= UInt64(data.count)
            }
            
            let computedHash = Array(hasher.finalize())
            guard computedHash == entry.hash else {
                throw CopperError.corruptedArchive("File hash mismatch for \(filename)")
            }
        }

        // Restore permissions and timestamp
        try fileManager.setAttributes(
            [
                .modificationDate: Date(timeIntervalSince1970: TimeInterval(entry.timestamp)),
                .posixPermissions: entry.permissions,
            ], ofItemAtPath: toPath)
    }

    /// Extract all files from the archive to a directory
    public func extractAll(toDirectory: String) throws {
        let fileManager = FileManager.default

        // Create directory if needed
        if !fileManager.fileExists(atPath: toDirectory) {
            try fileManager.createDirectory(atPath: toDirectory, withIntermediateDirectories: true)
        }

        for entry in fileEntries {
            let outputPath = (toDirectory as NSString).appendingPathComponent(entry.filename)
            try extractFile(filename: entry.filename, toPath: outputPath)
        }
    }

    /// Extract a subfolder from the archive to a destination directory
    public func extractSubfolder(folderPath: String, to destinationDirectory: String) throws {
        // Normalize folder path to ensure it ends with / for prefix matching
        let normalizedFolder = folderPath.hasSuffix("/") ? folderPath : folderPath + "/"
        
        // Find all entries that start with the folder path
        let entries = fileEntries.filter { $0.filename.hasPrefix(normalizedFolder) }
        
        if entries.isEmpty {
            throw CopperError.fileNotFound(folderPath)
        }
        
        for entry in entries {
            let outputPath = (destinationDirectory as NSString).appendingPathComponent(entry.filename)
            try extractFile(filename: entry.filename, toPath: outputPath)
        }
    }

    /// Extract a selection of files or folders to a destination directory
    public func extractSelection(paths: [String], to destinationDirectory: String) throws {
        for path in paths {
            // Check if it's a file
            if findFileEntry(filename: path) != nil {
                let outputPath = (destinationDirectory as NSString).appendingPathComponent(path)
                try extractFile(filename: path, toPath: outputPath)
            } else {
                // Try as subfolder
                try extractSubfolder(folderPath: path, to: destinationDirectory)
            }
        }
    }

    /// Add a subfolder to the archive
    public mutating func addSubfolder(at path: String, baseDir: String? = nil) throws {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw CopperError.readError("Path is not a directory: \(path)")
        }
        try addPath(at: path, baseDir: baseDir)
    }

    /// Add a selection of paths (files or folders) to the archive
    public mutating func addSelection(paths: [String]) throws {
        try addPaths(paths)
    }
}
