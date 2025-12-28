// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "azurite",
    products: [
        .executable(name: "azt", targets: ["azurite"]),
        .executable(name: "copper-fuse", targets: ["copper-fuse"]),
        .library(name: "Copper", targets: ["Copper"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "5.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .systemLibrary(
            name: "Czlib"
        ),
        .systemLibrary(
            name: "Cfuse",
            pkgConfig: "fuse3",
            providers: [
                .apt(["libfuse3-dev"]),
                .brew(["fuse"]),
                .yum(["fuse3-devel"])
            ]
        ),
        .target(
            name: "Copper",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                "Czlib",
            ]
        ),
        .executableTarget(
            name: "azurite",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "Copper",
            ]
        ),
        .executableTarget(
            name: "copper-fuse",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "Cfuse",
                "Copper",
            ]
        ),
    ]
)
