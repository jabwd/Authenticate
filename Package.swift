// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Authenticate",
    products: [
        .library(
            name: "Authenticate",
            targets: ["Authenticate"]),
    ],
    dependencies: [
    ],
    targets: [
		.target(
			name: "CED25519Ref10",
			dependencies: [],
			path: "Sources/CED25519Ref10",
			sources: [
				"compact25519.c",
				"randombytes.c",
			],
			publicHeadersPath: "."
		),
        .target(
            name: "Authenticate",
            dependencies: ["CED25519Ref10"]),
        .testTarget(
            name: "AuthenticateTests",
            dependencies: ["Authenticate"]),
    ]
)
