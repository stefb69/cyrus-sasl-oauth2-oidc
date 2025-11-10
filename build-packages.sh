#!/bin/bash

# Unified build script for both DEB and RPM packages using Docker
# Usage: ./build-packages.sh [os] [version] [target] [arch]
# Examples:
#   ./build-packages.sh debian trixie packages amd64
#   ./build-packages.sh fedora 41 packages x86_64
#   ./build-packages.sh rhel 9 packages x86_64

set -e

OS=${1:-debian}
VERSION=${2:-trixie}
TARGET=${3:-packages}
HOST_ARCH=$(uname -m)
TARGET_ARCH=${4:-amd64}
IMAGE_NAME="cyrus-sasl-oauth2-oidc"

# Validate OS type
case $OS in
    debian)
        DOCKERFILE="Dockerfile.build"
        BUILD_ARG="DEBIAN_VERSION"
        if [[ "$VERSION" != "trixie" && "$VERSION" != "bookworm" ]]; then
            echo "Error: Only Debian Trixie and Bookworm are supported"
            echo "Usage: $0 debian {trixie|bookworm} <target> <arch>"
            exit 1
        fi
        ;;
    ubuntu)
        DOCKERFILE="Dockerfile.ubuntu"
        BUILD_ARG="UBUNTU_VERSION"
        if [[ "$VERSION" != "24.04" ]]; then
            echo "Error: Only Ubuntu 24.04 LTS is supported"
            echo "Usage: $0 ubuntu 24.04 <target> <arch>"
            exit 1
        fi
        ;;
    fedora)
        DOCKERFILE="Dockerfile.fedora"
        BUILD_ARG="FEDORA_VERSION"
        if [[ "$VERSION" != "41" ]]; then
            echo "Error: Only Fedora 41 is supported"
            echo "Usage: $0 fedora 41 <target> <arch>"
            exit 1
        fi
        ;;
    *)
        echo "❌ Error: Unsupported OS '$OS'. Supported: debian, ubuntu, fedora"
        exit 1
        ;;
esac

# Map architecture names
if [ "$OS" != "debian" ]; then
    # For RPM builds, map x86_64 -> amd64, aarch64 -> arm64
    case $TARGET_ARCH in
        x86_64) TARGET_ARCH="amd64" ;;
        aarch64) TARGET_ARCH="arm64" ;;
    esac
fi

echo "🚀 Building $OS package for $VERSION ($ARCH)..."
echo "📋 Configuration:"
echo "   OS: $OS"
echo "   Version: $VERSION"
echo "   Architecture: $HOST_ARCH (Target: $TARGET_ARCH)"
echo "   Target: $TARGET"
echo "   Dockerfile: $DOCKERFILE"

# Create packages directory
mkdir -p dist/packages

# Build the Docker image
echo "📦 Building Docker image..."
if [ "$TARGET_ARCH" != "amd64" -o "$TARGET_ARCH" != "$HOST_ARCH" ]; then
    # Use buildx for multi-arch builds
    docker buildx build \
        --platform "linux/$TARGET_ARCH" \
        --target "$TARGET" \
        --tag "$IMAGE_NAME:$OS-$VERSION-$ARCH" \
        --file "$DOCKERFILE" \
        --build-arg "$BUILD_ARG=$VERSION" \
        --load \
        .
else
    # Use regular build for AMD64
    docker build \
        --target "$TARGET" \
        --tag "$IMAGE_NAME:$OS-$VERSION-$ARCH" \
        --file "$DOCKERFILE" \
        --build-arg "$BUILD_ARG=$VERSION" \
        .
fi

if [ "$TARGET" = "packages" ]; then
    # Extract packages from the container
    echo "📤 Extracting packages..."
    docker run --rm -v "$(pwd)/dist/packages:/output" \
        "$IMAGE_NAME:$OS-$VERSION-$ARCH" \
        sh -c "cp -r /dist/packages/* /output/"

    echo "✅ Packages extracted to ./dist/packages/"
    echo "📋 Built packages:"
    find dist/packages -name "*.*" -type f -exec ls -lh {} \;

    # Run linting validation
    echo "🔍 Running package validation..."
    case $OS in
        debian)
            echo "Running lintian validation..."
            docker run --rm -v "$(pwd)/dist/packages:/packages" \
                "$IMAGE_NAME:$OS-$VERSION-$ARCH" \
                sh -c "find /packages -name '*.deb' -exec lintian {} \;" || true
            ;;
        fedora|rhel)
            echo "Running rpmlint validation..."
            docker run --rm -v "$(pwd)/dist/packages:/packages" \
                "$IMAGE_NAME:$OS-$VERSION-$ARCH" \
                sh -c "find /packages -name '*.rpm' -exec rpmlint {} \;" || true
            ;;
    esac

elif [ "$TARGET" = "test" ]; then
    # Run installation test
    echo "🧪 Testing package installation..."
    case $OS in
        debian)
            docker run --rm "$IMAGE_NAME:$OS-$VERSION-$ARCH" \
                bash -c "ls -la /usr/lib/*/sasl2/liboauth2.so"
            ;;
        fedora|rhel)
            docker run --rm "$IMAGE_NAME:$OS-$VERSION-$ARCH" \
                bash -c "find /usr/lib* -name 'liboauth2.so*' -type f"
            ;;
    esac
    echo "✅ Package installation test passed!"
fi

echo "🎉 Build completed successfully!"
