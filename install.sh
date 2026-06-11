#!/usr/bin/env sh
set -eu

REPO="North9-Labs/Seam"
INSTALL_DIR="${SEAM_INSTALL_DIR:-$HOME/.local/bin}"

detect_target() {
    OS=$(uname -s)
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64)  ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *)
            echo "error: unsupported architecture: $ARCH" >&2
            exit 1
            ;;
    esac

    case "$OS" in
        Linux)
            if [ "$ARCH" = "aarch64" ]; then
                echo "${ARCH}-unknown-linux-gnu"
            else
                echo "${ARCH}-unknown-linux-musl"
            fi
            ;;
        Darwin) echo "${ARCH}-apple-darwin" ;;
        *)
            echo "error: unsupported OS: $OS" >&2
            exit 1
            ;;
    esac
}

main() {
    TARGET=$(detect_target)

    LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

    if [ -z "$LATEST" ]; then
        echo "error: could not fetch latest release" >&2
        exit 1
    fi

    ASSET="seam-${TARGET}.tar.gz"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${ASSET}"
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/${LATEST}/checksums.sha256"

    TMPDIR=$(mktemp -d)
    # Always clean up temp dir on exit
    trap 'rm -rf "$TMPDIR"' EXIT

    echo "downloading seam ${LATEST} for ${TARGET}…"
    # Force progress output to /dev/tty so it's visible even when piped through sh
    if ! curl -fL --progress-bar "$DOWNLOAD_URL" -o "${TMPDIR}/${ASSET}" 2>/dev/tty && \
       ! curl -fL "$DOWNLOAD_URL" -o "${TMPDIR}/${ASSET}"; then
        echo "error: could not download ${ASSET}" >&2
        echo "  tried: ${DOWNLOAD_URL}" >&2
        echo "  the release may not have a pre-built binary for your platform." >&2
        echo "  build from source: cargo install --git https://github.com/${REPO} seam" >&2
        exit 1
    fi
    curl -fsSL "$CHECKSUM_URL" -o "${TMPDIR}/checksums.sha256"

    # Verify checksum
    cd "$TMPDIR"
    if command -v sha256sum >/dev/null 2>&1; then
        grep "$ASSET" checksums.sha256 | sha256sum -c - >/dev/null
    elif command -v shasum >/dev/null 2>&1; then
        grep "$ASSET" checksums.sha256 | shasum -a 256 -c - >/dev/null
    else
        echo "warning: could not verify checksum (no sha256sum/shasum found)" >&2
    fi

    tar -xzf "$ASSET" -C "$TMPDIR"
    chmod +x "${TMPDIR}/seam"

    mkdir -p "$INSTALL_DIR"
    mv "${TMPDIR}/seam" "${INSTALL_DIR}/seam"

    echo "installed seam ${LATEST} to ${INSTALL_DIR}/seam"

    # PATH hint
    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            echo ""
            echo "add to your shell profile:"
            echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
            ;;
    esac
}

main "$@"
