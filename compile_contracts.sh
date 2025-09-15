#!/bin/bash
# compile-contracts.sh
# Compile zap-contracts for specific networks
# Usage: ./compile-contracts.sh <network>
# Networks: mainnet, testnet, localdevnet

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Configuration
# CONTRACTS_DIR="zap-contracts"
# PROGRAMS_DIR="${CONTRACTS_DIR}/programs"

CONTRACTS_DIR="../zap-contracts"
PROGRAMS_DIR="${CONTRACTS_DIR}/programs"
WALLET_CONSTS_FILE="${PROGRAMS_DIR}/zapwallet_consts/src/wallet_consts.sw"
FORC_VERSION="v0.66.6"

# Network chain IDs
declare -A CHAIN_IDS=(
    ["mainnet"]="9889"
    ["testnet"]="129514"
    ["localdevnet"]="9889"  # Same as mainnet for local dev
)

# Contract modules to build
CONTRACT_MODULES=(
    "module00"
    "module01"
    "module02"
    "module03"
    "module04"
    "module05"
    "module06"
    "module07"
    "module08"
    "master"
    "zap_manager"
)

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_detail() { echo -e "${CYAN}  →${NC} $1"; }
log_network() { echo -e "${MAGENTA}[NETWORK]${NC} $1"; }

# Check if running from correct directory
check_working_directory() {
    # if [ ! -f "Cargo.toml" ]; then
    #     log_error "This script must be run from the Rust project root directory"
    #     log_error "Current directory: $(pwd)"
    #     exit 1
    # fi
    
    if [ ! -d "$CONTRACTS_DIR" ]; then
        log_error "Directory $CONTRACTS_DIR not found!"
        log_error "Make sure submodules are initialized: git submodule update --init --recursive"
        exit 1
    fi
    
    if [ ! -f "$WALLET_CONSTS_FILE" ]; then
        log_error "Wallet constants file not found: $WALLET_CONSTS_FILE"
        log_error "Make sure the submodule structure is correct"
        exit 1
    fi
}

# Check and install forc if needed
check_forc_installation() {
    log_info "Checking forc installation..."
    
    if command -v forc &> /dev/null; then
        local installed_version=$(forc --version 2>/dev/null | grep -oP 'forc \K[0-9.]+' || echo "unknown")
        log_success "forc is installed (version: $installed_version)"
        
        # Check if it's the recommended version
        if [[ "$installed_version" != "${FORC_VERSION#v}" ]]; then
            log_warning "Installed forc version ($installed_version) differs from recommended (${FORC_VERSION#v})"
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Installation cancelled"
                exit 0
            fi
        fi
    else
        log_warning "forc not found. Would you like to install it?"
        read -p "Install forc ${FORC_VERSION}? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_forc
        else
            log_error "forc is required to compile contracts"
            exit 1
        fi
    fi
}

# Install forc
install_forc() {
    log_info "Installing forc ${FORC_VERSION}..."
    
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Detect OS and architecture
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    if [[ "$os" == "darwin" ]]; then
        if [[ "$arch" == "arm64" ]]; then
            local platform="darwin_arm64"
        else
            local platform="darwin_amd64"
        fi
    elif [[ "$os" == "linux" ]]; then
        local platform="linux_amd64"
    else
        log_error "Unsupported OS: $os"
        exit 1
    fi
    
    local download_url="https://github.com/FuelLabs/sway/releases/download/${FORC_VERSION}/forc-binaries-${platform}.tar.gz"
    
    log_detail "Downloading from: $download_url"
    
    if curl -L "$download_url" -o forc.tar.gz; then
        tar -xzf forc.tar.gz
        
        # Move to user's local bin or /usr/local/bin
        if [ -w "/usr/local/bin" ]; then
            sudo mv forc-binaries/* /usr/local/bin/
            sudo chmod +x /usr/local/bin/forc*
        else
            mkdir -p "$HOME/.local/bin"
            mv forc-binaries/* "$HOME/.local/bin/"
            chmod +x "$HOME/.local/bin/forc*"
            log_warning "Installed to $HOME/.local/bin - make sure this is in your PATH"
        fi
        
        log_success "forc ${FORC_VERSION} installed successfully"
    else
        log_error "Failed to download forc"
        exit 1
    fi
    
    cd - > /dev/null
    rm -rf "$temp_dir"
}

# Backup the original wallet_consts.sw file
backup_wallet_consts() {
    local backup_file="${WALLET_CONSTS_FILE}.backup"
    
    if [ ! -f "$backup_file" ]; then
        log_info "Creating backup of wallet_consts.sw..."
        cp "$WALLET_CONSTS_FILE" "$backup_file"
        log_success "Backup created: $backup_file"
    else
        log_detail "Backup already exists: $backup_file"
    fi
}

# Restore the original wallet_consts.sw file
restore_wallet_consts() {
    local backup_file="${WALLET_CONSTS_FILE}.backup"
    
    if [ -f "$backup_file" ]; then
        log_info "Restoring original wallet_consts.sw..."
        cp "$backup_file" "$WALLET_CONSTS_FILE"
        log_success "Original file restored"
    else
        log_warning "No backup file found to restore"
    fi
}

# Configure network-specific constants
configure_network() {
    local network=$1
    local chain_id=${CHAIN_IDS[$network]}
    
    if [ -z "$chain_id" ]; then
        log_error "Invalid network: $network"
        log_detail "Valid networks: ${!CHAIN_IDS[@]}"
        exit 1
    fi
    
    log_network "Configuring for network: $network (Chain ID: $chain_id)"
    
    # Backup original file
    backup_wallet_consts
    
    # Update the FUEL_CHAINID constant
    log_detail "Updating FUEL_CHAINID to $chain_id..."
    
    # Use sed to replace the chain ID - be specific about the line format
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS sed syntax
        sed -i '' "s/^pub const FUEL_CHAINID: u64 = [0-9]*;/pub const FUEL_CHAINID: u64 = $chain_id;/" "$WALLET_CONSTS_FILE"
    else
        # Linux sed syntax
        sed -i "s/^pub const FUEL_CHAINID: u64 = [0-9]*;/pub const FUEL_CHAINID: u64 = $chain_id;/" "$WALLET_CONSTS_FILE"
    fi
    
    # Verify the change - extract just the number from the FUEL_CHAINID line
    local configured_id=$(grep "^pub const FUEL_CHAINID: u64 = " "$WALLET_CONSTS_FILE" | sed 's/.*= \([0-9]*\);.*/\1/')
    
    if [ "$configured_id" == "$chain_id" ]; then
        log_success "FUEL_CHAINID configured: $configured_id"

        # Show the actual line for confirmation
        log_detail "Updated line: $(grep '^pub const FUEL_CHAINID' "$WALLET_CONSTS_FILE")"
    else
        log_error "Failed to configure FUEL_CHAINID (found: $configured_id, expected: $chain_id)"
        restore_wallet_consts
        exit 1
    fi
}

# Clean previous build artifacts
clean_contracts() {
    log_info "Cleaning previous build artifacts..."
    
    cd "$PROGRAMS_DIR"
    
    if forc clean; then
        log_success "Clean completed"
    else
        log_warning "Clean failed or nothing to clean"
    fi
    
    # Also remove any out directories
    for module in "${CONTRACT_MODULES[@]}"; do
        if [ -d "${module}/out" ]; then
            rm -rf "${module}/out"
            log_detail "Removed ${module}/out"
        fi
    done
    
    cd - > /dev/null
}

# Build all contracts
build_contracts() {
    local network=$1
    
    log_info "Building contracts for $network..."
    
    cd "$PROGRAMS_DIR"
    
    # Run forc build
    log_detail "Running: forc build --release"
    
    if forc build --release; then
        log_success "Build completed successfully!"
    else
        log_error "Build failed!"
        cd - > /dev/null
        return 1
    fi
    
    cd - > /dev/null
}

# Verify build outputs
verify_build_outputs() {
    log_info "Verifying build outputs..."
    
    local all_found=true
    local missing_modules=()
    
    for module in "${CONTRACT_MODULES[@]}"; do
        # The ABI JSON file has -abi suffix, bin file doesn't have json extension
        local abi_file="${PROGRAMS_DIR}/${module}/out/release/${module}-abi.json"
        local bin_file="${PROGRAMS_DIR}/${module}/out/release/${module}.bin"
        local bin_root_file="${PROGRAMS_DIR}/${module}/out/release/${module}-bin-root"
        
        if [ -f "$abi_file" ] && [ -f "$bin_file" ]; then
            local size=$(du -h "$bin_file" | cut -f1)
            log_success "✓ ${module} (${size})"
            log_detail "  ABI: $(basename "$abi_file")"
            log_detail "  BIN: $(basename "$bin_file")"
            if [ -f "$bin_root_file" ]; then
                log_detail "  ROOT: $(basename "$bin_root_file")"
            fi
        else
            log_error "✗ ${module} - missing output files"
            if [ ! -f "$abi_file" ]; then
                log_detail "  Missing: ${module}-abi.json"
            fi
            if [ ! -f "$bin_file" ]; then
                log_detail "  Missing: ${module}.bin"
            fi
            missing_modules+=("$module")
            all_found=false
        fi
    done
    
    if $all_found; then
        log_success "All contract artifacts verified!"
        return 0
    else
        log_error "Missing artifacts for: ${missing_modules[*]}"
        return 1
    fi
}

# Create a summary of the build
create_build_summary() {
    local network=$1
    local output_dir="${PROGRAMS_DIR}/build-summary-${network}.txt"
    
    log_info "Creating build summary..."
    
    {
        echo "Build Summary for Network: $network"
        echo "Build Date: $(date)"
        echo "Chain ID: ${CHAIN_IDS[$network]}"
        echo ""
        echo "Contract Artifacts:"
        echo "=================="
        
        for module in "${CONTRACT_MODULES[@]}"; do
            local abi_file="${PROGRAMS_DIR}/${module}/out/release/${module}-abi.json"
            local bin_file="${PROGRAMS_DIR}/${module}/out/release/${module}.bin"
            local bin_root_file="${PROGRAMS_DIR}/${module}/out/release/${module}-bin-root"
            
            if [ -f "$abi_file" ] && [ -f "$bin_file" ]; then
                echo "✓ ${module}"
                echo "  ABI JSON: $(du -h "$abi_file" | cut -f1)"
                echo "  BIN:      $(du -h "$bin_file" | cut -f1)"
                if [ -f "$bin_root_file" ]; then
                    echo "  BIN ROOT: $(du -h "$bin_root_file" | cut -f1)"
                fi
            else
                echo "✗ ${module} - MISSING"
            fi
        done
        
        echo ""
        echo "Total size: $(du -sh "${PROGRAMS_DIR}/*/out" 2>/dev/null | tail -1 | cut -f1)"
    } > "$output_dir"
    
    log_success "Build summary saved to: $output_dir"
}

# Package contracts for deployment
package_contracts() {
    local network=$1
    local package_name="zap-contracts-${network}-$(date +%Y%m%d-%H%M%S).tar.gz"
    
    log_info "Packaging contracts..."
    
    # Create a temporary directory for packaging
    local temp_dir=$(mktemp -d)
    local package_dir="${temp_dir}/zap-contracts-${network}"
    
    mkdir -p "$package_dir"
    
    # Copy all contract outputs
    for module in "${CONTRACT_MODULES[@]}"; do
        local module_out="${PROGRAMS_DIR}/${module}/out"
        if [ -d "$module_out" ]; then
            cp -r "$module_out" "${package_dir}/${module}"
        fi
    done
    
    # Add build info
    {
        echo "Network: $network"
        echo "Chain ID: ${CHAIN_IDS[$network]}"
        echo "Build Date: $(date)"
        echo "forc Version: $(forc --version)"
    } > "${package_dir}/BUILD_INFO.txt"
    
    # Create tarball
    cd "$temp_dir"
    tar -czf "$package_name" "zap-contracts-${network}"
    cd - > /dev/null
    
    # Move to current directory
    mv "${temp_dir}/${package_name}" .
    
    # Cleanup
    rm -rf "$temp_dir"
    
    log_success "Contracts packaged: $package_name"
}

# Show usage information
show_usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  build <network>    Build contracts for specific network"
    echo "  clean              Clean all build artifacts"
    echo "  restore            Restore original wallet_consts.sw"
    echo "  verify             Verify current build outputs"
    echo "  package <network>  Build and package contracts"
    echo "  info               Show network configuration info"
    echo "  help               Show this help message"
    echo ""
    echo "Networks:"
    echo "  mainnet       Chain ID: ${CHAIN_IDS[mainnet]}"
    echo "  testnet       Chain ID: ${CHAIN_IDS[testnet]}"
    echo "  localdevnet   Chain ID: ${CHAIN_IDS[localdevnet]}"
    echo ""
    echo "Examples:"
    echo "  $0 build testnet      # Build for testnet"
    echo "  $0 package mainnet    # Build and package for mainnet"
    echo "  $0 clean              # Clean all artifacts"
    echo "  $0 verify             # Check current build outputs"
}

# Show network info
show_network_info() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    Network Configuration                     ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    printf "%-15s %-15s %-40s\n" "Network" "Chain ID" "Description"
    printf "%-15s %-15s %-40s\n" "-------" "--------" "-----------"
    printf "%-15s %-15s %-40s\n" "mainnet" "${CHAIN_IDS[mainnet]}" "Fuel mainnet (production)"
    printf "%-15s %-15s %-40s\n" "testnet" "${CHAIN_IDS[testnet]}" "Fuel testnet (testing)"
    printf "%-15s %-15s %-40s\n" "localdevnet" "${CHAIN_IDS[localdevnet]}" "Local development (same as mainnet)"
    echo ""
    
    if [ -f "$WALLET_CONSTS_FILE" ]; then
        # Extract just the number from the FUEL_CHAINID line
        local current_id=$(grep "^pub const FUEL_CHAINID: u64 = " "$WALLET_CONSTS_FILE" | sed 's/.*= \([0-9]*\);.*/\1/')
        
        if [ -n "$current_id" ]; then
            echo "Current configuration in wallet_consts.sw:"
            echo "  FUEL_CHAINID: $current_id"

            for network in "${!CHAIN_IDS[@]}"; do
                if [ "${CHAIN_IDS[$network]}" == "$current_id" ]; then
                    echo "  Network: $network"
                    break
                fi
            done
        else
            echo "Unable to read current FUEL_CHAINID from wallet_consts.sw"
        fi
    fi
    echo ""
}

# Main execution
main() {
    local command="${1:-help}"
    
    case "$command" in
        build)
            local network="${2}"
            if [ -z "$network" ]; then
                log_error "Network not specified"
                show_usage
                exit 1
            fi
            
            check_working_directory
            check_forc_installation
            configure_network "$network"
            clean_contracts
            build_contracts "$network"
            verify_build_outputs
            create_build_summary "$network"
            
            echo ""
            log_success "Contracts built successfully for $network!"
            log_detail "Artifacts location: ${PROGRAMS_DIR}/*/out/release/"
            ;;
            
        clean)
            check_working_directory
            clean_contracts
            log_success "Clean completed"
            ;;
            
        restore)
            check_working_directory
            restore_wallet_consts
            ;;
            
        verify)
            check_working_directory
            verify_build_outputs
            ;;
            
        package)
            local network="${2}"
            if [ -z "$network" ]; then
                log_error "Network not specified"
                show_usage
                exit 1
            fi
            
            check_working_directory
            check_forc_installation
            configure_network "$network"
            clean_contracts
            build_contracts "$network"
            
            if verify_build_outputs; then
                package_contracts "$network"
            else
                log_error "Build verification failed, not packaging"
                exit 1
            fi
            ;;
            
        info)
            show_network_info
            ;;
            
        help|--help|-h|"")
            show_usage
            ;;
            
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Show header
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              ZAP Contracts Network Compiler                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Run main function
main "$@"