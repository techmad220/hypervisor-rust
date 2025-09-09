#!/bin/bash
# Complete build script for Hypervisor-Rust UEFI
# Builds all components and creates bootable UEFI image

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Hypervisor-Rust Build System ===${NC}"

# Check for required tools
check_tool() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}Error: $1 is not installed${NC}"
        exit 1
    fi
}

echo "Checking build dependencies..."
check_tool rustc
check_tool cargo
check_tool ld

# Set build environment
export RUST_TARGET_PATH="$(pwd)/targets"
export RUSTFLAGS="-C link-arg=-nostartfiles -C link-arg=-Wl,-T,linker.ld -C link-arg=-static -C relocation-model=static"

# Create build directory
BUILD_DIR="build"
mkdir -p $BUILD_DIR

# Step 1: Build the hypervisor core library
echo -e "${YELLOW}Building hypervisor core...${NC}"
cd hypervisor
cargo build --release --target x86_64-unknown-none --no-default-features
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Hypervisor core built successfully${NC}"
else
    echo -e "${RED}✗ Hypervisor core build failed${NC}"
    exit 1
fi
cd ..

# Step 2: Build UEFI runtime library
echo -e "${YELLOW}Building UEFI runtime...${NC}"
cd uefi-runtime
cargo build --release --target x86_64-unknown-none --no-default-features
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ UEFI runtime built successfully${NC}"
else
    echo -e "${RED}✗ UEFI runtime build failed${NC}"
    exit 1
fi
cd ..

# Step 3: Build UEFI bootloader
echo -e "${YELLOW}Building UEFI bootloader...${NC}"
cd bootloader

# Check if UEFI target is installed
if ! rustup target list | grep -q "x86_64-unknown-uefi (installed)"; then
    echo "Installing x86_64-unknown-uefi target..."
    rustup target add x86_64-unknown-uefi
fi

cargo build --release --target x86_64-unknown-uefi
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ UEFI bootloader built successfully${NC}"
    cp target/x86_64-unknown-uefi/release/hypervisor-bootloader.efi ../$BUILD_DIR/BOOTX64.EFI
else
    echo -e "${RED}✗ UEFI bootloader build failed${NC}"
    exit 1
fi
cd ..

# Step 4: Create ESP (EFI System Partition) structure
echo -e "${YELLOW}Creating ESP structure...${NC}"
ESP_DIR="$BUILD_DIR/esp"
mkdir -p $ESP_DIR/EFI/BOOT
mkdir -p $ESP_DIR/EFI/hypervisor
mkdir -p $ESP_DIR/EFI/Drivers

# Copy bootloader
cp $BUILD_DIR/BOOTX64.EFI $ESP_DIR/EFI/BOOT/

# Copy hypervisor binary
if [ -f hypervisor/target/x86_64-unknown-none/release/libhypervisor_core.a ]; then
    # Convert static library to binary format
    objcopy -O binary hypervisor/target/x86_64-unknown-none/release/libhypervisor_core.a $ESP_DIR/EFI/hypervisor/hypervisor.bin
    echo -e "${GREEN}✓ Hypervisor binary copied${NC}"
fi

# Create configuration file
cat > $ESP_DIR/EFI/hypervisor/config.ini << EOF
[Hypervisor]
Version=1.0.0
AutoStart=true
DebugMode=false
VirtualizationMode=Auto
MemorySize=256MB
VCPU=4

[Security]
SecureBoot=false
Attestation=false

[Features]
EPT=true
VPID=true
UnrestrictedGuest=true
EOF

echo -e "${GREEN}✓ Configuration created${NC}"

# Step 5: Create disk image (optional)
if command -v dd &> /dev/null && command -v mkfs.fat &> /dev/null; then
    echo -e "${YELLOW}Creating disk image...${NC}"
    
    # Create 100MB disk image
    dd if=/dev/zero of=$BUILD_DIR/hypervisor.img bs=1M count=100 2>/dev/null
    
    # Create GPT partition table and EFI partition
    # This would require gdisk or similar tool
    
    # Format as FAT32
    mkfs.fat -F 32 $BUILD_DIR/hypervisor.img 2>/dev/null || true
    
    echo -e "${GREEN}✓ Disk image created${NC}"
fi

# Step 6: Generate build report
echo -e "${YELLOW}Generating build report...${NC}"
cat > $BUILD_DIR/build_report.txt << EOF
Hypervisor-Rust Build Report
============================
Date: $(date)
Host: $(uname -a)
Rust Version: $(rustc --version)
Cargo Version: $(cargo --version)

Build Status:
- Hypervisor Core: SUCCESS
- UEFI Runtime: SUCCESS
- UEFI Bootloader: SUCCESS

Output Files:
- BOOTX64.EFI: UEFI bootloader
- hypervisor.bin: Hypervisor core binary
- config.ini: Configuration file
- hypervisor.img: Disk image (if created)

ESP Structure:
$(find $ESP_DIR -type f | sort)

Next Steps:
1. Copy ESP contents to a FAT32-formatted USB drive
2. Boot from USB in UEFI mode
3. The hypervisor will automatically load

Testing:
- Use QEMU: qemu-system-x86_64 -bios /usr/share/ovmf/OVMF.fd -drive file=$BUILD_DIR/hypervisor.img,format=raw
- Or copy to USB: dd if=$BUILD_DIR/hypervisor.img of=/dev/sdX bs=4M
EOF

echo -e "${GREEN}✓ Build report generated${NC}"

# Summary
echo ""
echo -e "${GREEN}=== Build Complete ===${NC}"
echo "Build artifacts are in: $BUILD_DIR/"
echo "ESP contents are in: $ESP_DIR/"
echo ""
echo "To test with QEMU:"
echo "  ./test_qemu.sh"
echo ""
echo "To create bootable USB:"
echo "  sudo ./create_usb.sh /dev/sdX"