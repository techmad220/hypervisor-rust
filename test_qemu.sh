#!/bin/bash
# Test the hypervisor in QEMU with UEFI

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== QEMU Test Environment ===${NC}"

# Check for QEMU
if ! command -v qemu-system-x86_64 &> /dev/null; then
    echo -e "${RED}Error: qemu-system-x86_64 is not installed${NC}"
    echo "Install with: apt-get install qemu-system-x86"
    exit 1
fi

# Check for OVMF (UEFI firmware)
OVMF_PATHS=(
    "/usr/share/ovmf/OVMF.fd"
    "/usr/share/qemu/OVMF.fd"
    "/usr/share/edk2-ovmf/x64/OVMF.fd"
    "/usr/share/OVMF/OVMF.fd"
)

OVMF_PATH=""
for path in "${OVMF_PATHS[@]}"; do
    if [ -f "$path" ]; then
        OVMF_PATH="$path"
        break
    fi
done

if [ -z "$OVMF_PATH" ]; then
    echo -e "${RED}Error: OVMF UEFI firmware not found${NC}"
    echo "Install with: apt-get install ovmf"
    exit 1
fi

echo -e "${GREEN}Found OVMF at: $OVMF_PATH${NC}"

# Check if build exists
if [ ! -d "build/esp" ]; then
    echo -e "${YELLOW}Build not found. Running build script...${NC}"
    ./build.sh
fi

# Create disk image from ESP
echo -e "${YELLOW}Creating disk image...${NC}"
DISK_IMG="build/test_disk.img"
ESP_SIZE=$(du -sm build/esp | cut -f1)
DISK_SIZE=$((ESP_SIZE + 50))  # Add 50MB padding

# Create disk image
dd if=/dev/zero of=$DISK_IMG bs=1M count=$DISK_SIZE status=none

# Create GPT partition
echo -e "${YELLOW}Creating GPT partition...${NC}"
(
echo g      # Create GPT
echo n      # New partition
echo 1      # Partition 1
echo 2048   # First sector
echo        # Last sector (default)
echo t      # Change type
echo 1      # EFI System
echo w      # Write
) | fdisk $DISK_IMG > /dev/null 2>&1

# Format and copy files (requires loop device)
if command -v losetup &> /dev/null; then
    echo -e "${YELLOW}Mounting and copying files...${NC}"
    LOOP_DEV=$(sudo losetup -f)
    sudo losetup -P $LOOP_DEV $DISK_IMG
    sudo mkfs.fat -F 32 ${LOOP_DEV}p1 2>/dev/null
    
    # Mount and copy
    MOUNT_POINT=$(mktemp -d)
    sudo mount ${LOOP_DEV}p1 $MOUNT_POINT
    sudo cp -r build/esp/* $MOUNT_POINT/
    sudo umount $MOUNT_POINT
    sudo losetup -d $LOOP_DEV
    rmdir $MOUNT_POINT
    
    echo -e "${GREEN}✓ Disk image prepared${NC}"
else
    echo -e "${YELLOW}Warning: Cannot mount loop device. Using raw image.${NC}"
fi

# QEMU parameters
QEMU_ARGS=(
    # System
    -machine q35,accel=kvm:tcg
    -cpu host,+vmx,+svm
    -m 4G
    -smp 4
    
    # UEFI firmware
    -bios $OVMF_PATH
    
    # Storage
    -drive file=$DISK_IMG,format=raw,if=none,id=disk0
    -device ahci,id=ahci0
    -device ide-hd,drive=disk0,bus=ahci0.0
    
    # Display
    -vga std
    -display sdl
    
    # Debugging
    -debugcon file:debug.log
    -global isa-debugcon.iobase=0x402
    
    # Monitor
    -monitor stdio
    
    # Network (optional)
    -netdev user,id=net0
    -device e1000,netdev=net0
)

# Add additional debugging if requested
if [ "$1" == "--debug" ]; then
    QEMU_ARGS+=(
        -s
        -S
        -d int,cpu_reset
        -D qemu_debug.log
    )
    echo -e "${YELLOW}Debug mode enabled. GDB can connect to localhost:1234${NC}"
fi

# Run QEMU
echo -e "${GREEN}Starting QEMU...${NC}"
echo "Press Ctrl+A, X to exit"
echo ""

qemu-system-x86_64 "${QEMU_ARGS[@]}"

# Cleanup
echo ""
echo -e "${GREEN}Test completed.${NC}"
if [ -f debug.log ]; then
    echo "Debug output saved to: debug.log"
fi
if [ -f qemu_debug.log ]; then
    echo "QEMU debug log saved to: qemu_debug.log"
fi