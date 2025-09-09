/* Linker script for Hypervisor-Rust */
/* Memory layout for x86_64 bare metal hypervisor */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(hypervisor_entry)

/* Define memory regions */
MEMORY
{
    /* Hypervisor loaded at 16MB mark */
    HYPERVISOR_ROM (rx) : ORIGIN = 0x1000000, LENGTH = 16M
    HYPERVISOR_RAM (rw) : ORIGIN = 0x2000000, LENGTH = 16M
    STACK (rw) : ORIGIN = 0x3000000, LENGTH = 2M
}

/* Define sections */
SECTIONS
{
    /* Code section */
    .text : ALIGN(4K)
    {
        *(.text.entry)
        *(.text .text.*)
    } > HYPERVISOR_ROM

    /* Read-only data */
    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
    } > HYPERVISOR_ROM

    /* Exception handling */
    .eh_frame : ALIGN(4K)
    {
        KEEP(*(.eh_frame))
    } > HYPERVISOR_ROM

    /* Data section */
    .data : ALIGN(4K)
    {
        *(.data .data.*)
    } > HYPERVISOR_RAM AT> HYPERVISOR_ROM

    /* BSS section */
    .bss : ALIGN(4K)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } > HYPERVISOR_RAM

    /* Stack section */
    .stack : ALIGN(4K)
    {
        __stack_start = .;
        . = . + 0x200000; /* 2MB stack */
        __stack_end = .;
    } > STACK

    /* Discard unwanted sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.note.*)
    }
}

/* Export symbols */
PROVIDE(__hypervisor_start = ORIGIN(HYPERVISOR_ROM));
PROVIDE(__hypervisor_end = ORIGIN(HYPERVISOR_RAM) + LENGTH(HYPERVISOR_RAM));
PROVIDE(__stack_top = __stack_end);