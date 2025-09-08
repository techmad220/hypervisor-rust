//! Disk serial, MBR signature, and GPT GUID spoofing

use uefi::prelude::*;
use uefi::proto::media::block::BlockIo;
use log::info;
use alloc::vec::Vec;

#[repr(C, packed)]
struct GptHeader {
    signature: [u8; 8],
    revision: u32,
    header_size: u32,
    crc32: u32,
    reserved: u32,
    my_lba: u64,
    alternate_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: [u8; 16],
    partition_entry_lba: u64,
    number_of_partition_entries: u32,
    size_of_partition_entry: u32,
    partition_entry_array_crc32: u32,
}

#[repr(C, packed)]
struct GptPartitionEntry {
    partition_type_guid: [u8; 16],
    unique_partition_guid: [u8; 16],
    starting_lba: u64,
    ending_lba: u64,
    attributes: u64,
    partition_name: [u16; 36],
}

/// Override all disk serials
pub fn override_all_disk_serials() {
    info!("[Disk] Starting disk serial spoofing...");
    
    let bt = unsafe { uefi::table::boot::BootServices::unsafe_clone() };
    
    let handles = match bt.locate_handle_buffer(
        uefi::table::boot::SearchType::ByProtocol(&BlockIo::GUID)
    ) {
        Ok(h) => h,
        Err(_) => {
            info!("[Disk] No block devices found");
            return;
        }
    };
    
    for handle in handles.handles() {
        if let Ok(mut block_io) = bt.open_protocol_exclusive::<BlockIo>(*handle) {
            let media = block_io.media();
            let block_size = media.block_size() as usize;
            
            // Read first block
            let mut buffer = vec![0u8; block_size];
            if block_io.read_blocks(media.media_id(), 0, &mut buffer).is_ok() {
                // Spoof serial in ATA identify data location (offset 20*2)
                if buffer.len() >= 60 {
                    let serial = crate::random_ascii_string(20);
                    buffer[40..60].copy_from_slice(&serial);
                    
                    // Write back
                    let _ = block_io.write_blocks(media.media_id(), 0, &buffer);
                }
            }
        }
    }
    
    info!("[Disk] Disk serial spoofing completed");
}

/// Override MBR signatures
pub fn override_mbr_signatures() {
    info!("[Disk] Starting MBR signature spoofing...");
    
    let bt = unsafe { uefi::table::boot::BootServices::unsafe_clone() };
    
    let handles = match bt.locate_handle_buffer(
        uefi::table::boot::SearchType::ByProtocol(&BlockIo::GUID)
    ) {
        Ok(h) => h,
        Err(_) => return,
    };
    
    let seed = *crate::SPOOF_SEED.lock();
    
    for handle in handles.handles() {
        if let Ok(mut block_io) = bt.open_protocol_exclusive::<BlockIo>(*handle) {
            let media = block_io.media();
            
            // Read MBR
            let mut mbr = vec![0u8; 512];
            if block_io.read_blocks(media.media_id(), 0, &mut mbr).is_ok() {
                // Spoof disk signature at offset 440
                if mbr.len() >= 444 {
                    let signature = (seed ^ media.media_id() as u64) as u32;
                    mbr[440..444].copy_from_slice(&signature.to_le_bytes());
                    
                    // Write back
                    let _ = block_io.write_blocks(media.media_id(), 0, &mbr);
                }
            }
        }
    }
    
    info!("[Disk] MBR signature spoofing completed");
}

/// Spoof GPT partition GUIDs
pub fn spoof_gpt_partition_guids() {
    info!("[Disk] Starting GPT GUID spoofing...");
    
    let bt = unsafe { uefi::table::boot::BootServices::unsafe_clone() };
    
    let handles = match bt.locate_handle_buffer(
        uefi::table::boot::SearchType::ByProtocol(&BlockIo::GUID)
    ) {
        Ok(h) => h,
        Err(_) => return,
    };
    
    for handle in handles.handles() {
        if let Ok(mut block_io) = bt.open_protocol_exclusive::<BlockIo>(*handle) {
            let media = block_io.media();
            let block_size = media.block_size() as usize;
            
            // Read GPT header (LBA 1)
            let mut header_buf = vec![0u8; block_size];
            if block_io.read_blocks(media.media_id(), 1, &mut header_buf).is_err() {
                continue;
            }
            
            // Check if it's GPT
            if &header_buf[0..8] != b"EFI PART" {
                continue;
            }
            
            let header = unsafe { &mut *(header_buf.as_mut_ptr() as *mut GptHeader) };
            
            // Spoof disk GUID
            let disk_guid = crate::random_guid();
            header.disk_guid.copy_from_slice(disk_guid.as_bytes());
            
            // Read partition entries
            let entry_count = header.number_of_partition_entries as usize;
            let entry_size = header.size_of_partition_entry as usize;
            let entries_size = entry_count * entry_size;
            let mut entries_buf = vec![0u8; entries_size];
            
            if block_io.read_blocks(
                media.media_id(),
                header.partition_entry_lba,
                &mut entries_buf
            ).is_ok() {
                // Spoof each partition GUID
                for i in 0..entry_count {
                    let entry_ptr = unsafe {
                        entries_buf.as_mut_ptr().add(i * entry_size) as *mut GptPartitionEntry
                    };
                    
                    let entry = unsafe { &mut *entry_ptr };
                    
                    // Skip empty entries
                    if entry.partition_type_guid == [0u8; 16] {
                        continue;
                    }
                    
                    // Randomize GUIDs
                    let type_guid = crate::random_guid();
                    let unique_guid = crate::random_guid();
                    
                    entry.partition_type_guid.copy_from_slice(type_guid.as_bytes());
                    entry.unique_partition_guid.copy_from_slice(unique_guid.as_bytes());
                }
                
                // Write entries back
                let _ = block_io.write_blocks(
                    media.media_id(),
                    header.partition_entry_lba,
                    &entries_buf
                );
            }
            
            // Recalculate CRC32
            header.crc32 = 0;
            let crc = calculate_crc32(&header_buf[0..header.header_size as usize]);
            header.crc32 = crc;
            
            // Write header back
            let _ = block_io.write_blocks(media.media_id(), 1, &header_buf);
        }
    }
    
    info!("[Disk] GPT GUID spoofing completed");
}

fn calculate_crc32(data: &[u8]) -> u32 {
    const CRC32_POLY: u32 = 0xEDB88320;
    let mut crc = 0xFFFFFFFF;
    
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC32_POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    
    !crc
}