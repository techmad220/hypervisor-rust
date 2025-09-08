//! Network MAC address spoofing

use uefi::prelude::*;
use uefi::proto::network::SimpleNetwork;
use log::info;

/// Override all network MACs
pub fn override_all_network_macs() {
    info!("[Network] Starting MAC address spoofing...");
    
    let bt = unsafe { uefi::table::boot::BootServices::unsafe_clone() };
    
    let handles = match bt.locate_handle_buffer(
        uefi::table::boot::SearchType::ByProtocol(&SimpleNetwork::GUID)
    ) {
        Ok(h) => h,
        Err(_) => {
            info!("[Network] No network devices found");
            return;
        }
    };
    
    for handle in handles.handles() {
        if let Ok(mut snp) = bt.open_protocol_exclusive::<SimpleNetwork>(*handle) {
            let mac = crate::generate_random_mac();
            
            // Reset network interface
            let _ = snp.reset(false);
            let _ = snp.start();
            
            // Set new MAC address
            if snp.station_address(Some(&mac), false).is_ok() {
                info!("[Network] Spoofed MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            }
            
            let _ = snp.stop();
        }
    }
    
    info!("[Network] MAC address spoofing completed");
}