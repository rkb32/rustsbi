//! Secure Memory Manager Hardware Protectors
//!
//! Implementation of `SecMemProtector` using RISC-V PMP with **NAPOT** mode.
//! Manages hardware isolation for **RT** (Runtime) and **APP** (Application) enclaves.
//! Includes `TestSecMemProtector` for mock testing and `SecMemProtectorByPMP` for production HAL.
//! Supports **RWX** permission toggling and cross-core **sync**.

use super::SecMemProtector;
use core::usize;
use pmpm::{
    PmpConfig, PmpSlot, bitmap::PMPSlotAllocator, check_pmp_area_available, disable_pmp_entry_sync,
    set_pmp_entry, set_pmp_entry_sync,
};
use riscv::register::{Permission, Range};

pub struct TestSecMemProtector {
    hw_manager: PMPSlotAllocator,
}

impl TestSecMemProtector {
    pub fn new(alloc_mask: u64, manage_mask: u64) -> Self {
        Self {
            hw_manager: (PMPSlotAllocator::new(alloc_mask, manage_mask)),
        }
    }
}

impl SecMemProtector for TestSecMemProtector {
    fn with_masks(alloc_mask: u64, manage_mask: u64) -> Self {
        Self::new(alloc_mask, manage_mask)
    }
    fn is_protectable(&self, addr: usize, len: usize) -> bool {
        check_pmp_area_available(addr, len, Range::NAPOT)
    }
    fn alloc(&mut self) -> Option<PmpSlot> {
        match self.hw_manager.alloc() {
            Ok(slot) => Some(slot),
            Err(_) => None,
        }
    }
    fn free(&mut self, hwid: PmpSlot) -> bool {
        match self.hw_manager.free(hwid) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
    fn disable(&self, hwid: PmpSlot) -> bool {
        let _ = hwid;
        true
    }
    fn enable(&self, hwid: PmpSlot) -> bool {
        let _ = hwid;
        true
    }
    fn grant_access(&self, addr: usize, len: usize, hwid: PmpSlot) -> bool {
        let _ = hwid;
        let _ = addr;
        let _ = len;
        true
    }
    fn grant_access_all(&self, addr: usize, len: usize, hwid: PmpSlot) -> bool {
        let _ = hwid;
        let _ = addr;
        let _ = len;
        true
    }
    fn retrive_access(&self, addr: usize, len: usize, hwid: PmpSlot) -> bool {
        let _ = hwid;
        let _ = addr;
        let _ = len;
        true
    }
    fn retrive_access_all(&self, addr: usize, len: usize, hwid: PmpSlot) -> bool {
        let _ = hwid;
        let _ = addr;
        let _ = len;
        true
    }
}

pub type SecMemProtectorByPMP = PMPSlotAllocator;

impl SecMemProtector for SecMemProtectorByPMP {
    fn with_masks(alloc_mask: u64, manage_mask: u64) -> Self {
        Self::new(alloc_mask, manage_mask)
    }
    fn is_protectable(&self, addr: usize, len: usize) -> bool {
        check_pmp_area_available(addr, len, Range::NAPOT)
    }
    fn alloc(&mut self) -> Option<PmpSlot> {
        match self.alloc() {
            Ok(slot) => Some(slot),
            Err(_) => None,
        }
    }
    fn free(&mut self, hwid: PmpSlot) -> bool {
        match self.free(hwid) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
    fn disable(&self, hwid: PmpSlot) -> bool {
        self.is_managed(hwid) && disable_pmp_entry_sync(hwid)
    }
    /// Not implemented as a real operation: nothing calls it, and with the current
    /// zero-length call it returns `false` instead of panicking. See #502.
    fn enable(&self, hwid: PmpSlot) -> bool {
        self.is_managed(hwid)
            && set_pmp_entry_sync(
                hwid,
                0,
                0,
                &PmpConfig::new(Range::NAPOT, Permission::RWX, false),
            )
    }
    fn grant_access(&self, addr: usize, len: usize, hwid: PmpSlot) -> bool {
        self.is_managed(hwid)
            && set_pmp_entry(
                hwid,
                addr,
                len,
                &PmpConfig::new(Range::NAPOT, Permission::RWX, false),
            )
    }
    fn retrive_access(&self, addr: usize, len: usize, hwid: PmpSlot) -> bool {
        self.is_managed(hwid)
            && set_pmp_entry(
                hwid,
                addr,
                len,
                &PmpConfig::new(Range::NAPOT, Permission::NONE, false),
            )
    }
    fn grant_access_all(&self, addr: usize, len: usize, hwid: PmpSlot) -> bool {
        self.is_managed(hwid)
            && set_pmp_entry_sync(
                hwid,
                addr,
                len,
                &PmpConfig::new(Range::NAPOT, Permission::RWX, false),
            )
    }
    fn retrive_access_all(&self, addr: usize, len: usize, hwid: PmpSlot) -> bool {
        self.is_managed(hwid)
            && set_pmp_entry_sync(
                hwid,
                addr,
                len,
                &PmpConfig::new(Range::NAPOT, Permission::NONE, false),
            )
    }
}
