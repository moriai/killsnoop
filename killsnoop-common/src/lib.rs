#![no_std]

#[repr(C)]
#[derive(Copy,Clone)]
pub struct SignalLog {
    pub pid: u32,       // Process ID
    pub tid: u32,       // Thread ID
    pub tpid: i32,      // Target PID
    pub tsig: u32,      // Signal
    pub comm: [i8; 16], // Command Name
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SignalLog {}
