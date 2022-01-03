#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
pub struct DockerLog {
    pub count: usize,
    pub data: [u8; 32],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DockerLog {}
