#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum EventType{
    Exec = 1,
    Exit = 2,
    Fork = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessEvent{
    pub event_type: EventType,
    pub pid: u32,
    pub tgid: u32,
    pub parent_pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
    pub filename_len: u32,
}
