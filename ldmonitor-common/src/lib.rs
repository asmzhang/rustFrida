#![no_std]

pub const MAX_PATH_LEN: usize = 256;
pub const LDMON_MAX_PATH_LEN: usize = MAX_PATH_LEN;

pub const LDMON_MAGIC: u32 = 0x4c44_4d4e;
pub const LDMON_PROTO_VERSION: u16 = 1;

pub const LDMON_CMD_HELLO: u16 = 0x0001;
pub const LDMON_CMD_GET_CAPS: u16 = 0x0002;
pub const LDMON_CMD_SET_FILTER: u16 = 0x0003;
pub const LDMON_CMD_START: u16 = 0x0004;
pub const LDMON_CMD_STOP: u16 = 0x0005;

pub const LDMON_CAP_READ_EVENTS: u32 = 1 << 0;
pub const LDMON_CAP_PROC_DEBUG: u32 = 1 << 1;
pub const LDMON_CAP_NETLINK_EVENTS: u32 = 1 << 2;

pub const LDMON_NL_VERSION: u32 = 1;
pub const LDMON_NL_MSG_SUBSCRIBE: u32 = 0;
pub const LDMON_NL_MSG_EVENT_DLOPEN: u32 = 1;
pub const LDMON_NL_MSG_UNSUBSCRIBE: u32 = 255;
pub const LDMON_NL_PROTO_PRIMARY: i32 = 31;
pub const LDMON_NL_PROTO_FALLBACK: i32 = 30;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LdmMsgHeader {
    pub magic: u32,
    pub version: u16,
    pub cmd: u16,
    pub flags: u32,
    pub len: u32,
}

impl LdmMsgHeader {
    pub const fn new(cmd: u16, flags: u32, len: u32) -> Self {
        Self {
            magic: LDMON_MAGIC,
            version: LDMON_PROTO_VERSION,
            cmd,
            flags,
            len,
        }
    }

    pub const fn is_valid(&self) -> bool {
        self.magic == LDMON_MAGIC && self.version == LDMON_PROTO_VERSION
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DlopenEvent {
    pub pid: u32,
    pub uid: u32,
    pub path_len: u32,
    pub path: [u8; MAX_PATH_LEN],
}

impl DlopenEvent {
    pub fn path_str(&self) -> &str {
        decode_path(&self.path, self.path_len)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LdmFilter {
    pub target_pid: u32,
    pub path_substr_len: u32,
    pub path_substr: [u8; MAX_PATH_LEN],
}

impl LdmFilter {
    pub const fn empty() -> Self {
        Self {
            target_pid: 0,
            path_substr_len: 0,
            path_substr: [0; MAX_PATH_LEN],
        }
    }

    pub fn path_substr(&self) -> &str {
        decode_path(&self.path_substr, self.path_substr_len)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LdmCaps {
    pub version: u16,
    pub reserved: u16,
    pub flags: u32,
}

impl LdmCaps {
    pub const fn new(flags: u32) -> Self {
        Self {
            version: LDMON_PROTO_VERSION,
            reserved: 0,
            flags,
        }
    }

    pub const fn supports(&self, capability: u32) -> bool {
        (self.flags & capability) != 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LdmNlEvent {
    pub version: u32,
    pub msg_type: u32,
    pub pid: u32,
    pub uid: u32,
    pub path_len: u32,
    pub reserved: u32,
    pub path: [u8; LDMON_MAX_PATH_LEN],
}

impl LdmNlEvent {
    pub fn path_str(&self) -> &str {
        decode_path(&self.path, self.path_len)
    }
}

fn decode_path(path: &[u8], path_len: u32) -> &str {
    let len = (path_len as usize).min(path.len());
    let actual_len = path[..len].iter().position(|&b| b == 0).unwrap_or(len);
    core::str::from_utf8(&path[..actual_len]).unwrap_or("")
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DlopenEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LdmMsgHeader {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LdmFilter {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LdmCaps {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LdmNlEvent {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_protocol_constants_match_expected_values() {
        assert_eq!(LDMON_MAGIC, 0x4c44_4d4e);
        assert_eq!(LDMON_PROTO_VERSION, 1);
        assert_eq!(LDMON_CMD_HELLO, 0x0001);
        assert_eq!(LDMON_CMD_GET_CAPS, 0x0002);
        assert_eq!(LDMON_CMD_SET_FILTER, 0x0003);
        assert_eq!(LDMON_CMD_START, 0x0004);
        assert_eq!(LDMON_CMD_STOP, 0x0005);
        assert_eq!(LDMON_CAP_READ_EVENTS, 1);
        assert_eq!(LDMON_CAP_PROC_DEBUG, 2);
        assert_eq!(LDMON_CAP_NETLINK_EVENTS, 4);
    }

    #[test]
    fn control_struct_layouts_are_stable() {
        assert_eq!(core::mem::size_of::<LdmMsgHeader>(), 16);
        assert_eq!(core::mem::size_of::<LdmFilter>(), 264);
        assert_eq!(core::mem::size_of::<LdmCaps>(), 8);
        assert_eq!(core::mem::size_of::<DlopenEvent>(), 268);
    }

    #[test]
    fn header_constructor_and_validation_work() {
        let header = LdmMsgHeader::new(LDMON_CMD_START, 0x12, 0x34);

        assert_eq!(header.magic, LDMON_MAGIC);
        assert_eq!(header.version, LDMON_PROTO_VERSION);
        assert_eq!(header.cmd, LDMON_CMD_START);
        assert_eq!(header.flags, 0x12);
        assert_eq!(header.len, 0x34);
        assert!(header.is_valid());
    }

    #[test]
    fn caps_supports_flags() {
        let caps = LdmCaps::new(LDMON_CAP_READ_EVENTS | LDMON_CAP_PROC_DEBUG);

        assert!(caps.supports(LDMON_CAP_READ_EVENTS));
        assert!(caps.supports(LDMON_CAP_PROC_DEBUG));
        assert!(!caps.supports(LDMON_CAP_NETLINK_EVENTS));
    }

    #[test]
    fn netlink_protocol_constants_match_expected_values() {
        assert_eq!(LDMON_NL_VERSION, 1);
        assert_eq!(LDMON_NL_MSG_SUBSCRIBE, 0);
        assert_eq!(LDMON_NL_MSG_EVENT_DLOPEN, 1);
        assert_eq!(LDMON_NL_MSG_UNSUBSCRIBE, 255);
        assert_eq!(LDMON_NL_PROTO_PRIMARY, 31);
        assert_eq!(LDMON_NL_PROTO_FALLBACK, 30);
        assert_eq!(LDMON_MAX_PATH_LEN, 256);
    }

    #[test]
    fn netlink_event_layout_is_stable() {
        assert_eq!(core::mem::size_of::<LdmNlEvent>(), 280);
    }

    #[test]
    fn dlopen_event_path_str_respects_length_and_nul() {
        let mut event = DlopenEvent {
            pid: 456,
            uid: 10000,
            path_len: 32,
            path: [0; MAX_PATH_LEN],
        };

        let path = b"/data/app/lib/arm64/libbar.so\0garbage";
        event.path[..path.len()].copy_from_slice(path);

        assert_eq!(event.path_str(), "/data/app/lib/arm64/libbar.so");
    }

    #[test]
    fn filter_path_str_respects_length_and_nul() {
        let mut filter = LdmFilter::empty();
        filter.path_substr_len = 24;
        let needle = b"libnative-lib.so\0padding";
        filter.path_substr[..needle.len()].copy_from_slice(needle);

        assert_eq!(filter.path_substr(), "libnative-lib.so");
    }

    #[test]
    fn netlink_event_path_str_respects_length_and_nul() {
        let mut event = LdmNlEvent {
            version: LDMON_NL_VERSION,
            msg_type: LDMON_NL_MSG_EVENT_DLOPEN,
            pid: 123,
            uid: 10000,
            path_len: 32,
            reserved: 0,
            path: [0; LDMON_MAX_PATH_LEN],
        };

        let path = b"/data/app/lib/arm64/libfoo.so\0garbage";
        event.path[..path.len()].copy_from_slice(path);

        assert_eq!(event.path_str(), "/data/app/lib/arm64/libfoo.so");
    }
}
