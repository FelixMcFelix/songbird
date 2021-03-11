//! Temporary global stats + profiling.
use std::sync::atomic::{AtomicU64, Ordering};

static CORE_TASK_COUNT: AtomicU64 = AtomicU64::new(0);
static EVENT_TASK_COUNT: AtomicU64 = AtomicU64::new(0);
static DISPOSAL_TASK_COUNT: AtomicU64 = AtomicU64::new(0);
static MIXER_TASK_COUNT: AtomicU64 = AtomicU64::new(0);
static UDP_RX_TASK_COUNT: AtomicU64 = AtomicU64::new(0);
static UDP_TX_TASK_COUNT: AtomicU64 = AtomicU64::new(0);
static WS_TASK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Prints a list of all active task counts to STDOUT.
pub fn global_songbird_tasks() {
    println!(
        r#"SONGBIRD THREAD STATS:
		CORE_TASK_COUNT: {}
		EVENT_TASK_COUNT: {}
		DISPOSAL_TASK_COUNT: {}
		MIXER_TASK_COUNT: {}
		UDP_RX_TASK_COUNT: {}
		UDP_TX_TASK_COUNT: {}
		WS_TASK_COUNT: {}
		"#,
        CORE_TASK_COUNT.load(Ordering::SeqCst),
        EVENT_TASK_COUNT.load(Ordering::SeqCst),
        DISPOSAL_TASK_COUNT.load(Ordering::SeqCst),
        MIXER_TASK_COUNT.load(Ordering::SeqCst),
        UDP_RX_TASK_COUNT.load(Ordering::SeqCst),
        UDP_TX_TASK_COUNT.load(Ordering::SeqCst),
        WS_TASK_COUNT.load(Ordering::SeqCst),
    )
}

pub(crate) struct CoreTaskToken {
    illegal_init: u8,
}

impl CoreTaskToken {
    pub fn new() -> Self {
        CORE_TASK_COUNT.fetch_add(1, Ordering::SeqCst);
        Self { illegal_init: 0 }
    }
}

impl Drop for CoreTaskToken {
    fn drop(&mut self) {
        CORE_TASK_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) struct EventTaskToken {
    illegal_init: u8,
}

impl EventTaskToken {
    pub fn new() -> Self {
        EVENT_TASK_COUNT.fetch_add(1, Ordering::SeqCst);
        Self { illegal_init: 0 }
    }
}

impl Drop for EventTaskToken {
    fn drop(&mut self) {
        EVENT_TASK_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) struct DisposalTaskToken {
    illegal_init: u8,
}

impl DisposalTaskToken {
    pub fn new() -> Self {
        DISPOSAL_TASK_COUNT.fetch_add(1, Ordering::SeqCst);
        Self { illegal_init: 0 }
    }
}

impl Drop for DisposalTaskToken {
    fn drop(&mut self) {
        DISPOSAL_TASK_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) struct MixerTaskToken {
    illegal_init: u8,
}

impl MixerTaskToken {
    pub fn new() -> Self {
        MIXER_TASK_COUNT.fetch_add(1, Ordering::SeqCst);
        Self { illegal_init: 0 }
    }
}

impl Drop for MixerTaskToken {
    fn drop(&mut self) {
        MIXER_TASK_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) struct UdpRxTaskToken {
    illegal_init: u8,
}

impl UdpRxTaskToken {
    pub fn new() -> Self {
        UDP_RX_TASK_COUNT.fetch_add(1, Ordering::SeqCst);
        Self { illegal_init: 0 }
    }
}

impl Drop for UdpRxTaskToken {
    fn drop(&mut self) {
        UDP_RX_TASK_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) struct UdpTxTaskToken {
    illegal_init: u8,
}

impl UdpTxTaskToken {
    pub fn new() -> Self {
        UDP_TX_TASK_COUNT.fetch_add(1, Ordering::SeqCst);
        Self { illegal_init: 0 }
    }
}

impl Drop for UdpTxTaskToken {
    fn drop(&mut self) {
        UDP_TX_TASK_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}

pub(crate) struct WsTaskToken {
    illegal_init: u8,
}

impl WsTaskToken {
    pub fn new() -> Self {
        WS_TASK_COUNT.fetch_add(1, Ordering::SeqCst);
        Self { illegal_init: 0 }
    }
}

impl Drop for WsTaskToken {
    fn drop(&mut self) {
        WS_TASK_COUNT.fetch_sub(1, Ordering::SeqCst);
    }
}
