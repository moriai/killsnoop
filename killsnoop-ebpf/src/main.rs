#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_comm},
    macros::{tracepoint, map},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use core::convert::TryInto;
use killsnoop_common::SignalLog;

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<SignalLog> = PerfEventArray::<SignalLog>::with_max_entries(1024, 0);

#[tracepoint(name="killsnoop")]
pub fn killsnoop(ctx: TracePointContext) -> u32 {
    match unsafe { try_killsnoop(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_killsnoop(ctx: TracePointContext) -> Result<u32, u32> {
    let tsig = ctx.read_at::<u64>(24).unwrap() as u32;
    if tsig == 0 { return Ok(0); }
    let tpid = ctx.read_at::<i64>(16).unwrap() as i32;
    let pid = (bpf_get_current_pid_tgid() >> 32).try_into().unwrap();
    let tid = bpf_get_current_pid_tgid() as u32;
    let comm = bpf_get_current_comm().unwrap();

    let log_entry = SignalLog { pid, tid, tpid, tsig, comm };
    EVENTS.output(&ctx, &log_entry, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
