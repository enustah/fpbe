#![no_std]
#![no_main]

use aya_bpf::{macros::tracepoint, programs::TracePointContext};

/*
reference /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format

format:
    field:unsigned short common_type;	offset:0;	size:2;	signed:0;
    field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
    field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
    field:int common_pid;	offset:4;	size:4;	signed:1;

    field:int __syscall_nr;	offset:8;	size:4;	signed:1;
    field:const char * filename;	offset:16;	size:8;	signed:0;
    field:int flags;	offset:24;	size:8;	signed:0;
    field:umode_t mode;	offset:32;	size:8;	signed:0;

*/

mod execve;
mod openat;

#[tracepoint(name = "enter_open_at")]
pub fn enter_open_at(ctx: TracePointContext) -> u32 {
    match openat::handle_enter_open_at(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint(name = "enter_execve")]
pub fn enter_execve(ctx: TracePointContext) -> u32 {
    match execve::handle_enter_execve(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
