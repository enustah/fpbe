use aya_bpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    programs::TracePointContext,
};

use crate::common::socket_trace::{SyscallSrcFunc, TrafficDirection};
use crate::common::{map::active_write_args_map, socket_trace::DataArgT};

/*
reference /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format

format:
    field:unsigned short common_type;	offset:0;	size:2;	signed:0;
    field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
    field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
    field:int common_pid;	offset:4;	size:4;	signed:1;

    field:int __syscall_nr;	offset:8;	size:4;	signed:1;
    field:unsigned int fd;	offset:16;	size:8;	signed:0;
    field:const char * buf;	offset:24;	size:8;	signed:0;
    field:size_t count;	offset:32;	size:8;	signed:0;

*/

pub(crate) fn handle_sys_enter_write(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        let pid: u64 = bpf_get_current_pid_tgid();
        let fd: u32 = ctx.read_at(16).map_err(|err| return err as u32)?;
        let buf: *const [u8] = ctx.read_at(24).map_err(|err| return err as u32)?;
        let write_args = DataArgT {
            syscall_src_func: SyscallSrcFunc::WRITEV,
            fd,
            buf,
            enter_ts: bpf_ktime_get_ns(),
        };
        active_write_args_map
            .insert(&pid, &write_args, 0)
            .map_err(|err| return err as u32)?;
    }

    return Ok(0);
}



/*
reference /sys/kernel/debug/tracing/events/syscalls/sys_exit_write/format

format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;
*/
pub(crate) fn handle_sys_exit_write(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe{
        let pid: u64 = bpf_get_current_pid_tgid();
        let write_arg = active_write_args_map.get(&pid).ok_or(1u32)?;
        let byte_count:i64 = ctx.read_at(16).map_err(|err|{return err as u32})?;
        handle_sys_exit_data(ctx,pid,TrafficDirection::EGRESS,write_arg,byte_count as u32);
        active_write_args_map.remove(&pid);
    }
    return Ok(0);
}

unsafe fn handle_sys_exit_data(ctx: TracePointContext,pid:u64,dir:TrafficDirection,write_arg: &DataArgT,data_len:u32){
    // TODO proress data.

}