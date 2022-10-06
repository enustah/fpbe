use aya_bpf::{bpf_printk, helpers::bpf_get_current_comm, programs::TracePointContext};

/*
reference /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format

format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:int dfd;  offset:16;      size:8; signed:0;
        field:const char * filename;    offset:24;      size:8; signed:0;
        field:int flags;        offset:32;      size:8; signed:0;
        field:umode_t mode;     offset:40;      size:8; signed:0;

*/

pub(crate) fn handle_enter_open_at(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        let comm = bpf_get_current_comm().unwrap();
        let fname_ptr: usize = ctx.read_at(24).unwrap();
        bpf_printk!(
            b"---------------- command: %s openfile: %s",
            comm.as_ptr() as usize,
            fname_ptr
        );
    }
    Ok(0)
}
