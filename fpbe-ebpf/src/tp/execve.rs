use aya_bpf::{bpf_printk, helpers::bpf_get_current_comm, programs::TracePointContext};

/*
reference /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format

format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:const char * filename;    offset:16;      size:8; signed:0;
        field:const char *const * argv; offset:24;      size:8; signed:0;
        field:const char *const * envp; offset:32;      size:8; signed:0;

*/

pub(crate) fn handle_enter_execve(ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        let comm = bpf_get_current_comm().unwrap();

        let exec_comm: usize = ctx.read_at(16).unwrap();
        // let arg_ptr:usize  = ctx.read_at(24).unwrap();

        bpf_printk!(
            b"---------------- command: %s execve: %s",
            comm.as_ptr(),
            exec_comm
        );
    }
    Ok(0)
}
