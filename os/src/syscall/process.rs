//! Process management syscalls
use crate::config::PAGE_SIZE;
use crate::mm::{MapPermission, VirtAddr, is_user_readable, is_user_writable, translated_byte_buffer};
use crate::task::{change_program_brk, current_user_token, exit_current_and_run_next, get_count, get_current_task_id, suspend_current_and_run_next,with_current_task};
use crate::timer::get_time_us;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    let t_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };


    let size = 16;
    let token = current_user_token();
    let buffers = translated_byte_buffer(token, _ts as *const u8, size);

    let time_bytes = unsafe {
        core::slice::from_raw_parts(
            &t_val as *const TimeVal as *const u8,
            size
        )
    };

    let mut offset = 0;
    for buf in buffers {
        let len = buf.len();
        if offset + len > time_bytes.len() {
            return -1; // 缓冲区长度不匹配
        }
        buf.copy_from_slice(&time_bytes[offset..offset+len]);
        offset += len;
    }
    0
}

/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(_trace_request: usize, _id: usize, _data: usize) -> isize {
    trace!("kernel: sys_trace");
    match _trace_request {
        0 => {
            // read one byte from user space address `_id`
            let token = current_user_token();
            // check read permission first
            if !is_user_readable(token, _id as *const u8) {
                return -1 as isize;
            }
            let buffers = translated_byte_buffer(token, _id as *const u8, 1);
            if buffers.is_empty() || buffers[0].len() == 0 {
                return -1 as isize;
            }
            buffers[0][0] as isize
        }
        1 => {
            // write one byte to user space address `_id`
            let token = current_user_token();
            // check write permission first
            if !is_user_writable(token, _id as *const u8) {
                return -1 as isize;
            }
            let mut buffers = translated_byte_buffer(token, _id as *const u8, 1);
            if buffers.is_empty() || buffers[0].len() == 0 {
                return -1 as isize;
            }
            buffers[0][0] = (_data & 0xFF) as u8;
            0
        }
        2 => {
            let current_task_id = get_current_task_id();
            
            get_count(current_task_id, _id) as isize
        }
        _ => {
            -1
        }
    }
}

//权限转化
fn prot_to_map_permission(prot: usize) -> Option<MapPermission> {
    if prot & !0x7 != 0 || prot & 0x7 == 0 {
        return None;
    }
    
    let mut perm = MapPermission::U;
    if prot & 0x1 != 0 { perm |= MapPermission::R; }
    if prot & 0x2 != 0 { perm |= MapPermission::W; }
    if prot & 0x4 != 0 { perm |= MapPermission::X; }
    
    Some(perm)
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!("kernel: sys_mmap NOT IMPLEMENTED YET!");
    // 基本参数检查
    if _start % PAGE_SIZE != 0 {
        return -1;
    }
    
    if _len == 0 {
        return 0;
    }
    
    // 转换保护标志
    let map_perm = match prot_to_map_permission(_port) {
        Some(perm) => perm,
        None => return -1,
    };
    
    // 计算结束地址
    let page_count = (_len + PAGE_SIZE - 1) / PAGE_SIZE;
    let end_addr = _start + page_count * PAGE_SIZE;
    
    let start_va = VirtAddr::from(_start);
    let end_va = VirtAddr::from(end_addr);
    

    with_current_task(|current_task| {
    // 安全地使用 current_task
        let memory_set = &mut current_task.memory_set;
        if memory_set.mmap_anonymous(start_va, end_va, map_perm) {
        0
        } else {
            -1
        }
    })
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!("kernel: sys_munmap NOT IMPLEMENTED YET!");
    // 基本参数检查
    if _start % PAGE_SIZE != 0 {
        return -1;
    }
    
    if _len == 0 {
        return 0;
    }
    
    // 计算结束地址
    let page_count = (_len + PAGE_SIZE - 1) / PAGE_SIZE;
    let end_addr = _start + page_count * PAGE_SIZE;
    
    let start_va = VirtAddr::from(_start);
    let end_va = VirtAddr::from(end_addr);
    

    with_current_task(|current_task| {
    // 安全地使用 current_task
        let memory_set = &mut current_task.memory_set;
        if memory_set.munmap_region(start_va, end_va) {
        0
        } else {
            -1
        }
    })
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
