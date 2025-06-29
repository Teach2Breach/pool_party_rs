### pool_party_rs

This tool is a remote process injection uses techniques described in https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/ and found in https://github.com/SafeBreach-Labs/PoolParty . So far variants 1 and 2 are implemented. I will add more variants in the future.

##### Note

This version does not use dynamic resolution of APIs or other OPSEC safe considerations. I'll push a more OPSEC safe version in the future on the 'opsec' branch. Usually about 1 month after initial repo release.

#### How it works

The 1st variant implements a process injection technique using Windows Thread Pools, specifically targeting worker factories. Here's how it works:

The program takes shellcode and a target process ID as input, then performs several key steps:
- First, it obtains a handle to the target process using OpenProcess with permissions for memory operations and handle manipulation.
- It then searches through all handles in the target process using NtQueryInformationProcess with ProcessHandleInformation to find a TpWorkerFactory handle. This is done by:
  - Enumerating all handles
  - Duplicating each handle into our process
  - Using NtQueryObject to check if the handle type is "TpWorkerFactory"
- Once it finds a worker factory handle, it queries information about it using NtQueryInformationWorkerFactory to get the WorkerFactoryBasicInformation, which includes the StartRoutine address.
- The program then uses WriteProcessMemory to overwrite the StartRoutine address with the provided shellcode.
- Finally, it triggers execution of the shellcode by using NtSetInformationWorkerFactory with WorkerFactoryThreadMinimum to increase the minimum thread count. This forces the worker factory to create a new thread, which will execute our shellcode since we overwrote the StartRoutine.

The key Windows APIs and NT APIs used are:
- OpenProcess: To get handle to target process
- NtQueryInformationProcess: To enumerate process handles
- DuplicateHandle: To duplicate handles for inspection
- NtQueryObject: To identify handle types
- NtQueryInformationWorkerFactory: To get worker factory information
- WriteProcessMemory: To write shellcode
- NtSetInformationWorkerFactory: To trigger execution

This technique is particularly interesting because it abuses legitimate Windows thread pool functionality to execute arbitrary code, making it potentially harder to detect than traditional injection methods.

The 2nd variant tampers with the thread pool task queue to inject a malicious task into the queue. You can read more about it in the blog post.

#### Important: Target Process Requirements

**The target process MUST be using thread pools for injection to work.** This means:

- The process must have called `CreateThreadpoolWork`, `CreateThreadpoolTimer`, or similar thread pool APIs
- Simple processes like notepad.exe, calc.exe, etc. typically don't use thread pools by default
- Processes that use thread pools include: explorer.exe, modern browsers, development tools, etc.

If you get "Failed to find worker factory handle" errors, the target process is not using thread pools.

#### Testing and Debugging

The tool includes enhanced debugging and testing capabilities:

**Debug Output:**
- Shows all handle types found in the target process
- Displays the number of handles and specific handle types
- Provides clear error messages when injection fails

**Test Process Creation:**
- Use variant `0` to create a test process that uses thread pools
- Automatically compiles and runs a C program that creates thread pool work items
- Provides the PID for easy testing

**Example Testing Workflow:**
```bash
# 1. Create a test process that uses thread pools
cargo run 0 0

# 2. Inject into the test process (use the PID from step 1)
cargo run <test_pid> 1
```

**Troubleshooting Common Issues:**

1. **"Failed to find worker factory handle"**
   - The target process is not using thread pools
   - Try targeting explorer.exe or use the test process (variant 0)

2. **"Failed to open process"**
   - Insufficient permissions (try running as Administrator)
   - Process doesn't exist or has terminated

##### Usage
 Add this to your cargo.toml

```
[dependencies]
pool_party_rs = { git = "https://github.com/Teach2Breach/pool_party_rs" }
```

##### Example

see main.rs for a full example

```
use pool_party_rs::wrapper;

let info_string = wrapper(&SHELL_CODE, pid, variant);
println!("{}", info_string);
```

Video of creating the 1st variant PoC:

[watch on X](https://x.com/Teach2Breach/status/1888336755067150736)



