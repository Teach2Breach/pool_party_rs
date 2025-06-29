
#include <windows.h>
#include <stdio.h>

void CALLBACK WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work) {
    printf("Work callback executed!\\n");
    Sleep(1000);
}

int main() {
    printf("Test process started. PID: %d\\n", GetCurrentProcessId());
    printf("Creating thread pool work items...\\n");
    
    // Create a thread pool work item
    PTP_WORK work = CreateThreadpoolWork(WorkCallback, NULL, NULL);
    if (work) {
        printf("Thread pool work created successfully\\n");
        SubmitThreadpoolWork(work);
        Sleep(2000);
        WaitForThreadpoolWorkCallbacks(work, FALSE);
        CloseThreadpoolWork(work);
    }
    
    printf("Test process will sleep for 60 seconds. You can now inject into PID %d\\n", GetCurrentProcessId());
    Sleep(60000);
    return 0;
}
