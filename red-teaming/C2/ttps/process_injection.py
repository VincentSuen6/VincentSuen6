"""
T1055 — Process Injection (simulation stub)

Simulates the Win32 API call sequence for classic remote process injection
without executing any real shellcode. The telemetry dict mirrors exactly
what the Frida bridge will capture when the real implementation runs,
making this stub useful for testing the detection-comparison pipeline.

Real implementation would call:
  OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
"""

from typing import Tuple


def run(params: dict) -> Tuple[str, str, dict]:
    target_pid = params.get("target_pid")
    if not target_pid:
        return "failed", "target_pid required", {}

    shellcode_size = params.get("shellcode_size", 4096)

    telemetry = {
        "ttp": "T1055",
        "variant": "classic_remote_thread",
        "target_pid": target_pid,
        "api_sequence": [
            {
                "api": "OpenProcess",
                "args": {
                    "dwDesiredAccess": "PROCESS_ALL_ACCESS",
                    "dwProcessId": target_pid,
                },
            },
            {
                "api": "VirtualAllocEx",
                "args": {
                    "hProcess": "<handle>",
                    "dwSize": shellcode_size,
                    "flAllocationType": "MEM_COMMIT|MEM_RESERVE",
                    "flProtect": "PAGE_EXECUTE_READWRITE",
                },
            },
            {
                "api": "WriteProcessMemory",
                "args": {
                    "hProcess": "<handle>",
                    "nSize": shellcode_size,
                },
            },
            {
                "api": "CreateRemoteThread",
                "args": {
                    "hProcess": "<handle>",
                    "lpStartAddress": "<alloc_base>",
                },
            },
        ],
    }

    output = (
        f"[sim] T1055 — injected into PID {target_pid} "
        f"({shellcode_size} bytes, PAGE_EXECUTE_READWRITE)"
    )
    return "success", output, telemetry
