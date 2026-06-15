/**
 * Frida hook — T1055 Process Injection witness
 *
 * Intercepts the four canonical Win32 APIs used in classic remote-thread
 * injection and emits a structured telemetry event for each call.
 * The bridge.py collects these events and saves them alongside the C2 result
 * so the Sigma-compare stage can diff expected vs. observed API sequences.
 */

const APIS = [
  { module: "kernel32", export: "OpenProcess" },
  { module: "kernel32", export: "VirtualAllocEx" },
  { module: "kernel32", export: "WriteProcessMemory" },
  { module: "kernel32", export: "CreateRemoteThread" },
];

APIS.forEach(({ module: mod, export: name }) => {
  const addr = Module.findExportByName(mod, name);
  if (!addr) {
    send({ warn: `${name} not found in ${mod}` });
    return;
  }

  Interceptor.attach(addr, {
    onEnter(args) {
      const event = { api: name, args: {} };

      if (name === "OpenProcess") {
        event.args.dwDesiredAccess = args[0].toInt32().toString(16);
        event.args.dwProcessId    = args[2].toInt32();
      } else if (name === "VirtualAllocEx") {
        event.args.hProcess       = args[0].toInt32();
        event.args.dwSize         = args[2].toInt32();
        event.args.flAllocationType = args[3].toInt32().toString(16);
        event.args.flProtect      = args[4].toInt32().toString(16);
      } else if (name === "WriteProcessMemory") {
        event.args.hProcess = args[0].toInt32();
        event.args.nSize    = args[3].toInt32();
      } else if (name === "CreateRemoteThread") {
        event.args.hProcess      = args[0].toInt32();
        event.args.lpStartAddress = args[3];
      }

      send(event);
    },
  });
});
