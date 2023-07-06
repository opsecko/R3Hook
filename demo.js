function buf2hex(buffer) { // buffer is an ArrayBuffer
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join(' ');
  }
 
//you can generate by gpt
Interceptor.attach(Module.findExportByName("kernel32.dll", "DeviceIoControl"), {
    onEnter: function (args) {
        send('-'.repeat(40));
            send('[+] DeviceIoControl hooked.');
            send('[*] Parameter 1 (HANDLE): ' + args[0]);
            send('[*] Parameter 2 (DWORD): ' + args[1].toInt32());
            send('[*] Parameter 3 (LPVOID): ' + args[2]);
            send('[*] Parameter 4 (DWORD): ' + args[3].toInt32());
            send(buf2hex(args[2].readByteArray(args[3].toInt32())));
            send('[*] Parameter 5 (LPVOID): ' + args[4]);
            send('[*] Parameter 6 (DWORD): ' + args[5].toInt32());
            send('[*] Parameter 7 (LPDWORD): ' + args[6]);
            send('[*] Parameter 8 (LPOVERLAPPED): ' + args[7]);
        },
    onLeave: function (retval) {}
});

Interceptor.attach(Module.findExportByName("kernel32.dll", "CreateProcessW"), {
    onEnter: function(args) {
        // Extract the command-line arguments
        var appNamePtr = args[0];
        var cmdLinePtr = args[1];
        var processAttrsPtr = args[2];
        var threadAttrsPtr = args[3];
        var inheritHandles = args[4];
        var creationFlags = args[5];
        var environmentPtr = args[6];
        var currentDirPtr = args[7];
        var startupInfoPtr = args[8];
        var processInfoPtr = args[9];

        // Convert the pointers to strings and print them out
        var appName = appNamePtr.readUtf16String();
        var cmdLine = cmdLinePtr.readUtf16String();
        var processAttrs = processAttrsPtr.isNull() ? 0 : processAttrsPtr.toInt32();
        var threadAttrs = threadAttrsPtr.isNull() ? 0 : threadAttrsPtr.toInt32();
        var inherit = inheritHandles.toInt32();
        var flags = creationFlags.toInt32();
        var env = environmentPtr.isNull() ? "" : environmentPtr.readUtf16String();
        var dir = currentDirPtr.isNull() ? "" : currentDirPtr.readUtf16String();
        send('-'.repeat(40));
        send("[+] Old Creation Flags: " + flags);

        args[5] = creationFlags.add(2)
        send("[+] New Creation Flags: " +  args[5].toInt32());
        send("[+] CreateProcess Hook Called:");
        send("[+] Application Name: " + appName);
        send("[+] Command Line: " + cmdLine);
        send("[+] Process Attributes: " + processAttrs);
        send("[+] Thread Attributes: " + threadAttrs);
        send("[+] Inherit Handles: " + inherit);
        send("[+] Creation Flags: " + flags);
        send("[+] Environment: " + env);
        send("[+] Current Directory: " + dir);
    }
});

Interceptor.attach(Module.findExportByName("ntdll.dll", "NtProtectVirtualMemory"), {
    onEnter: function(args) {
        send('-'.repeat(40));
        send('[+] NtProtectVirtualMemory hooked.');
        send("[+] arg0: " + args[0].toString());
        send("[+] arg1: " + args[1].toString());
        send("[+] arg2: " + args[2].toString());
        send("[+] arg3: " + args[3].toString());
        send("[+] arg4: " + args[4].toString());
    }
});


Interceptor.attach(Module.findExportByName("ntdll.dll", "NtSuspendThread"), {
    onEnter: function (args) {
        send('-'.repeat(40));
            send('[+] NtSuspendThread called!.');
            send('[*] Parameter 1 (HANDLE): ' + args[0]);
            send('[*] Parameter 2 (DWORD): ' + buf2hex(args[1].readByteArray(8)));
        },
    onLeave: function (retval) {}
});

Interceptor.attach(Module.findExportByName("ntdll.dll", "NtResumeThread"), {
    onEnter: function (args) {
        send('-'.repeat(40));
            send('[+] NtResumeThread called!.');
            send('[*] Parameter 1 (HANDLE): ' + args[0]);
            send('[*] Parameter 2 (DWORD): ' + buf2hex(args[1].readByteArray(8)));
        },
    onLeave: function (retval) {}
});