# MecanikProcessBreaker
C++ POC Tool to inject process and RIP functions using NT SYSCALLS
***

# What is this ?
This project was made as a proof-of-concept to demontrate remote DLL injection into any usermode process, and detour functions.

Why words like "breaker" and "RIP" ? Because basically that's what this tool will do, "break" inside almost ANY process using native NT SYSCALLS, and the DLL will "RIP" through ANY function you want to hijack. It will not matter if it was previously "detoured" or "hooked".

# The Purpose:
I was able to inject and debug malware, trojans, protected games, protected applications. Some inject attempts WILL FAIL due to protection from the kernel leverl, but a driver is coming soon as well to "enforce" my "breaker" :)

Use this tool for anything you want, as long as you do not cause harm to anyone/anything.

#### Project features:

* [MecanikInjector] - Simple GUI with process list, offers you the abillity to inject processes with 2 methods: simple + advanced
* [MecanikProcessBreaker] - A special DLL developed "my own" way to RIP ( detour ) functions. This DLL has it's own "dispatcher", the abillity to "hide" in the target process and can "pass-through" ANY function you want to. Much more faster and effective than any traditional "detour".

#### Abilities:

* [HideModule] - The injector will attempt to hide the DLL in the remote target, but the DLL also has it's own thread to "hide" itself every minute.
* [CheckForIATHook] - Check if there is any IAT hooks on the functions we want to "RIP"
* [CheckIfPatched] - Check if the functions we want to import are already detoured/hooked
* [ManualMap] - Load File (DLL) From Memory to import NT functions
* [Console] - Once the DLL is injected, a console will pop-up where you can see everything happening inside the DLL, logging to a .txt file also included
* [Loader] - Soon, abillity to load additional DLL's and hide them through my DLL.

#### Screenshot:

![Alt text](https://github.com/Mecanik/MecanikProcessBreaker/blob/master/2017-10-10%2012_22_17.png?raw=true "Optional Title")

***

### OK, I'm sold! How do I add more functions ??

There are a few steps required to add more functions, and without some C++ knowledge you will NOT be able to do it.
We first define our functions in MecanikProcessBreaker.h, for example:

    static int __stdcall MyWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

While we are here, we also add "critical" sections for our function:

    CRITICAL_SECTION MyWSASend_Critical;

Not done yet, we need to add also a definition for our "backup" hook:

    BYTE MyWSASendHook[6]; // Keep the size 6!!
    
Now we can go into MecanikProcessBreaker.cpp, and continue adding our "critical" sections:

    InitializeCriticalSection(&MyWSASend_Critical);

We also need to add into the destructor of the class:

    DeleteCriticalSection(&MyWSASend_Critical);
    
Inside "StartRippingFunctions()", we insert the functions we want to "RIP". At the same time, we can add our additional checks to see if the function has a IAT hook, or it was detoured previously:

    MecanikDetours::T_MNTDetours.CheckForIATHook("ws2_32.dll", "WSASend");
    MecanikDetours::T_MNTDetours.CheckIfPatched("ws2_32.dll", "WSASend");
    MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "WSASend", (LPVOID)T_MecanikProcessBreaker.MyWSASend, T_MecanikProcessBreaker.MyWSASendHook);
    
Now for the final callback function, we add inside the class:

    int __stdcall MecanikProcessBreaker::MyWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
      {
        EnterCriticalSection(&T_MecanikProcessBreaker.MyWSASend_Critical);
        MecanikDetours::T_MNTDetours.UNRIPFunction("ws2_32.dll", "WSASend", T_MecanikProcessBreaker.MyWSASendHook);

        int result = WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);

        // WE CAN DO ANYTHING WE WANT HERE LOL :)
        M_Console.ConsoleOutput(6, "[MyWSASend] :: (0x%02hX 0x%02hX 0x%02hX 0x%02hX 0x%02hX 0x%02hX)", lpBuffers->buf[0], lpBuffers->buf[1], lpBuffers->buf[2], lpBuffers->buf[3], lpBuffers->buf[4]);

        MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "WSAsend", T_MecanikProcessBreaker.MyWSASend, T_MecanikProcessBreaker.MyWSASendHook);
        LeaveCriticalSection(&T_MecanikProcessBreaker.MyWSASend_Critical);
        return result;
      }
      

That's it, now was that simple or what ?! If you follow instructions you will succeed even with a small amount of experience.

#### Bugs, problems:
* [GUI] - The injector LOG has no sorting
* [GUI] - The injector Process List does not get "refreshed" properly when you empty the Process Cache ( press the button lol )
* [DLL] - WriteProcessMemory needs to be replaced with NtWriteVirtualMemory somehow...
* Anything else you can find ?...

#### Disclaimer:

The project is using functions, classes from other developers too. I have not written everything by myself, unfortunately I cannot recall all authors to include them...
Please do not steal code from this project and claim it for yourself, it would be lame and it will not make you smarter or more experienced... instead learn by yourself.

Copyright © 2017 Norbert Boros / [LiveGuard Software Ltd](https://liveguard-software.com/)
