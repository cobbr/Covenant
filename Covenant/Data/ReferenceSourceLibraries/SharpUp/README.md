# SharpUp

----

SharpUp is a C# port of various [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1) functionality. Currently, only the most common checks have been ported; no weaponization functions have yet been implemented.

[@harmj0y](https://twitter.com/harmj0y) is the primary author.

SharpUp is licensed under the BSD 3-Clause license.

## Usage

    C:\Temp>SharpUp.exe

    === SharpUp: Running Privilege Escalation Checks ===


    === Modifiable Services ===

    Name             : VulnSvc
    DisplayName      : VulnSvc
    Description      :
    State            : Stopped
    StartMode        : Auto
    PathName         : C:\Program Files\VulnSvc\VulnSvc.exe


    === Modifiable Service Binaries ===

    Name             : VulnSvc2
    DisplayName      : VulnSvc22
    Description      :
    State            : Stopped
    StartMode        : Auto
    PathName         : C:\VulnSvc2\VulnSvc2.exe


    === AlwaysInstallElevated Registry Keys ===



    === Modifiable Folders in %PATH% ===

    Modifable %PATH% Folder  : C:\Go\bin


    === Modifiable Registry Autoruns ===



    === *Special* User Privileges ===



    === Unattended Install Files ===



    === McAfee Sitelist.xml Files ===



    [*] Completed Privesc Checks in 11 seconds

## Compile Instructions

We are not planning on releasing binaries for SharpUp, so you will have to compile yourself :)

SharpUp has been built against .NET 3.5 and is compatible with [Visual Studio 2015 Community Edition](https://go.microsoft.com/fwlink/?LinkId=532606&clcid=0x409). Simply open up the project .sln, choose "release", and build.

## Acknowledgments

SharpUp incorporates various code C# snippets and bits of PoCs found throughout research for its capabilities. These snippets and authors are highlighted in the appropriate locations in the source code, and include:

* [Igor Korkhov's code to retrieve current token group information](https://stackoverflow.com/questions/2146153/how-to-get-the-logon-sid-in-c-sharp/2146418#2146418)
* [JGU's snippet on file/folder ACL right comparison](https://stackoverflow.com/questions/1410127/c-sharp-test-if-user-has-write-access-to-a-folder/21996345#21996345)
* [Rod Stephens' pattern for recursive file enumeration](http://csharphelper.com/blog/2015/06/find-files-that-match-multiple-patterns-in-c/)
* [SwDevMan81's snippet for enumerating current token privileges](https://stackoverflow.com/questions/4349743/setting-size-of-token-privileges-luid-and-attributes-array-returned-by-gettokeni)
* [Nikki Locke's code for querying service security descriptors](https://stackoverflow.com/questions/15771998/how-to-give-a-user-permission-to-start-and-stop-a-particular-service-using-c-sha/15796352#15796352)
