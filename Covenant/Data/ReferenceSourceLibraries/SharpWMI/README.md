# SharpWMI

----

SharpWMI is a C# implementation of various WMI functionality. This includes local/remote WMI queries, remote WMI process creation through win32_process, and remote execution of arbitrary VBS through WMI event subscriptions. Alternate credentials are also supported for remote methods. 

[@harmj0y](https://twitter.com/harmj0y) is the primary author.

SharpWMI is licensed under the BSD 3-Clause license.

## Usage

    Local system enumeration  :
        SharpWMI.exe action=query query="select * from win32_service" [namespace=BLAH]

    Remote system enumeration :
        SharpWMI.exe action=query computername=HOST1[,HOST2,...] query="select * from win32_service" [namespace=BLAH]

    Remote process creation   :
        SharpWMI.exe action=create computername=HOST[,HOST2,...] command="C:\temp\process.exe [args]"

    Remote VBS execution      :
        SharpWMI.exe action=executevbs computername=HOST[,HOST2,...] [eventname=blah]

    Note: Any remote function also takes an optional "username=DOMAIN\user" "password=Password123!"

    Examples:

        SharpWMI.exe action=query query="select * from win32_process"
        SharpWMI.exe action=query query="SELECT * FROM AntiVirusProduct" namespace="root\SecurityCenter2"
        SharpWMI.exe action=query computername=primary.testlab.local query="select * from win32_service"
        SharpWMI.exe action=query computername=primary,secondary query="select * from win32_process"
        SharpWMI.exe action=create computername=primary.testlab.local command="powershell.exe -enc ZQBj..."
        SharpWMI.exe action=executevbs computername=primary.testlab.local
        SharpWMI.exe action=executevbs computername=primary.testlab.local username="TESTLAB\harmj0y" password="Password123!"


## Compile Instructions

We are not planning on releasing binaries for SharpWMI, so you will have to compile yourself :)

SharpWMI has been built against .NET 3.5 and is compatible with [Visual Studio 2015 Community Edition](https://go.microsoft.com/fwlink/?LinkId=532606&clcid=0x409). Simply open up the project .sln, choose "release", and build.
