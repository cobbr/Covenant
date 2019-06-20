![Covenant](https://raw.githubusercontent.com/wiki/cobbr/Covenant/covenant.png)

# Covenant

Covenant is a .NET command and control framework that aims to highlight the attack surface of .NET, make the use of offensive .NET tradecraft easier, and serve as a collaborative command and control platform for red teamers.

Covenant is an ASP.NET Core, cross-platform application that includes a robust API to enable a client-server architecture that allows for multi-user collaboration. There are three main components of Covenant's architecture:

* **Covenant** - Covenant is the server-side component of the client-server architecture. Covenant runs the command and control server hosted on infrastructure shared between operators. I will also frequently use the term "Covenant" to refer to the entire overarching project that includes all components of the architecture.
* **Elite** - [Elite](https://github.com/cobbr/Elite) is the client-side component of the client-server architecture. Elite is a command-line interface that operators use to interact with the Covenant server to conduct operations.
* **Grunt** - A "Grunt" is the name of Covenant's implant that is deployed to targets.

## Features

Covenant has several key features:

* **Multi-Platform** - Covenant and Elite both target .NET Core, which makes them multi-platform. This allows these programs to run natively on Linux, MacOS, and Windows platforms. Additionally, both Covenant and Elite have docker support, allowing these programs to run within a container on any system that has docker installed.
* **Multi-User** - Covenant supports multi-user collaboration. The ability to collaborate has become crucial for effective red team operations. Many users can start Elite clients that connect to the same Covenant server and operate independently or collaboratively.
* **API Driven** - Covenant is driven by a server-side API that enables multi-user collaboration and is easily extendible. Additionally, Covenant includes a Swagger UI that makes development and debugging easier and more convenient.
* **Listener Profiles** - Covenant supports listener "profiles" that control how the network communication between Grunt implants and Covenant listeners look on the wire.
* **Encrypted Key Exchange** - Covenant implements an encrypted key exchange between Grunt implants and Covenant listeners that is largely based on a similar exchange in the [Empire project](https://github.com/EmpireProject/Empire), in addition to optional SSL encryption. This achieves the cryptographic property of forward secrecy between Grunt implants.
* **Dynamic Compilation** - Covenant uses the [Roslyn API](https://github.com/dotnet/roslyn) for dynamic C# compilation. Every time a new Grunt is generated or a new task is assigned, the relevant code is recompiled and obfuscated with [ConfuserEx](https://github.com/mkaring/ConfuserEx), avoiding totally static payloads. Covenant reuses much of the compilation code from the [SharpGen](https://github.com/cobbr/sharpgen) project, which I described in much more detail [in a previous post](https://cobbr.io/SharpGen.html).
* **Inline C# Execution** - Covenant borrows code and ideas from both the [SharpGen](https://github.com/cobbr/sharpgen) and [SharpShell](https://github.com/cobbr/sharpshell) projects to allow operators to execute C# one-liners on Grunt implants. This allows for similar functionality to that described in the [SharpShell post](https://cobbr.io/SharpShell.html), but allows the one-liners to be executed on remote implants.
* **Tracking Indicators** - Covenant tracks "indicators" throughout an operation, and summarizes them in the `Indicators` menu. This allows an operator to conduct actions that are tracked throughout an operation and easily summarize those actions to the blue team during or at the end of an assessment for deconfliction and educational purposes. This feature is still in it's infancy and still has room for improvement.

## Users Quick-Start Guide

Be sure to clone Covenant recursively to initialize the git submodules: `git clone --recurse-submodules https://github.com/cobbr/Covenant`

### Dotnet Core

The easiest way to use Covenant, is by installing dotnet core. You can download dotnet core for your platform from [here](https://dotnet.microsoft.com/download).

Once you have installed dotnet core, we can build and run Covenant using the dotnet CLI:
```
$ ~/Covenant/Covenant > dotnet build
$ ~/Covenant/Covenant > dotnet run
```

### Docker

Covenant can also be run with Docker. There are a couple of gotchas with Docker, so I only recommend using docker if you are familiar with docker or are willing to learn the subtle gotchas.

First, build the docker image:
```
$ ~/Covenant/Covenant > docker build -t covenant .
```

Now we can run Covenant in a Docker container:
```
$ ~/Covenant/Covenant > docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v /absolute/path/to/Covenant/Covenant/Data:/app/Data covenant --username AdminUser --computername 0.0.0.0
```
The `--username user` and `--computername 0.0.0.0` are arguments being passed to Covenant. This creates a Covenant admin user named `AdminUser`, and binds the Covenant API to `0.0.0.0`, which is important when using Docker (we won't have access to bind to the docker container's IP address).

The `-it` parameter is a Docker parameter that indicates that we should begin Covenant in an interactive tty. This is important, as you will be prompted to set a password for the `AdminUser` user. Alternatively, you can set this non-interactively with the `--password` parameter to Covenant, but this will leave your password in plaintext in command history, not ideal.

The `-p` parameters expose ports to the Covenant Docker container. You must expose port 7443 and any other ports you would like to start listeners on.

The `-v` parameter creates a shared Data directory between the host and the container. Be sure to specify an absolute path to your data directory, a relative path will not work.

Once Covanant has been started and you have set the admin password, you can disconnect from the interactive interface, if you would like, by pressing `Ctrl+p` and `Ctrl+q` consecutively.


To stop the container, you can run:
```
$ ~/Covenant/Covenant > docker stop covenant
```
And to restart covenant interactively (with all data saved), you can run:
```
$ ~/Covenant/Covenant > docker start covenant -ai
```
Alternatively, to remove all Covenant data and restart fresh, you can remove and run again:
```
$ ~/Covenant/Covenant > docker rm covenant
$ ~/Covenant/Covenant > docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v /absolute/path/to/Covenant/Covenant/Data:/app/Data covenant --username AdminUser --computername 0.0.0.0
```

Finally, want to develop and hack on Covenant? Awesome, Covenant has a Swagger UI, built for exactly this purpose! Just start Covenant in Development mode as seen below and navigate to `https://localhost:7443/swagger`:
```
$ ~/Covenant/Covenant > docker run -it -p 7443:7443 -p 80:80 -p 443:443 --env ASPNETCORE_ENVIRONMENT=Development --name covenant -v /absolute/path/to/Covenant/Covenant/Data:/app/Data covenant --username AdminUser --computername 0.0.0.0
```

### Next Steps

> Okay it's running.... Now what?

You need the client-side component of this project, `Elite`! Go checkout the [Elite README](https://github.com/cobbr/Elite/blob/master/README.md) to see how to do that.

### Questions and Discussion

Have questions or want to chat more about Covenant? Join the #Covenant channel in the [BloodHound Gang Slack](https://bloodhoundgang.herokuapp.com/).
