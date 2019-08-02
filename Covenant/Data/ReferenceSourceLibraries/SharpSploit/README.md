# SharpSploit

[SharpSploit](https://github.com/cobbr/SharpSploit) is a .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.

[SharpSploit](https://github.com/cobbr/SharpSploit) is named, in part, as a homage to the [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) project, a personal favorite of mine! While [SharpSploit](https://github.com/cobbr/SharpSploit) does port over some functionality from [PowerSploit](https://github.com/PowerShellMafia/PowerSploit), my intention is **not** at all to create a direct port of [PowerSploit](https://github.com/PowerShellMafia/PowerSploit). [SharpSploit](https://github.com/cobbr/SharpSploit) will be it's own project, albeit with similar goals to [PowerSploit](https://github.com/PowerShellMafia/PowerSploit).

### Intro

You'll find some details and motivations for the SharpSploit project in this [introductory blog post](https://cobbr.io/SharpSploit.html).

### Documentation

The complete SharpSploit API docfx documentation is available [here](https://sharpsploit.cobbr.io/api/).

For an easier to read, high-level quick reference and summary of SharpSploit functionality, refer to the [SharpSploit - Quick Command Reference](https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/SharpSploit%20-%20Quick%20Command%20Reference.md).

### Credits

I owe a ton of credit to a lot of people. Nearly none of `SharpSploit` is truly original work. `SharpSploit` ports many modules written in PowerShell by others, utilizes techniques discovered by others, and borrows ideas and code from other C# projects as well. With that being said, I'd like to thank the following people for contributing to the project (whether they know they did or not :)):

* Justin Bui ([@youslydawg](https://twitter.com/youslydawg)) - For contributing the `SharpSploit.Enumeration.Host.CreateProcessDump()` function.
* Matt Graeber ([@mattifestation](https://twitter.com/mattifestation)), Will Schroeder ([@harmj0y](https://twitter.com/harmj0y)), and Ruben ([@FuzzySec](https://twitter.com/fuzzysec)) - For their work on [PowerSploit](https://github.com/PowerShellMafia/PowerSploit).
* Will Schroeder ([@harmj0y](https://twitter.com/harmj0y)) - For the [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) project.
* Alexander Leary ([@0xbadjuju](https://twitter.com/0xbadjuju)) - For the [Tokenvator](https://github.com/0xbadjuju/Tokenvator) project.
* James Foreshaw ([@tiraniddo](https://twitter.com/tiraniddo)) - For his discovery of the token duplication UAC bypass technique documented [here](https://tyranidslair.blogspot.com/2017/05/reading-your-way-around-uac-part-3.html).
* Matt Nelson ([@enigma0x3](https://twitter.com/enigma0x3)) - For his [Invoke-TokenDuplication](https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Invoke-TokenDuplication.ps1) implementation of the token duplication UAC bypass, as well his C# shellcode execution method.
* Benjamin Delpy ([@gentilkiwi](https://twitter.com/gentilkiwi)) - For the [Mimikatz](https://github.com/gentilkiwi/mimikatz) project.
* Casey Smith ([@subtee](https://twitter.com/subtee)) - For his work on a C# PE Loader.
* Chris Ross ([@xorrior](https://twitter.com/xorrior)) - For his implementation of a Mimikatz PE Loader found [here](https://github.com/xorrior/Random-CSharpTools/blob/master/DllLoader/DllLoader/PELoader.cs).
* Matt Graeber ([@mattifestation](https://twitter.com/mattifestation)) - For discovery of the AMSI bypass found [here](https://twitter.com/mattifestation/status/735261120487772160).
* Lee Christensen ([@tifkin_](https://twitter.com/tifkin_)) - For the discovery of the PowerShell logging bypass found [here](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs).
* All the contributors to [www.pinvoke.net](www.pinvoke.net) - For numerous PInvoke signatures.
