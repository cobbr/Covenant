// Author: Ryan Cobb (@cobbr_io)
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3

using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Reflection;
using System.IO.Compression;
using System.Collections.Generic;

using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Emit;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

using Confuser.Core;
using Confuser.Core.Project;

namespace Covenant.Core
{
    public static class Compiler
    {
        public class CompilationRequest
        {
            public Covenant.Models.Grunts.ImplantLanguage Language { get; set; } = Models.Grunts.ImplantLanguage.CSharp;
            public Platform Platform { get; set; } = Platform.AnyCpu;
        }

        public class CsharpCompilationRequest : CompilationRequest
        {
            public Common.DotNetVersion TargetDotNetVersion { get; set; } = Common.DotNetVersion.Net35;
            public OutputKind OutputKind { get; set; } = OutputKind.DynamicallyLinkedLibrary;
            public bool Optimize { get; set; } = true;
            public bool Confuse { get; set; } = false;
            public bool UnsafeCompile { get; set; } = false;
            public bool UseSubprocess { get; set; } = false;

            public string AssemblyName { get; set; } = null;
            public List<Reference> References { get; set; } = new List<Reference>();
            public List<EmbeddedResource> EmbeddedResources { get; set; } = new List<EmbeddedResource>();
        }

        public class CsharpFrameworkCompilationRequest : CsharpCompilationRequest
        {
            public string Source { get; set; } = null;
            public List<string> SourceDirectories { get; set; } = null;
        }

        public class CsharpCoreCompilationRequest : CsharpCompilationRequest
        {
            public string ResultName { get; set; } = "";
            public string SourceDirectory { get; set; } = "";
            public RuntimeIdentifier RuntimeIdentifier { get; set; } = RuntimeIdentifier.win_x64;
        }

        private static readonly Dictionary<RuntimeIdentifier, string> RuntimeIdentifiers = new Dictionary<RuntimeIdentifier, string>
        {
            { RuntimeIdentifier.win_x64, "win-x64" }, { RuntimeIdentifier.win_x86, "win-x86" },
            { RuntimeIdentifier.win_arm, "win-arm" }, { RuntimeIdentifier.win_arm64, "win-arm64" },
            { RuntimeIdentifier.win7_x64, "win7-x64" }, { RuntimeIdentifier.win7_x86, "win7-x86" },
            { RuntimeIdentifier.win81_x64, "win81-x64" }, { RuntimeIdentifier.win81_x86, "win81-x86" }, { RuntimeIdentifier.win81_arm, "win81-arm" },
            { RuntimeIdentifier.win10_x64, "win10-x64" }, { RuntimeIdentifier.win10_x86, "win10-x86" },
            { RuntimeIdentifier.win10_arm, "win10-arm" }, { RuntimeIdentifier.win10_arm64, "win10-arm64" },
            { RuntimeIdentifier.linux_x64, "linux-x64" }, { RuntimeIdentifier.linux_musl_x64, "linux-musl-x64" }, { RuntimeIdentifier.linux_arm, "linux-arm" }, { RuntimeIdentifier.linux_arm64, "linux-arm64" },
            { RuntimeIdentifier.rhel_x64, "rhel-x64" }, { RuntimeIdentifier.rhel_6_x64, "rhel.6-x64" },
            { RuntimeIdentifier.tizen, "tizen" }, { RuntimeIdentifier.tizen_4_0_0, "tizen.4.0.0" }, { RuntimeIdentifier.tizen_5_0_0, "tizen.5.0.0" },
            { RuntimeIdentifier.osx_x64, "osx-x64" },{ RuntimeIdentifier.osx_10_10_x64, "osx.10.10-x64" }, { RuntimeIdentifier.osx_10_11_x64, "osx.10.11-x64" },
            { RuntimeIdentifier.osx_10_12_x64, "osx.10.12-x64" }, { RuntimeIdentifier.osx_10_13_x64, "osx.10.13-x64" }, { RuntimeIdentifier.osx_10_14_x64, "osx.10.14-x64" }, { RuntimeIdentifier.osx_10_15_x64, "osx.10.15-x64" }
        };

        public enum RuntimeIdentifier
        {
            win_x64, win_x86,
            win_arm, win_arm64,
            win7_x64, win7_x86,
            win81_x64, win81_x86, win81_arm,
            win10_x64, win10_x86,
            win10_arm, win10_arm64,
            linux_x64, linux_musl_x64, linux_arm, linux_arm64,
            rhel_x64, rhel_6_x64,
            tizen, tizen_4_0_0, tizen_5_0_0,
            osx_x64, osx_10_10_x64, osx_10_11_x64,
            osx_10_12_x64, osx_10_13_x64, osx_10_14_x64, osx_10_15_x64
        }

        public class EmbeddedResource
        {
            public string Name { get; set; }
            public string File { get; set; }
            public Platform Platform { get; set; } = Platform.AnyCpu;
            public bool Enabled { get; set; } = false;
        }

        public class Reference
        {
            public string File { get; set; }
            public Common.DotNetVersion Framework { get; set; } = Common.DotNetVersion.Net35;
            public bool Enabled { get; set; } = false;
        }

        private class SourceSyntaxTree
        {
            public string FileName { get; set; } = "";
            public SyntaxTree SyntaxTree { get; set; }
            public List<ITypeSymbol> UsedTypes { get; set; } = new List<ITypeSymbol>();
        }

        public static byte[] Compile(CompilationRequest request)
        {
            if (request.Language == Models.Grunts.ImplantLanguage.CSharp)
            {
                return CompileCSharp((CsharpCompilationRequest)request);
            }
            return null;
        }

        private static byte[] CompileCSharp(CsharpCompilationRequest request)
        {
            if (request.TargetDotNetVersion == Common.DotNetVersion.NetCore31 && request.UseSubprocess)
            {
                return CompileCSharpCoreSubProcess((CsharpCoreCompilationRequest)request);
            }
            else
            {
                return CompileCSharpRoslyn((CsharpFrameworkCompilationRequest)request);
            }
        }

        private static byte[] CompileCSharpCoreSubProcess(CsharpCoreCompilationRequest request)
        {
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo.WorkingDirectory = request.SourceDirectory;
            p.StartInfo.FileName = "dotnet";
            p.StartInfo.Arguments = $"publish -c release -r {RuntimeIdentifiers[request.RuntimeIdentifier]}";
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = true;
            p.Start();
            p.WaitForExit();
            try
            {
                string dir = Path.Combine(request.SourceDirectory, "bin", "Release", "netcoreapp3.1", RuntimeIdentifiers[request.RuntimeIdentifier], "publish");
                IEnumerable<string> files = Directory.EnumerateFiles(dir);
                string file = files
                    .Select(F => new FileInfo(F))
                    .FirstOrDefault(F => F.DirectoryName == dir &&
                                    F.Name.Contains(request.ResultName, StringComparison.CurrentCultureIgnoreCase) &&
                                    !F.Name.EndsWith(".pdb", StringComparison.CurrentCultureIgnoreCase) &&
                                    !F.Name.EndsWith(".deps.json", StringComparison.CurrentCultureIgnoreCase))
                    .FullName;
                byte[] bytes = File.ReadAllBytes(file);
                if (request.Confuse)
                {
                    return ConfuseAssembly(bytes);
                }
                return bytes;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Exception: " + e.Message + Environment.NewLine + e.StackTrace);
            }
            return null;
        }

        private static byte[] CompileCSharpRoslyn(CsharpFrameworkCompilationRequest request)
        {
            // Gather SyntaxTrees for compilation
            List<SourceSyntaxTree> sourceSyntaxTrees = new List<SourceSyntaxTree>();
            List<SyntaxTree> compilationTrees = new List<SyntaxTree>();

            if (request.SourceDirectories != null)
            {
                foreach (var sourceDirectory in request.SourceDirectories)
                {
                    sourceSyntaxTrees.AddRange(Directory.GetFiles(sourceDirectory, "*.cs", SearchOption.AllDirectories)
                        .Select(F => new SourceSyntaxTree { FileName = F, SyntaxTree = CSharpSyntaxTree.ParseText(File.ReadAllText(F), new CSharpParseOptions()) })
                        .ToList());
                    compilationTrees.AddRange(sourceSyntaxTrees.Select(S => S.SyntaxTree).ToList());
                }
            }
            SyntaxTree sourceTree = CSharpSyntaxTree.ParseText(request.Source, new CSharpParseOptions());
            compilationTrees.Add(sourceTree);

            List<PortableExecutableReference> references = request.References
                .Where(R => R.Framework == request.TargetDotNetVersion)
                .Where(R => R.Enabled)
                .Select(R => MetadataReference.CreateFromFile(R.File))
                .ToList();

            // Use specified OutputKind and Platform
            CSharpCompilationOptions options = new CSharpCompilationOptions(outputKind: request.OutputKind, optimizationLevel: OptimizationLevel.Release, platform: request.Platform, allowUnsafe: request.UnsafeCompile);
            // Compile to obtain SemanticModel
            CSharpCompilation compilation = CSharpCompilation.Create(
                request.AssemblyName == null ? Path.GetRandomFileName() : request.AssemblyName,
                compilationTrees,
                references,
                options
            );

            // Perform source code optimization, removing unused types
            if (request.Optimize)
            {
                // Find all Types used by the generated compilation
                HashSet<ITypeSymbol> usedTypes = new HashSet<ITypeSymbol>();
                GetUsedTypesRecursively(compilation, sourceTree, ref usedTypes, ref sourceSyntaxTrees);
                List<string> usedTypeNames = usedTypes.Select(T => GetFullyQualifiedTypeName(T)).ToList();

                // Filter SyntaxTrees to trees that define a used Type, otherwise the tree is not needed in this compilation
                compilationTrees = sourceSyntaxTrees.Where(SST => SyntaxTreeDefinesUsedType(compilation, SST.SyntaxTree, usedTypeNames))
                                                    .Select(SST => SST.SyntaxTree)
                                                    .ToList();

                // Removed unused Using statements from the additional entrypoint source
                List<string> usedNamespaceNames = GetUsedTypes(compilation, sourceTree)
                    .Select(T => GetFullyQualifiedContainingNamespaceName(T)).Distinct().ToList();
                List<SyntaxNode> unusedUsingDirectives = sourceTree.GetRoot().DescendantNodes().Where(N =>
                {
                    return N.Kind() == SyntaxKind.UsingDirective && !((UsingDirectiveSyntax)N).Name.ToFullString().StartsWith("System.") && !usedNamespaceNames.Contains(((UsingDirectiveSyntax)N).Name.ToFullString());
                }).ToList();
                sourceTree = sourceTree.GetRoot().RemoveNodes(unusedUsingDirectives, SyntaxRemoveOptions.KeepNoTrivia).SyntaxTree;

                // Compile again, with unused SyntaxTrees and unused using statements removed
                compilationTrees.Add(sourceTree);
                compilation = CSharpCompilation.Create(
                    request.AssemblyName == null ? Path.GetRandomFileName() : request.AssemblyName,
                    compilationTrees,
                    request.References.Where(R => R.Framework == request.TargetDotNetVersion).Where(R => R.Enabled).Select(R =>
                    {
                        return MetadataReference.CreateFromFile(R.File);
                    }).ToList(),
                    options
                );
            }

            // Emit compilation
            EmitResult emitResult;
            byte[] ILbytes = null;
            using (var ms = new MemoryStream())
            {
                emitResult = compilation.Emit(
                    ms,
                    manifestResources: request.EmbeddedResources.Where(ER =>
                    {
                        return request.Platform == Platform.AnyCpu || ER.Platform == Platform.AnyCpu || ER.Platform == request.Platform;
                    }).Where(ER => ER.Enabled).Select(ER =>
                    {
                        return new ResourceDescription(ER.Name, () => File.OpenRead(ER.File), true);
                    }).ToList()
                );
                if (emitResult.Success)
                {
                    ms.Flush();
                    ms.Seek(0, SeekOrigin.Begin);
                    ILbytes = ms.ToArray();
                }
                else
                {
                    StringBuilder sb = new StringBuilder();
                    foreach (Diagnostic d in emitResult.Diagnostics)
                    {
                        sb.AppendLine(d.ToString());
                    }
                    throw new CompilerException("CompilationErrors: " + Environment.NewLine + sb);
                }
            }
            if (request.Confuse)
            {
                return ConfuseAssembly(ILbytes);
            }
            return ILbytes;
        }

        private static byte[] ConfuseAssembly(byte[] ILBytes)
        {
            ConfuserProject project = new ConfuserProject();
            System.Xml.XmlDocument doc = new System.Xml.XmlDocument();
            File.WriteAllBytes(Common.CovenantTempDirectory + "confused", ILBytes);
            string ProjectFile = String.Format(
                ConfuserExOptions,
                Common.CovenantTempDirectory,
                Common.CovenantTempDirectory,
                "confused"
            );
            doc.Load(new StringReader(ProjectFile));
            project.Load(doc);
            project.ProbePaths.Add(Common.CovenantAssemblyReferenceNet35Directory);
            project.ProbePaths.Add(Common.CovenantAssemblyReferenceNet40Directory);

            ConfuserParameters parameters = new ConfuserParameters();
            parameters.Project = project;
            parameters.Logger = default;
            ConfuserEngine.Run(parameters).Wait();
            return File.ReadAllBytes(Common.CovenantTempDirectory + "confused");
        }

        private static string ConfuserExOptions { get; set; } = @"
<project baseDir=""{0}"" outputDir=""{1}"" xmlns=""http://confuser.codeplex.com"">
 <module path=""{2}"">
    <rule pattern=""true"" inherit=""false"">
       <!-- <protection id=""anti debug"" />       -->
       <!-- <protection id=""anti dump"" />        -->
       <!-- <protection id=""anti ildasm"" />      -->
       <!-- <protection id=""anti tamper"" />      -->
       <!-- <protection id=""constants"" />        -->
       <!-- <protection id=""ctrl flow"" />        -->
       <!-- <protection id=""invalid metadata"" /> -->
       <!-- <protection id=""ref proxy"" />        -->
       <!-- <protection id=""rename"" />           -->
       <protection id=""resources"" />
    </rule>
  </module>
</project>
";

        private static string GetFullyQualifiedContainingNamespaceName(INamespaceSymbol namespaceSymbol)
        {
            string name = namespaceSymbol.Name;
            namespaceSymbol = namespaceSymbol.ContainingNamespace;
            while (namespaceSymbol != null)
            {
                name = namespaceSymbol.Name + "." + name;
                namespaceSymbol = namespaceSymbol.ContainingNamespace;
            }
            return name.Trim('.');
        }

        private static string GetFullyQualifiedContainingNamespaceName(ITypeSymbol symbol)
        {
            if (symbol.ContainingNamespace == null)
            {
                return symbol.Name;
            }
            return GetFullyQualifiedContainingNamespaceName(symbol.ContainingNamespace);
        }

        private static string GetFullyQualifiedTypeName(ITypeSymbol symbol)
        {
            return GetFullyQualifiedContainingNamespaceName(symbol) + "." + symbol.Name;
        }

        private static bool SyntaxTreeDefinesUsedType(CSharpCompilation compilation, SyntaxTree tree, List<string> typeNames)
        {
            SemanticModel model = compilation.GetSemanticModel(tree);
            return null != tree.GetRoot().DescendantNodes().FirstOrDefault(SN =>
            {
                if (SN.Kind() != SyntaxKind.ClassDeclaration)
                {
                    return false;
                }
                ITypeSymbol symbol = model.GetDeclaredSymbol(((ClassDeclarationSyntax)SN));
                if (symbol == null)
                {
                    return false;
                }
                return typeNames.Contains(GetFullyQualifiedTypeName(symbol));
            });
        }

        private static List<SymbolKind> typeKinds { get; } = new List<SymbolKind> { SymbolKind.ArrayType, SymbolKind.DynamicType, SymbolKind.ErrorType, SymbolKind.NamedType, SymbolKind.PointerType, SymbolKind.TypeParameter };
        private static HashSet<ITypeSymbol> GetUsedTypes(CSharpCompilation compilation, SyntaxTree sourceTree)
        {
            SemanticModel sm = compilation.GetSemanticModel(sourceTree);

            return sourceTree.GetRoot().DescendantNodes().Select(N => sm.GetSymbolInfo(N).Symbol).Where(S =>
            {
                return S != null && typeKinds.Contains(S.Kind);
            }).Select(T => (ITypeSymbol)T).ToHashSet();
        }

        private static HashSet<ITypeSymbol> GetUsedTypesRecursively(CSharpCompilation compilation, SyntaxTree sourceTree, ref HashSet<ITypeSymbol> currentUsedTypes, ref List<SourceSyntaxTree> sourceSyntaxTrees)
        {
            HashSet<string> copyCurrentUsedTypes = currentUsedTypes.Select(CT => GetFullyQualifiedTypeName(CT)).ToHashSet();

            HashSet<ITypeSymbol> usedTypes = GetUsedTypes(compilation, sourceTree);
            currentUsedTypes.UnionWith(usedTypes);

            HashSet<SyntaxTree> searchTrees = new HashSet<SyntaxTree>();
            foreach (ITypeSymbol symbol in usedTypes)
            {
                SyntaxReference sr = symbol.DeclaringSyntaxReferences.FirstOrDefault();
                if (sr != null)
                {
                    SourceSyntaxTree sst = sourceSyntaxTrees.FirstOrDefault(SST => SST.SyntaxTree == sr.SyntaxTree);
                    if (sst != null) { sst.UsedTypes.Add(symbol); }
                    string fullyQualifiedTypeName = GetFullyQualifiedTypeName(symbol);
                    searchTrees.Add(sr.SyntaxTree);
                }
            }

            searchTrees.Remove(sourceTree);
            foreach (SyntaxTree tree in searchTrees)
            {
                HashSet<ITypeSymbol> newTypes = GetUsedTypesRecursively(compilation, tree, ref currentUsedTypes, ref sourceSyntaxTrees);
                currentUsedTypes.UnionWith(newTypes);
            }
            return currentUsedTypes;
        }

        public static byte[] Compress(byte[] bytes)
        {
            byte[] compressedILBytes;
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (DeflateStream deflateStream = new DeflateStream(memoryStream, CompressionMode.Compress))
                {
                    deflateStream.Write(bytes, 0, bytes.Length);
                }
                compressedILBytes = memoryStream.ToArray();
            }
            return compressedILBytes;
        }
    }

    public class CompilerException : Exception
    {
        public CompilerException()
        {

        }

        public CompilerException(string message) : base(message)
        {

        }

        public CompilerException(string message, Exception inner) : base(message, inner)
        {

        }
    }
}
