// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using Reflect = System.Reflection;

using SharpSploit.Generic;

namespace SharpSploit.Execution
{
    /// <summary>
    /// Assembly is a library for loading .NET assemblies and executing methods contained within them.
    /// </summary>
    public class Assembly
    {
        /// <summary>
        /// Loads a specified .NET assembly byte array and executes the EntryPoint.
        /// </summary>
        /// <param name="AssemblyBytes">The .NET assembly byte array.</param>
        /// <param name="Args">The arguments to pass to the assembly's EntryPoint.</param>
        public static void AssemblyExecute(byte[] AssemblyBytes, Object[] Args = null)
        {
            if (Args == null)
            {
                Args = new Object[] { new string[] { } };
            }
            Reflect.Assembly assembly = Load(AssemblyBytes);
            assembly.EntryPoint.Invoke(null, Args);
        }

        /// <summary>
        /// Loads a specified .NET assembly byte array and executes a specified method within a
        /// specified type with specified parameters.
        /// </summary>
        /// <param name="AssemblyBytes">The .NET assembly byte array.</param>
        /// <param name="TypeName">The name of the type that contains the method to execute.</param>
        /// <param name="MethodName">The name of the method to execute.</param>
        /// <param name="Parameters">The parameters to pass to the method.</param>
        /// <returns>GenericObjectResult of the method.</returns>
        public static GenericObjectResult AssemblyExecute(byte[] AssemblyBytes, String TypeName = "", String MethodName = "Execute", Object[] Parameters = default(Object[]))
        {
            Reflect.Assembly assembly = Load(AssemblyBytes);
            Type type = TypeName == "" ? assembly.GetTypes()[0] : assembly.GetType(TypeName);
            Reflect.MethodInfo method = MethodName == "" ? type.GetMethods()[0] : type.GetMethod(MethodName);
            var results = method.Invoke(null, Parameters);
            return new GenericObjectResult(results);
        }

        /// <summary>
        /// Loads a specified base64-encoded .NET assembly and executes a specified method within a
        /// specified type with specified parameters.
        /// </summary>
        /// <param name="EncodedAssembly">The base64-encoded .NET assembly byte array.</param>
        /// <param name="TypeName">The name of the type that contains the method to execute.</param>
        /// <param name="MethodName">The name of the method to execute.</param>
        /// <param name="Parameters">The parameters to pass to the method.</param>
        /// <returns>GenericObjectResult of the method.</returns>
        public static GenericObjectResult AssemblyExecute(String EncodedAssembly, String TypeName = "", String MethodName = "Execute", Object[] Parameters = default(Object[]))
        {
            return AssemblyExecute(Convert.FromBase64String(EncodedAssembly), TypeName, MethodName, Parameters);
        }

        /// <summary>
        /// Loads a specified base64-encoded .NET assembly and executes the EntryPoint.
        /// </summary>
        /// <param name="EncodedAssembly">The base64-encoded .NET assembly byte array.</param>
        /// <param name="Args">The arguments to pass to the assembly's EntryPoint.</param>
        public static void AssemblyExecute(String EncodedAssembly, Object[] Args = default(Object[]))
        {
            AssemblyExecute(Convert.FromBase64String(EncodedAssembly), Args);
        }

        /// <summary>
        /// Loads a specified .NET assembly byte array.
        /// </summary>
        /// <param name="AssemblyBytes">The .NET assembly byte array.</param>
        /// <returns>Loaded assembly.</returns>
        public static Reflect.Assembly Load(byte[] AssemblyBytes)
        {
            return Reflect.Assembly.Load(AssemblyBytes);
        }

        /// <summary>
        /// Loads a specified .NET assembly byte array.
        /// </summary>
        /// <param name="EncodedAssembly">The base64-encoded .NET assembly byte array.</param>
        /// <returns>Loaded assembly.</returns>
        public static Reflect.Assembly Load(string EncodedAssembly)
        {
            return Reflect.Assembly.Load(Convert.FromBase64String(EncodedAssembly));
        }
    }
}
