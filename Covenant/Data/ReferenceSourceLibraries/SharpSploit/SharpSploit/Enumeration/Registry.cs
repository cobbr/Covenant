// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.IO;
using System.Linq;
using Win = Microsoft.Win32;

namespace SharpSploit.Enumeration
{
    /// <summary>
    /// Host is a library for local host enumeration.
    /// </summary>
    public class Registry
    {
        #region Local Registry
        /// <summary>
        /// Gets the value of a RegistryKey.
        /// </summary>
        /// <param name="RegHiveKeyValue">The path to the registry key to set, including: hive, subkey, and value name.</param>
        /// <returns>The value of a RegistryKey, cast as a string.</returns>
        public static string GetRegistryKey(string RegHiveKeyValue)
        {
            return GetRegistryKey(RegHiveKeyValue, "");
        }

        /// <summary>
        /// Gets the entries of a RegistryKey or value of a RegistryKey.
        /// </summary>
        /// <param name="RegHiveKey">The path to the registry key to set, including: hive and subkey.</param>
        /// <param name="RegValue">The name of name/value pair to read from in the RegistryKey.</param>
        /// <returns>List of the entries of the RegistrySubKey or the RegistryValue, cast as a string.</returns>
        public static string GetRegistryKey(string RegHiveKey, string RegValue)
        {
            string[] pieces = RegHiveKey.Split(Path.DirectorySeparatorChar);
            string hivename = pieces.First();
            string keyname = "";
            for (int i = 1; i < pieces.Length; i++)
            {
                keyname += pieces[i] + Path.DirectorySeparatorChar;
            }
            return GetRegistryKey(ConvertToRegistryHive(hivename), keyname.Trim(Path.DirectorySeparatorChar), RegValue);
        }

        /// <summary>
        /// Gets the entries of a RegistryKey or value of a RegistryKey.
        /// </summary>
        /// <param name="RegHive">The RegistryHive to read from.</param>
        /// <param name="RegKey">The RegistryKey, including the hive, to read from.</param>
        /// <param name="RegValue">The name of name/value pair to read from in the RegistryKey.</param>
        /// <returns>List of the entries of the RegistrySubKey or the RegistryValue, cast as a string.</returns>
        public static string GetRegistryKey(string RegHive, string RegKey, string RegValue)
        {
            return GetRegistryKey(ConvertToRegistryHive(RegHive), RegKey, RegValue);
        }

        /// <summary>
        /// Gets the entries of a RegistryKey or value of a RegistryKey.
        /// </summary>
        /// <param name="RegHive">The RegistryHive to read from.</param>
        /// <param name="RegKey">The RegistryKey in the RegsitryHive to read from.</param>
        /// <param name="RegValue">The name of name/value pair to read from in the RegistryKey.</param>
        /// <returns>List of the entries of the RegistrySubKey or the RegistryValue, cast as a string.</returns>
        public static string GetRegistryKey(Win.RegistryHive RegHive, string RegKey, string RegValue)
        {
            Win.RegistryKey baseKey = null;
            switch (RegHive)
            {
                case Win.RegistryHive.CurrentUser:
                    baseKey = Win.Registry.CurrentUser;
                    break;
                case Win.RegistryHive.LocalMachine:
                    baseKey = Win.Registry.LocalMachine;
                    break;
                case Win.RegistryHive.ClassesRoot:
                    baseKey = Win.Registry.ClassesRoot;
                    break;
                case Win.RegistryHive.CurrentConfig:
                    baseKey = Win.Registry.CurrentConfig;
                    break;
                case Win.RegistryHive.Users:
                    baseKey = Win.Registry.Users;
                    break;
                default:
                    baseKey = Win.Registry.CurrentUser;
                    break;
            }
            string[] pieces = RegKey.Split(Path.DirectorySeparatorChar);
            for (int i = 0; i < pieces.Length; i++)
            {
                string[] valuenames = baseKey.GetValueNames();
                string[] subkeynames = baseKey.GetSubKeyNames();
                if (i == pieces.Length - 1 && valuenames.Contains(pieces[i], StringComparer.OrdinalIgnoreCase))
                {
                    string keyname = "";
                    for (int j = 0; j < pieces.Length - 1; j++)
                    {
                        keyname += pieces[j] + Path.DirectorySeparatorChar;
                    }
                    return GetRegistryKeyValue(baseKey, pieces[i]);
                }
                if (!subkeynames.Contains(pieces[i], StringComparer.OrdinalIgnoreCase))
                {
                    return null;
                }
                baseKey = baseKey.OpenSubKey(pieces[i]);
            }
            if (string.IsNullOrEmpty(RegValue))
            {
                string output = "Key: " + RegHive.ToString() + "\\" + RegKey + Environment.NewLine;
                string[] valuenames = baseKey.GetValueNames();
                string[] subkeynames = baseKey.GetSubKeyNames();
                if (subkeynames.Any())
                {
                    output += "SubKeys:" + Environment.NewLine;
                }
                foreach (string subkeyname in subkeynames)
                {
                    output += "  " + subkeyname + Environment.NewLine;
                }
                if (valuenames.Any())
                {
                    output += "Values:";
                }
                foreach (string valuename in valuenames)
                {
                    output += Environment.NewLine;
                    output += "  Name: " + valuename + Environment.NewLine;
                    output += "  Kind: " + baseKey.GetValueKind(valuename).ToString() + Environment.NewLine;
                    output += "  Value: " + baseKey.GetValue(valuename) + Environment.NewLine;
                }
                return output.Trim();
            }
            return GetRegistryKeyValue(baseKey, RegValue);
        }

        /// <summary>
        /// Gets a value stored in a RegistryKey.
        /// </summary>
        /// <param name="RegHiveKey">The RegistryKey to set.</param>
        /// <param name="RegValue">The name of name/value pair to read from in the RegistryKey.</param>
        /// <returns>Content of the value of the RegistryKey, cast as a string.</returns>
        private static string GetRegistryKeyValue(Win.RegistryKey RegHiveKey, string RegValue)
        {
            object value = null;
            try
            {
                value = RegHiveKey.GetValue(RegValue, null);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Registry read exception: " + e.Message);
            }
            return value == null ? null : value.ToString();
        }

        /// <summary>
        /// Sets a value in the registry.
        /// </summary>
        /// <param name="RegHiveKeyValue">The path to the registry key to set, including: hive, subkey, and value name.</param>
        /// <param name="Value">The value to write to the registry key.</param>
        /// <returns>True if succeeded, false otherwise.</returns>
        public static bool SetRegistryKey(string RegHiveKeyValue, object Value)
        {
            string[] pieces = RegHiveKeyValue.Split(Path.DirectorySeparatorChar);
            if (!pieces.Any()) { return false; }
            string RegHiveKey = "";
            for (int i = 1; i < pieces.Length - 1; i++)
            {
                RegHiveKey = pieces[i] + Path.DirectorySeparatorChar;
            }
            return SetRegistryKey(ConvertToRegistryHive(pieces.First()), RegHiveKey.Trim(Path.DirectorySeparatorChar), pieces[pieces.Length - 1], Value);
        }

        /// <summary>
        /// Sets a value in the registry.
        /// </summary>
        /// <param name="RegHiveKey">The path to the registry key to set, including: hive and subkey.</param>
        /// <param name="RegValue">The name of the RegistryKey to set.</param>
        /// <param name="Value">The value to write to the registry key.</param>
        /// <returns>True if succeeded, false otherwise.</returns>
        public static bool SetRegistryKey(string RegHiveKey, string RegValue, object Value)
        {
            string[] pieces = RegHiveKey.Split(Path.DirectorySeparatorChar);
            if (!pieces.Any()) { return false; }
            string RegKey = "";
            for (int i = 1; i < pieces.Length; i++)
            {
                RegKey = pieces[i] + Path.DirectorySeparatorChar;
            }
            return SetRegistryKey(ConvertToRegistryHive(pieces.First()), RegKey.Trim(Path.DirectorySeparatorChar), RegValue, Value);
        }

        /// <summary>
        /// Sets a value in the registry.
        /// </summary>
        /// <param name="RegHive">The RegistryHive to set within.</param>
        /// <param name="RegKey">The RegistryKey to set, including the hive.</param>
        /// <param name="RegValue">The name of name/value pair to write to in the RegistryKey.</param>
        /// <param name="Value">The value to write to the registry key.</param>
        /// <returns>True if succeeded, false otherwise.</returns>
        public static bool SetRegistryKey(string RegHive, string RegKey, string RegValue, object Value)
        {
            return SetRegistryKey(ConvertToRegistryHive(RegHive), RegKey, RegValue, Value);
        }

        /// <summary>
        /// Sets a value in the registry.
        /// </summary>
        /// <param name="RegHive">The RegistryHive to set within.</param>
        /// <param name="RegKey">The RegistryKey to set, including the hive.</param>
        /// <param name="RegValue">The name of name/value pair to write to in the RegistryKey.</param>
        /// <param name="Value">The value to write to the registry key.</param>
        /// <returns>True if succeeded, false otherwise.</returns>
        public static bool SetRegistryKey(Win.RegistryHive RegHive, string RegKey, string RegValue, object Value)
        {
            Win.RegistryKey baseKey = null;
            switch (RegHive)
            {
                case Win.RegistryHive.CurrentUser:
                    baseKey = Win.Registry.CurrentUser;
                    break;
                case Win.RegistryHive.LocalMachine:
                    baseKey = Win.Registry.LocalMachine;
                    break;
                case Win.RegistryHive.ClassesRoot:
                    baseKey = Win.Registry.ClassesRoot;
                    break;
                case Win.RegistryHive.CurrentConfig:
                    baseKey = Win.Registry.CurrentConfig;
                    break;
                case Win.RegistryHive.Users:
                    baseKey = Win.Registry.Users;
                    break;
                default:
                    baseKey = Win.Registry.CurrentUser;
                    break;
            }
            string[] pieces = RegKey.Split(Path.DirectorySeparatorChar);
            for (int i = 0; i < pieces.Length; i++)
            {
                string[] subkeynames = baseKey.GetSubKeyNames();
                if (!subkeynames.Contains(pieces[i], StringComparer.OrdinalIgnoreCase))
                {
                    baseKey = baseKey.CreateSubKey(pieces[i]);
                }
                else
                {
                    baseKey = baseKey.OpenSubKey(pieces[i], true);
                }
            }
            return SetRegistryKeyValue(baseKey, RegValue, Value);
        }

        /// <summary>
        /// Sets a value in the registry.
        /// </summary>
        /// <param name="RegHiveKey">The RegistryKey to set.</param>
        /// <param name="RegValue">The name of name/value pair to write to in the RegistryKey.</param>
        /// <param name="Value">The value to write to the registry key.</param>
        /// <returns>True if succeeded, false otherwise.</returns>
        private static bool SetRegistryKeyValue(Win.RegistryKey RegHiveKey, string RegValue, object Value)
        {
            try
            {
                RegHiveKey.SetValue(RegValue, Value);
                return true;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.GetType().FullName + ": " + e.Message);
                return false;
            }
        }
        #endregion
        #region Remote Registry
        /// <summary>
        /// Gets the value of a RegistryKey.
        /// </summary>
        /// <param name="Hostname">Remote hostname to connect to for remote registry.</param>
        /// <param name="RegHiveKeyValue">The path to the registry key to set, including: hive, subkey, and value name.</param>
        /// <returns>The value of a RegistryKey, cast as a string.</returns>
        public static string GetRemoteRegistryKey(string Hostname, string RegHiveKeyValue)
        {
            return GetRemoteRegistryKey(Hostname, RegHiveKeyValue, "");
        }

        /// <summary>
        /// Gets the entries of a RegistryKey or value of a RegistryKey.
        /// </summary>
        /// <param name="Hostname">Remote hostname to connect to for remote registry.</param>
        /// <param name="RegHiveKey">The path to the registry key to set, including: hive and subkey.</param>
        /// <param name="RegValue">The name of name/value pair to read from in the RegistryKey.</param>
        /// <returns>List of the entries of the RegistrySubKey or the RegistryValue, cast as a string.</returns>
        public static string GetRemoteRegistryKey(string Hostname, string RegHiveKey, string RegValue)
        {
            string[] pieces = RegHiveKey.Split(Path.DirectorySeparatorChar);
            string hivename = pieces.First();
            string keyname = "";
            for (int i = 1; i < pieces.Length; i++)
            {
                keyname += pieces[i] + Path.DirectorySeparatorChar;
            }
            return GetRemoteRegistryKey(Hostname, ConvertToRegistryHive(hivename), keyname.Trim(Path.DirectorySeparatorChar), RegValue);
        }

        /// <summary>
        /// Gets the entries of a RegistryKey or value of a RegistryKey.
        /// </summary>
        /// <param name="Hostname">Remote hostname to connect to for remote registry.</param>
        /// <param name="RegHive">The RegistryHive to read from.</param>
        /// <param name="RegKey">The RegistryKey, including the hive, to read from.</param>
        /// <param name="RegValue">The name of name/value pair to read from in the RegistryKey.</param>
        /// <returns>List of the entries of the RegistrySubKey or the RegistryValue, cast as a string.</returns>
        public static string GetRemoteRegistryKey(string Hostname, string RegHive, string RegKey, string RegValue)
        {
            return GetRemoteRegistryKey(Hostname, ConvertToRegistryHive(RegHive), RegKey, RegValue);
        }

        /// <summary>
        /// Gets the entries of a RegistryKey or value of a RegistryKey.
        /// </summary>
        /// <param name="Hostname">Remote hostname to connect to for remote registry.</param>
        /// <param name="RegHive">The RegistryHive to read from.</param>
        /// <param name="RegKey">The RegistryKey in the RegsitryHive to read from.</param>
        /// <param name="RegValue">The name of name/value pair to read from in the RegistryKey.</param>
        /// <returns>List of the entries of the RegistrySubKey or the RegistryValue, cast as a string.</returns>
        public static string GetRemoteRegistryKey(string Hostname, Win.RegistryHive RegHive, string RegKey, string RegValue = "")
        {
            Win.RegistryKey baseKey = null;
            switch (RegHive)
            {
                case Win.RegistryHive.CurrentUser:
                    baseKey = Win.RegistryKey.OpenRemoteBaseKey(Win.RegistryHive.CurrentUser, Hostname);
                    break;
                case Win.RegistryHive.LocalMachine:
                    baseKey = Win.RegistryKey.OpenRemoteBaseKey(Win.RegistryHive.LocalMachine, Hostname);
                    break;
                case Win.RegistryHive.ClassesRoot:
                    baseKey = Win.RegistryKey.OpenRemoteBaseKey(Win.RegistryHive.ClassesRoot, Hostname);
                    break;
                case Win.RegistryHive.CurrentConfig:
                    baseKey = Win.RegistryKey.OpenRemoteBaseKey(Win.RegistryHive.CurrentConfig, Hostname);
                    break;
                case Win.RegistryHive.Users:
                    baseKey = Win.RegistryKey.OpenRemoteBaseKey(Win.RegistryHive.Users, Hostname);
                    break;
                default:
                    baseKey = Win.RegistryKey.OpenRemoteBaseKey(Win.RegistryHive.CurrentUser, Hostname);
                    break;
            }
            string[] pieces = RegKey.Split(Path.DirectorySeparatorChar);
            for (int i = 0; i < pieces.Length; i++)
            {
                string[] valuenames = baseKey.GetValueNames();
                string[] subkeynames = baseKey.GetSubKeyNames();
                if (i == pieces.Length - 1 && valuenames.Contains(pieces[i], StringComparer.OrdinalIgnoreCase))
                {
                    string keyname = "";
                    for (int j = 0; j < pieces.Length - 1; j++)
                    {
                        keyname += pieces[j] + Path.DirectorySeparatorChar;
                    }
                    return GetRegistryKeyValue(baseKey, pieces[i]);
                }
                if (!subkeynames.Contains(pieces[i], StringComparer.OrdinalIgnoreCase))
                {
                    return null;
                }
                baseKey = baseKey.OpenSubKey(pieces[i]);
            }
            if (string.IsNullOrEmpty(RegValue))
            {
                string output = "Key: " + RegHive.ToString() + "\\" + RegKey + Environment.NewLine;
                string[] valuenames = baseKey.GetValueNames();
                string[] subkeynames = baseKey.GetSubKeyNames();
                if (subkeynames.Any())
                {
                    output += "SubKeys:" + Environment.NewLine;
                }
                foreach (string subkeyname in subkeynames)
                {
                    output += "  " + subkeyname + Environment.NewLine;
                }
                if (valuenames.Any())
                {
                    output += "Values:";
                }
                foreach (string valuename in valuenames)
                {
                    output += Environment.NewLine;
                    output += "  Name: " + valuename + Environment.NewLine;
                    output += "  Kind: " + baseKey.GetValueKind(valuename).ToString() + Environment.NewLine;
                    output += "  Value: " + baseKey.GetValue(valuename) + Environment.NewLine;
                }
                return output.Trim();
            }
            return GetRegistryKeyValue(baseKey, RegValue);
        }

        /// <summary>
        /// Sets a value in the registry.
        /// </summary>
        /// <param name="Hostname">Remote hostname to connect to for remote registry.</param>
        /// <param name="RegHiveKeyValue">The path to the registry key to set, including: hive, subkey, and value name.</param>
        /// <param name="Value">The value to write to the registry key.</param>
        /// <returns>True if succeeded, false otherwise.</returns>
        public static bool SetRemoteRegistryKey(string Hostname, string RegHiveKeyValue, object Value)
        {
            string[] pieces = RegHiveKeyValue.Split(Path.DirectorySeparatorChar);
            if (!pieces.Any()) { return false; }
            string RegHiveKey = "";
            for (int i = 1; i < pieces.Length - 1; i++)
            {
                RegHiveKey = pieces[i] + Path.DirectorySeparatorChar;
            }
            return SetRemoteRegistryKey(Hostname, ConvertToRegistryHive(pieces.First()), RegHiveKey.Trim(Path.DirectorySeparatorChar), pieces[pieces.Length - 1], Value);
        }

        /// <summary>
        /// Sets a value in the registry.
        /// </summary>
        /// <param name="Hostname">Remote hostname to connect to for remote registry.</param>
        /// <param name="RegHiveKey">The path to the registry key to set, including: hive and subkey.</param>
        /// <param name="RegValue">The name of the RegistryKey to set.</param>
        /// <param name="Value">The value to write to the registry key.</param>
        /// <returns>True if succeeded, false otherwise.</returns>
        public static bool SetRemoteRegistryKey(string Hostname, string RegHiveKey, string RegValue, object Value)
        {
            string[] pieces = RegHiveKey.Split(Path.DirectorySeparatorChar);
            if (!pieces.Any()) { return false; }
            string RegKey = "";
            for (int i = 1; i < pieces.Length; i++)
            {
                RegKey = pieces[i] + Path.DirectorySeparatorChar;
            }
            return SetRemoteRegistryKey(Hostname, ConvertToRegistryHive(pieces.First()), RegKey.Trim(Path.DirectorySeparatorChar), RegValue, Value);
        }

        /// <summary>
        /// Sets a value in the registry.
        /// </summary>
        /// <param name="Hostname">Remote hostname to connect to for remote registry.</param>
        /// <param name="RegHive">The RegistryHive to set within.</param>
        /// <param name="RegKey">The RegistryKey to set, including the hive.</param>
        /// <param name="RegValue">The name of name/value pair to write to in the RegistryKey.</param>
        /// <param name="Value">The value to write to the registry key.</param>
        /// <returns>True if succeeded, false otherwise.</returns>
        public static bool SetRemoteRegistryKey(string Hostname, string RegHive, string RegKey, string RegValue, object Value)
        {
            return SetRemoteRegistryKey(Hostname, ConvertToRegistryHive(RegHive), RegKey, RegValue, Value);
        }

        /// <summary>
        /// Sets a value in the registry.
        /// </summary>
        /// <param name="Hostname">Remote hostname to connect to for remote registry.</param>
        /// <param name="RegHive">The RegistryHive to set within.</param>
        /// <param name="RegKey">The RegistryKey to set, including the hive.</param>
        /// <param name="RegValue">The name of name/value pair to write to in the RegistryKey.</param>
        /// <param name="Value">The value to write to the registry key.</param>
        /// <returns>True if succeeded, false otherwise.</returns>
        public static bool SetRemoteRegistryKey(string Hostname, Win.RegistryHive RegHive, string RegKey, string RegValue, object Value)
        {
            Win.RegistryKey baseKey = null;
            switch (RegHive)
            {
                case Win.RegistryHive.CurrentUser:
                    baseKey = Win.RegistryKey.OpenRemoteBaseKey(Win.RegistryHive.CurrentUser, Hostname);
                    break;
                case Win.RegistryHive.LocalMachine:
                    baseKey = Win.RegistryKey.OpenRemoteBaseKey(Win.RegistryHive.LocalMachine, Hostname);
                    break;
                case Win.RegistryHive.ClassesRoot:
                    baseKey = Win.RegistryKey.OpenRemoteBaseKey(Win.RegistryHive.ClassesRoot, Hostname);
                    break;
                case Win.RegistryHive.CurrentConfig:
                    baseKey = Win.RegistryKey.OpenRemoteBaseKey(Win.RegistryHive.CurrentConfig, Hostname);
                    break;
                case Win.RegistryHive.Users:
                    baseKey = Win.RegistryKey.OpenRemoteBaseKey(Win.RegistryHive.Users, Hostname);
                    break;
                default:
                    baseKey = Win.RegistryKey.OpenRemoteBaseKey(Win.RegistryHive.CurrentUser, Hostname);
                    break;
            }
            string[] pieces = RegKey.Split(Path.DirectorySeparatorChar);
            for (int i = 0; i < pieces.Length; i++)
            {
                string[] subkeynames = baseKey.GetSubKeyNames();
                if (!subkeynames.Contains(pieces[i], StringComparer.OrdinalIgnoreCase))
                {
                    baseKey = baseKey.CreateSubKey(pieces[i]);
                }
                else
                {
                    baseKey = baseKey.OpenSubKey(pieces[i], true);
                }
            }
            return SetRegistryKeyValue(baseKey, RegValue, Value);
        }
        #endregion

        private static Win.RegistryHive ConvertToRegistryHive(string RegHive)
        {
            if (RegHive.Equals("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase) || RegHive.Equals("HKCU", StringComparison.OrdinalIgnoreCase))
            {
                return Win.RegistryHive.CurrentUser;
            }
            if (RegHive.Equals("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase) || RegHive.Equals("HKLM", StringComparison.OrdinalIgnoreCase))
            {
                return Win.RegistryHive.LocalMachine;
            }
            if (RegHive.Equals("HKEY_CLASSES_ROOT", StringComparison.OrdinalIgnoreCase) || RegHive.Equals("HKCR", StringComparison.OrdinalIgnoreCase))
            {
                return Win.RegistryHive.ClassesRoot;
            }
            if (RegHive.Equals("HKEY_CURRENT_CONFIG", StringComparison.OrdinalIgnoreCase) || RegHive.Equals("HKCC", StringComparison.OrdinalIgnoreCase))
            {
                return Win.RegistryHive.CurrentConfig;
            }
            if (RegHive.Equals("HKEY_USERS", StringComparison.OrdinalIgnoreCase) || RegHive.Equals("HKU", StringComparison.OrdinalIgnoreCase))
            {
                return Win.RegistryHive.Users;
            }
            return Win.RegistryHive.CurrentUser;
        }

        private static string ConvertRegistryHiveToString(Win.RegistryHive RegHive)
        {
            switch (RegHive)
            {
                case Win.RegistryHive.CurrentUser:
                    return "HKEY_CURRENT_USER";
                case Win.RegistryHive.LocalMachine:
                    return "HKEY_LOCAL_MACHINE";
                case Win.RegistryHive.ClassesRoot:
                    return "HKEY_CLASSES_ROOT";
                case Win.RegistryHive.CurrentConfig:
                    return "HKEY_CURRENT_CONFIG";
                case Win.RegistryHive.Users:
                    return "HKEY_USERS";
                default:
                    return "HKEY_CURRENT_USER";
            }
        }
    }
}
