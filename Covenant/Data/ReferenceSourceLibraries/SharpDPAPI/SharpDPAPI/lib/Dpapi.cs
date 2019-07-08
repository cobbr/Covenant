using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using PBKDF2;

namespace SharpDPAPI
{
    public class Dpapi
    {
        public static byte[] DescribeDPAPIBlob(byte[] blobBytes, Dictionary<string, string> MasterKeys, string blobType = "credential")
        {
            // parses a DPAPI credential or vault policy blob, also returning the decrypted blob plaintext

            // credentialBytes  ->  byte array of the credential file
            // MasterKeys       ->  dictionary of GUID:Sha1(MasterKey) mappings for decryption
            // blobType         ->  "credential" or vault "policy"

            int offset = 0;
            if (blobType.Equals("credential"))
            {
                offset = 36;
            }
            else if (blobType.Equals("policy"))
            {
                offset = 24;
            }
            else
            {
                Console.WriteLine("[X] Unsupported blob type: {0}", blobType);
                return new byte[0];
            }

            byte[] guidMasterKeyBytes = new byte[16];
            Array.Copy(blobBytes, offset, guidMasterKeyBytes, 0, 16);
            Guid guidMasterKey = new Guid(guidMasterKeyBytes);
            string guidString = String.Format("{{{0}}}", guidMasterKey);
            Console.WriteLine("    guidMasterKey    : {0}", guidString);
            offset += 16;

            Console.WriteLine("    size             : {0}", blobBytes.Length);

            UInt32 flags = BitConverter.ToUInt32(blobBytes, offset);
            offset += 4;
            Console.Write("    flags            : 0x{0}", flags.ToString("X"));
            if ((flags & 0x20000000) == flags)
            {
                Console.Write(" (CRYPTPROTECT_SYSTEM)");
            }
            Console.WriteLine();

            int descLength = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;
            string description = Encoding.Unicode.GetString(blobBytes, offset, descLength);
            offset += descLength;

            int algCrypt = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            int algCryptLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            int saltLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            byte[] saltBytes = new byte[saltLen];
            Array.Copy(blobBytes, offset, saltBytes, 0, saltLen);
            offset += saltLen;

            int hmacKeyLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4 + hmacKeyLen;

            int algHash = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            Console.WriteLine("    algHash/algCrypt : {0}/{1}", algHash, algCrypt);

            Console.WriteLine("    description      : {0}", description);

            int algHashLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            int hmac2KeyLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4 + hmac2KeyLen;

            int dataLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;
            byte[] dataBytes = new byte[dataLen];
            Array.Copy(blobBytes, offset, dataBytes, 0, dataLen);

            if (MasterKeys.ContainsKey(guidString))
            {
                // if this key is present, decrypt this blob

                if (algHash == 32782)
                {
                    // grab the sha1(masterkey) from the cache
                    try
                    {
                        byte[] keyBytes = Helpers.StringToByteArray(MasterKeys[guidString].ToString());

                        // derive the session key
                        byte[] derivedKeyBytes = Crypto.DeriveKey(keyBytes, saltBytes, algHash);
                        byte[] finalKeyBytes = new byte[algCryptLen / 8];
                        Array.Copy(derivedKeyBytes, finalKeyBytes, algCryptLen / 8);

                        // decrypt the blob with the session key
                        return Crypto.DecryptBlob(dataBytes, finalKeyBytes, algCrypt);
                    }
                    catch
                    {
                        Console.WriteLine("Error retrieving GUID:SHA1 from cache {0}", guidString);
                    }
                }
                else if (algHash == 32772)
                {
                    try {
                        // grab the sha1(masterkey) from the cache
                        byte[] keyBytes = Helpers.StringToByteArray(MasterKeys[guidString].ToString());

                        // derive the session key
                        byte[] derivedKeyBytes = Crypto.DeriveKey(keyBytes, saltBytes, algHash);
                        byte[] finalKeyBytes = new byte[algCryptLen / 8];
                        Array.Copy(derivedKeyBytes, finalKeyBytes, algCryptLen / 8);

                        // decrypt the blob with the session key
                        return Crypto.DecryptBlob(dataBytes, finalKeyBytes, algCrypt);
                    }
                    catch
                    {
                        Console.WriteLine("Error retrieving GUID:SHA1 from cache {0}", guidString);
                    }
                }
                else
                {
                    Console.WriteLine("    [X] Only sha1 and sha256 are currently supported for the hash algorithm. Alg '{0}' not supported", algHash);
                }
            }
            else
            {
                Console.WriteLine("    [X] MasterKey GUID not in cache: {0}", guidString);
            }
            Console.WriteLine();

            return new byte[0];
        }

        public static ArrayList DescribePolicy(byte[] policyBytes, Dictionary<string, string> MasterKeys)
        {
            // parses a vault policy file, attempting to decrypt if possible
            // a two-valued arraylist of the aes128/aes256 keys is returned if decryption is successful

            // from https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L111-L131
            /*
               typedef struct _KULL_M_CRED_VAULT_POLICY_KEY {
	                GUID unk0;
	                GUID unk1;
	                DWORD dwKeyBlob;
	                PVOID KeyBlob;
                } KULL_M_CRED_VAULT_POLICY_KEY, *PKULL_M_CRED_VAULT_POLICY_KEY;

                typedef struct _KULL_M_CRED_VAULT_POLICY {
	                DWORD version;
	                GUID vault;

	                DWORD dwName;
	                LPWSTR Name;

	                DWORD unk0;
	                DWORD unk1;
	                DWORD unk2;

	                DWORD dwKey;
	                PKULL_M_CRED_VAULT_POLICY_KEY key;
                } KULL_M_CRED_VAULT_POLICY, *PKULL_M_CRED_VAULT_POLICY;
            */
            
            int offset = 0;

            int version = BitConverter.ToInt32(policyBytes, offset);
            offset += 4;

            byte[] vaultIDbytes = new byte[16];
            Array.Copy(policyBytes, offset, vaultIDbytes, 0, 16);
            Guid vaultID = new Guid(vaultIDbytes);
            offset += 16;

            Console.WriteLine("\r\n  VaultID            : {0}", vaultID);

            int nameLen = BitConverter.ToInt32(policyBytes, offset);
            offset += 4;
            string name = Encoding.Unicode.GetString(policyBytes, offset, nameLen);
            offset += nameLen;
            Console.WriteLine("  Name               : {0}", name);

            // skip unk0/unk1/unk2
            offset += 12;

            int keyLen = BitConverter.ToInt32(policyBytes, offset);
            offset += 4;

            // skip unk0/unk1 GUIDs
            offset += 32;

            int keyBlobLen = BitConverter.ToInt32(policyBytes, offset);
            offset += 4;

            // extract out the DPAPI blob
            byte[] blobBytes = new byte[keyBlobLen];
            Array.Copy(policyBytes, offset, blobBytes, 0, keyBlobLen);

            // 24 -> offset where the masterkey GUID starts
            byte[] plaintextBytes = DescribeDPAPIBlob(blobBytes, MasterKeys, "policy");

            if (plaintextBytes.Length > 0)
            {
                ArrayList keys = ParseDecPolicyBlob(plaintextBytes);

                if (keys.Count == 2)
                {
                    string aes128KeyStr = BitConverter.ToString((byte[])keys[0]).Replace("-", "");
                    Console.WriteLine("    aes128 key       : {0}", aes128KeyStr);

                    string aes256KeyStr = BitConverter.ToString((byte[])keys[1]).Replace("-", "");
                    Console.WriteLine("    aes256 key       : {0}", aes256KeyStr);

                    return keys;
                }
                else
                {
                    Console.WriteLine("    [X] Error parsing decrypted Policy.vpol (AES keys not extracted)");
                    return new ArrayList();
                }
            }
            else
            {
                return new ArrayList();
            }
        }

        public static void DescribeVaultCred(byte[] vaultBytes, ArrayList AESKeys)
        {
            // parses a vault credential file and displays data, attempting to decrypt if the necessary AES keys are supplied

            // from https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L139-L154
            /*
                typedef struct _KULL_M_CRED_VAULT_CREDENTIAL {
	                GUID SchemaId;
	                DWORD unk0; // 4
	                FILETIME LastWritten;
	                DWORD unk1; // ffffffff
	                DWORD unk2; // flags ?

	                DWORD dwFriendlyName;
	                LPWSTR FriendlyName;
	
	                DWORD dwAttributesMapSize;
	                PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP attributesMap;

	                DWORD __cbElements;
	                PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE *attributes;
                } KULL_M_CRED_VAULT_CREDENTIAL, *PKULL_M_CRED_VAULT_CREDENTIAL;
            */

            byte[] aes128key = (byte[])AESKeys[0];
            byte[] aes256key = (byte[])AESKeys[1];

            int offset = 0;
            int finalAttributeOffset = 0;

            // skip the schema GUID
            offset += 16;

            int unk0 = BitConverter.ToInt32(vaultBytes, offset);
            offset += 4;

            long lastWritten = (long)BitConverter.ToInt64(vaultBytes, offset);
            offset += 8;
            System.DateTime lastWrittenTime = System.DateTime.FromFileTime(lastWritten);
            Console.WriteLine("\r\n    LastWritten      : {0}", lastWrittenTime);

            // skip unk1/unk2
            offset += 8;

            int friendlyNameLen = BitConverter.ToInt32(vaultBytes, offset);
            offset += 4;

            string friendlyName = Encoding.Unicode.GetString(vaultBytes, offset, friendlyNameLen);
            offset += friendlyNameLen;
            Console.WriteLine("    FriendlyName     : {0}", friendlyName);

            int attributeMapLen = BitConverter.ToInt32(vaultBytes, offset);
            offset += 4;

            // https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L133-L137
            /*
                typedef struct _KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP {
	                DWORD id;
	                DWORD offset; //maybe 64
	                DWORD unk;
                } KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP
             */

            int numberOfAttributes = attributeMapLen / 12;
            
            Dictionary<int, int> attributeMap = new Dictionary<int, int>();

            for (int i = 0; i < numberOfAttributes; ++i)
            {
                int attributeNum = BitConverter.ToInt32(vaultBytes, offset);
                offset += 4;
                int attributeOffset = BitConverter.ToInt32(vaultBytes, offset);
                offset += 8; // skip unk

                attributeMap.Add(attributeNum, attributeOffset);
            }

            byte[] leftover = new byte[vaultBytes.Length - 222];
            Array.Copy(vaultBytes, 222, leftover, 0, leftover.Length);

            foreach (KeyValuePair<int, int> attribute in attributeMap)
            {
                // from https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L12-L22
                /*
                    typedef struct _KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE {
	                    DWORD id;
	                    DWORD unk0; // maybe flags
	                    DWORD unk1; // maybe type
	                    DWORD unk2; // 0a 00 00 00
	                    //DWORD unkComplex; // only in complex (and 0, avoid it ?)
	                    DWORD szData; // when parsing, inc bullshit... clean in structure
	                    PBYTE data;
	                    DWORD szIV;
	                    PBYTE IV;
                    } KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE, *PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE;
                */

                // initial offset
                int attributeOffset = attribute.Value;

                // skip cruft
                attributeOffset += 16;

                if(attribute.Key >= 100)
                {
                    attributeOffset += 4; // id100 https://github.com/SecureAuthCorp/impacket/blob/13a65706273680c297caee0211460ef7369aa8ca/impacket/dpapi.py#L551-L552
                }

                int dataLen = BitConverter.ToInt32(vaultBytes, attributeOffset);
                attributeOffset += 4;

                finalAttributeOffset = attributeOffset;

                if (dataLen > 0)
                {
                    bool IVPresent = BitConverter.ToBoolean(vaultBytes, attributeOffset);
                    attributeOffset += 1;

                    if (!IVPresent)
                    {
                        // we don't really care about these... do we?
                        byte[] dataBytes = new byte[dataLen - 1];

                        // use aes128, no IV
                        Array.Copy(vaultBytes, attributeOffset, dataBytes, 0, dataLen - 1);

                        finalAttributeOffset = attributeOffset + dataLen - 1;

                        byte[] decBytes = Crypto.AESDecrypt(aes128key, new byte[0], dataBytes);
                    }
                    else
                    {
                        // use aes256 w/ IV

                        int IVLen = BitConverter.ToInt32(vaultBytes, attributeOffset);
                        attributeOffset += 4;

                        byte[] IVBytes = new byte[IVLen];
                        Array.Copy(vaultBytes, attributeOffset, IVBytes, 0, IVLen);
                        attributeOffset += IVLen;

                        byte[] dataBytes = new byte[dataLen - 1 - 4 - IVLen];
                        Array.Copy(vaultBytes, attributeOffset, dataBytes, 0, dataLen - 1 - 4 - IVLen);
                        attributeOffset += dataLen - 1 - 4 - IVLen;
                        finalAttributeOffset = attributeOffset;

                        byte[] decBytes = Crypto.AESDecrypt(aes256key, IVBytes, dataBytes);

                        DescribeVaultItem(decBytes);
                    }
                }
            }

            if ( (numberOfAttributes > 0) && (unk0 < 4) )
            {
                // bullshit vault credential clear attributes...

                int clearOffset = finalAttributeOffset - 2;
                byte[] clearBytes = new byte[vaultBytes.Length - clearOffset];
                Array.Copy(vaultBytes, clearOffset, clearBytes, 0, clearBytes.Length);

                int cleatOffSet2 = 0;
                cleatOffSet2 += 4; // skip ID

                int dataLen = BitConverter.ToInt32(clearBytes, cleatOffSet2);
                cleatOffSet2 += 4;

                if (dataLen > 2000) {
                    Console.WriteLine("    [*] Vault credential clear attribute is > 2000 bytes, skipping...");
                }

                else if (dataLen > 0)
                {
                    bool IVPresent = BitConverter.ToBoolean(vaultBytes, cleatOffSet2);
                    cleatOffSet2 += 1;

                    if (!IVPresent)
                    {
                        // we don't really care about these... do we?
                        byte[] dataBytes = new byte[dataLen - 1];

                        // use aes128, no IV
                        Array.Copy(clearBytes, cleatOffSet2, dataBytes, 0, dataLen - 1);

                        byte[] decBytes = Crypto.AESDecrypt(aes128key, new byte[0], dataBytes);
                    }
                    else
                    {
                        // use aes256 w/ IV
                        int IVLen = BitConverter.ToInt32(clearBytes, cleatOffSet2);
                        cleatOffSet2 += 4;

                        byte[] IVBytes = new byte[IVLen];
                        Array.Copy(clearBytes, cleatOffSet2, IVBytes, 0, IVLen);
                        cleatOffSet2 += IVLen;

                        byte[] dataBytes = new byte[dataLen - 1 - 4 - IVLen];
                        Array.Copy(clearBytes, cleatOffSet2, dataBytes, 0, dataLen - 1 - 4 - IVLen);
                        cleatOffSet2 += dataLen - 1 - 4 - IVLen;
                        finalAttributeOffset = cleatOffSet2;

                        byte[] decBytes = Crypto.AESDecrypt(aes256key, IVBytes, dataBytes);

                        DescribeVaultItem(decBytes);
                    }
                }
            }
        }

        public static void DescribeVaultItem(byte[] vaultItemBytes)
        {
            // describes/parses a single vault item

            // https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L156-L167

            /*
                typedef struct _KULL_M_CRED_VAULT_CLEAR_ENTRY {
	                DWORD id;
	                DWORD size;
	                BYTE data[ANYSIZE_ARRAY];
                } KULL_M_CRED_VAULT_CLEAR_ENTRY, *PKULL_M_CRED_VAULT_CLEAR_ENTRY;

                typedef struct _KULL_M_CRED_VAULT_CLEAR {
	                DWORD version;
	                DWORD count;
	                DWORD unk;
	                PKULL_M_CRED_VAULT_CLEAR_ENTRY *entries;
                } KULL_M_CRED_VAULT_CLEAR, *PKULL_M_CRED_VAULT_CLEAR;
             */

            int offset = 0;

            int version = BitConverter.ToInt32(vaultItemBytes, offset);
            offset += 4;

            int count = BitConverter.ToInt32(vaultItemBytes, offset);
            offset += 4;

            // skip unk
            offset += 4;

            for(int i = 0; i < count; ++i)
            {
                int id = BitConverter.ToInt32(vaultItemBytes, offset);
                offset += 4;

                int size = BitConverter.ToInt32(vaultItemBytes, offset);
                offset += 4;

                string entryString = Encoding.Unicode.GetString(vaultItemBytes, offset, size);

                byte[] entryData = new byte[size];
                Array.Copy(vaultItemBytes, offset, entryData, 0, size);

                offset += size;

                switch (id)
                {
                    case 1:
                        Console.WriteLine("    Resource         : {0}", entryString);
                        break;
                    case 2:
                        Console.WriteLine("    Identity         : {0}", entryString);
                        break;
                    case 3:
                        Console.WriteLine("    Authenticator    : {0}", entryString);
                        break;
                    default:
                        string entryDataString = BitConverter.ToString(entryData).Replace("-", " ");
                        //Console.WriteLine("    Property         : {0}", entryDataString);
                        break;
                }
            }
        }

        public static void DescribeCredential(byte[] credentialBytes, Dictionary<string, string> MasterKeys)
        {
            // try to decrypt the credential blob, displaying if successful
            byte[] plaintextBytes = DescribeDPAPIBlob(credentialBytes, MasterKeys, "credential");
            if (plaintextBytes.Length > 0)
            {
                ParseDecCredBlob(plaintextBytes);
            }
        }

        public static void ParseDecCredBlob(byte[] decBlobBytes)
        {
            // parse/display a decrypted credential blob

            int offset = 0;

            UInt32 credFlags = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 credSize = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 credUnk0 = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 type = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 flags = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;

            long lastWritten = (long)BitConverter.ToInt64(decBlobBytes, offset);
            offset += 8;
            System.DateTime lastWrittenTime = System.DateTime.FromFileTime(lastWritten);
            Console.WriteLine("    LastWritten      : {0}", lastWrittenTime);

            UInt32 unkFlagsOrSize = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 persist = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 attributeCount = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 unk0 = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 unk1 = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;

            Int32 targetNameLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            string targetName = Encoding.Unicode.GetString(decBlobBytes, offset, targetNameLen);
            offset += targetNameLen;
            Console.WriteLine("    TargetName       : {0}", targetName);

            Int32 targetAliasLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            string targetAlias = Encoding.Unicode.GetString(decBlobBytes, offset, targetAliasLen);
            offset += targetAliasLen;
            Console.WriteLine("    TargetAlias      : {0}", targetAlias);

            Int32 commentLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            string comment = Encoding.Unicode.GetString(decBlobBytes, offset, commentLen);
            offset += commentLen;
            Console.WriteLine("    Comment          : {0}", comment);

            Int32 unkDataLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            string unkData = Encoding.Unicode.GetString(decBlobBytes, offset, unkDataLen);
            offset += unkDataLen;

            Int32 userNameLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            string userName = Encoding.Unicode.GetString(decBlobBytes, offset, userNameLen);
            offset += userNameLen;
            Console.WriteLine("    UserName         : {0}", userName);

            Int32 credBlobLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            string credBlob = Encoding.Unicode.GetString(decBlobBytes, offset, credBlobLen);
            offset += credBlobLen;
            Console.WriteLine("    Credential       : {0}", credBlob);
        }

        public static ArrayList ParseDecPolicyBlob(byte[] decBlobBytes)
        {
            // parse a decrypted policy blob, returning an arraylist of the AES 128/256 keys

            ArrayList keys = new ArrayList();
            string s = Encoding.ASCII.GetString(decBlobBytes, 12, 4);

            if (s.Equals("KDBM"))
            {
                // https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L211-L227
                /*
                24 00 00 00
	                01 00 00 00
	                02 00 00 00
	                4b 44 42 4d KDBM 'MBDK'
	                01 00 00 00
	                10 00 00 00
		                xx xx xx (16)
                34 00 00 00
	                01 00 00 00
	                01 00 00 00
	                4b 44 42 4d KDBM 'MBDK'
	                01 00 00 00
	                20 00 00 00
		                xx xx xx (32)
                */

                int offset = 20;

                int aes128len = BitConverter.ToInt32(decBlobBytes, offset);
                offset += 4;

                if(aes128len != 16)
                {
                    Console.WriteLine("    [X] Error parsing decrypted Policy.vpol (aes128len != 16)");
                    return keys;
                }

                byte[] aes128Key = new byte[aes128len];
                Array.Copy(decBlobBytes, offset, aes128Key, 0, aes128len);
                offset += aes128len;
                string aes128KeyStr = BitConverter.ToString(aes128Key).Replace("-", "");

                // skip more header stuff
                offset += 20;

                int aes256len = BitConverter.ToInt32(decBlobBytes, offset);
                offset += 4;

                if (aes256len != 32)
                {
                    Console.WriteLine("    [X] Error parsing decrypted Policy.vpol (aes256len != 32)");
                    return keys;
                }

                byte[] aes256Key = new byte[aes256len];
                Array.Copy(decBlobBytes, offset, aes256Key, 0, aes256len);
                string aes256KeyStr = BitConverter.ToString(aes256Key).Replace("-", "");

                keys.Add(aes128Key);
                keys.Add(aes256Key);
            }
            else
            {
                int offset = 16;
                string s2 = Encoding.ASCII.GetString(decBlobBytes, offset, 4);
                offset += 4;

                if (s2.Equals("KSSM"))
                {
                    // thank you @gentilkiwi :pray:
                    // https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L238-L279
                    /*
                    38 02 00 00
	                    01 00 00 00
	                    02 00 00 00
	                    30 02 00 00
		                    4b 53 53 4d KSSM	'MSSK'
		                    02 00 01 00
		                    01 00 00 00
		                    10 00 00 00
		                    80 00 00 00 (128)
		
		                    10 00 00 00
			                    xx xx xx (16)
		                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
		                    xx xx xx (16)
		                    yy yy yy (..)
		                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
		                    a0 00 00 00
		                    40 01 00 00
		                    00 00 00 00 00 00 00 00 00 00 00 00
		                    00 00 00 00 00 00 00 00 00 00 00 00
                    38 02 00 00
	                    01 00 00 00
	                    01 00 00 00
	                    30 02 00 00
		                    4b 53 53 4d KSSM	'MSSK'
		                    02 00 01 00
		                    01 00 00 00
		                    10 00 00 00
		                    00 01 00 00 (256)
		                    20 00 00 00 (32)
			                    xx xx xx (32)
		                    00 00 00 00
		                    xx xx xx (32)
		                    yy yy yy (..)
		                    e0 00 00 00
		                    c0 01 00 00
		                    00 00 00 00 00 00 00 00 00 00 00 00
		                    00 00 00 00 00 00 00 00 00 00 00 00
                    */

                    // skip
                    offset += 16;

                    int aes128len = BitConverter.ToInt32(decBlobBytes, offset);
                    offset += 4;

                    if (aes128len != 16)
                    {
                        Console.WriteLine("    [X] Error parsing decrypted Policy.vpol (aes128len != 16)");
                        return keys;
                    }

                    byte[] aes128Key = new byte[aes128len];
                    Array.Copy(decBlobBytes, offset, aes128Key, 0, aes128len);
                    offset += aes128len;
                    string aes128KeyStr = BitConverter.ToString(aes128Key).Replace("-", "");

                    // search for the next 'MSSK' header
                    byte[] pattern = new byte[12] { 0x4b, 0x53, 0x53, 0x4d, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
                    int index = Helpers.ArrayIndexOf(decBlobBytes, pattern, offset);

                    if (index != -1)
                    {
                        offset = index;
                        offset += 20;

                        int aes256len = BitConverter.ToInt32(decBlobBytes, offset);
                        offset += 4;

                        if (aes256len != 32)
                        {
                            Console.WriteLine("    [X] Error parsing decrypted Policy.vpol (aes256len != 32)");
                            return keys;
                        }

                        byte[] aes256Key = new byte[aes256len];
                        Array.Copy(decBlobBytes, offset, aes256Key, 0, aes256len);
                        string aes256KeyStr = BitConverter.ToString(aes256Key).Replace("-", "");

                        keys.Add(aes128Key);
                        keys.Add(aes256Key);
                    }
                    else
                    {
                        Console.WriteLine("[X] Error in decrypting Policy.vpol: second MSSK header not found!");
                    }
                }
            }

            return keys;
        }

        public static byte[] GetDomainKey(byte[] masterKeyBytes)
        {
            // helper to extract domain key bytes from a master key blob

            int offset = 96;

            long masterKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 8;
            long backupKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 8;
            long credHistLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 8;
            long domainKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 8;

            offset += (int)(masterKeyLen + backupKeyLen + credHistLen);

            byte[] domainKeyBytes = new byte[domainKeyLen];
            Array.Copy(masterKeyBytes, offset, domainKeyBytes, 0, domainKeyLen);

            return domainKeyBytes;
        }

        public static byte[] GetMasterKey(byte[] masterKeyBytes)
        {
            // helper to extract domain masterkey subbytes from a master key blob

            int offset = 96;

            long masterKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 4 * 8; // skip the key length headers
            
            byte[] masterKeySubBytes = new byte[masterKeyLen];
            Array.Copy(masterKeyBytes, offset, masterKeySubBytes, 0, masterKeyLen);

            return masterKeySubBytes;
        }

        public static Dictionary<string, string> DecryptMasterKey(byte[] masterKeyBytes, byte[] backupKeyBytes)
        {
            // takes masterkey bytes and backup key bytes, returns a dictionary of guid:sha1 masterkey mappings

            Dictionary<string, string> mapping = new Dictionary<string, string>();
            try
            {
                string guidMasterKey = String.Format("{{{0}}}", Encoding.Unicode.GetString(masterKeyBytes, 12, 72));

                int offset = 4;

                byte[] domainKeyBytes = GetDomainKey(masterKeyBytes);

                int secretLen = BitConverter.ToInt32(domainKeyBytes, offset);
                offset += 4;

                int accesscheckLen = BitConverter.ToInt32(domainKeyBytes, offset);
                offset += 4;

                // the guid
                offset += 16;

                byte[] secretBytes = new byte[secretLen];
                Array.Copy(domainKeyBytes, offset, secretBytes, 0, secretLen);
                offset += secretLen;

                byte[] accesscheckBytes = new byte[accesscheckLen];
                Array.Copy(domainKeyBytes, offset, accesscheckBytes, 0, accesscheckLen);

                // extract out the RSA private key
                byte[] rsaPriv = new byte[backupKeyBytes.Length - 24];
                Array.Copy(backupKeyBytes, 24, rsaPriv, 0, rsaPriv.Length);

                string a = BitConverter.ToString(rsaPriv).Replace("-", "");

                string sec = BitConverter.ToString(secretBytes).Replace("-", "");

                byte[] domainKeyBytesDec = Crypto.RSADecrypt(rsaPriv, secretBytes);

                int masteyKeyLen = BitConverter.ToInt32(domainKeyBytesDec, 0);
                int suppKeyLen = BitConverter.ToInt32(domainKeyBytesDec, 4);

                byte[] masterKey = new byte[masteyKeyLen];
                Buffer.BlockCopy(domainKeyBytesDec, 8, masterKey, 0, masteyKeyLen);

                SHA1Managed sha1 = new SHA1Managed();
                byte[] masterKeySha1 = sha1.ComputeHash(masterKey);
                string masterKeySha1Hex = BitConverter.ToString(masterKeySha1).Replace("-", "");

                mapping.Add(guidMasterKey, masterKeySha1Hex);
            }
            catch { }
            return mapping;
        }

        public static Dictionary<string, string> DecryptMasterKeyWithSha(byte[] masterKeyBytes, byte[] shaBytes)
        {
            // takes masterkey bytes and SYSTEM_DPAPI masterkey sha bytes, returns a dictionary of guid:sha1 masterkey mappings
            Dictionary<string, string> mapping = new Dictionary<string, string>();
            try
            {
                string guidMasterKey = String.Format("{{{0}}}", Encoding.Unicode.GetString(masterKeyBytes, 12, 72));
                byte[] mkBytes = GetMasterKey(masterKeyBytes);

                int offset = 4;
                byte[] salt = new byte[16];
                Array.Copy(mkBytes, 4, salt, 0, 16);
                offset += 16;

                int rounds = BitConverter.ToInt32(mkBytes, offset);
                offset += 4;

                int algHash = BitConverter.ToInt32(mkBytes, offset);
                offset += 4;

                int algCrypt = BitConverter.ToInt32(mkBytes, offset);
                offset += 4;

                byte[] encData = new byte[mkBytes.Length - offset];
                Array.Copy(mkBytes, offset, encData, 0, encData.Length);

                byte[] final = new byte[48];

                // CALG_SHA_512 == 32782
                if (algHash == 32782)
                {
                    // derive the "Pbkdf2/SHA512" key for the masterkey, using MS' silliness
                    using (var hmac = new HMACSHA512())
                    {
                        var df = new Pbkdf2(hmac, shaBytes, salt, rounds);
                        final = df.GetBytes(48);
                    }
                }
                else
                {
                    Console.WriteLine("[X] Note: alg hash  '{0} / 0x{1}' not currently supported!", algHash, algHash.ToString("X8"));
                    return mapping;
                }

                // TODO: support more than just CALG_AES_256 and CALG_SHA_512 !

                // CALG_AES_256 == 26128 , CALG_SHA_512 == 32782
                if ((algCrypt == 26128) && (algHash == 32782))
                {
                    int HMACLen = (new HMACSHA512()).HashSize / 8;
                    AesManaged aesCryptoProvider = new AesManaged();

                    byte[] ivBytes = new byte[16];
                    Array.Copy(final, 32, ivBytes, 0, 16);

                    byte[] key = new byte[32];
                    Array.Copy(final, 0, key, 0, 32);

                    aesCryptoProvider.Key = key;
                    aesCryptoProvider.IV = ivBytes;
                    aesCryptoProvider.Mode = CipherMode.CBC;
                    aesCryptoProvider.Padding = PaddingMode.Zeros;

                    // decrypt the encrypted data using the Pbkdf2-derived key
                    byte[] plaintextBytes = aesCryptoProvider.CreateDecryptor().TransformFinalBlock(encData, 0, encData.Length);

                    int outLen = plaintextBytes.Length;
                    int outputLen = outLen - 16 - HMACLen;
                    
                    byte[] masterKeyFull = new byte[HMACLen];

                    // outLen - outputLen == 80 in this case
                    Array.Copy(plaintextBytes, outLen - outputLen, masterKeyFull, 0, masterKeyFull.Length);

                    using (SHA1Managed sha1 = new SHA1Managed())
                    {
                        byte[] masterKeySha1 = sha1.ComputeHash(masterKeyFull);
                        string masterKeySha1Hex = BitConverter.ToString(masterKeySha1).Replace("-", "");
                        
                        // CALG_SHA_512 == 32782
                        if (algHash == 32782)
                        {
                            // we're HMAC'ing the first 16 bytes of the decrypted buffer with the shaBytes as the key
                            byte[] plaintextCryptBuffer = new byte[16];
                            Array.Copy(plaintextBytes, plaintextCryptBuffer, 16);
                            HMACSHA512 hmac1 = new HMACSHA512(shaBytes);
                            byte[] round1Hmac = hmac1.ComputeHash(plaintextCryptBuffer);

                            // round 2
                            byte[] round2buffer = new byte[outputLen];
                            Array.Copy(plaintextBytes, outLen - outputLen, round2buffer, 0, outputLen);
                            HMACSHA512 hmac2 = new HMACSHA512(round1Hmac);
                            byte[] round2Hmac = hmac2.ComputeHash(round2buffer);

                            // compare the second HMAC value to the original plaintextBytes, starting at index 16
                            byte[] comparison = new byte[64];
                            Array.Copy(plaintextBytes, 16, comparison, 0, comparison.Length);
                            string s1 = BitConverter.ToString(comparison).Replace("-", "");
                            string s2 = BitConverter.ToString(round2Hmac).Replace("-", "");

                            if (s1.Equals(s2))
                            {
                                mapping.Add(guidMasterKey, masterKeySha1Hex);
                            }
                            else
                            {
                                Console.WriteLine("[X] {0}:{1} - HMAC integrity check failed!", guidMasterKey, masterKeySha1Hex);
                                return mapping;
                            }
                        }
                        else
                        {
                            Console.WriteLine("[X] Note: alg hash  '{0} / 0x{1}' not currently supported!", algHash, algHash.ToString("X8"));
                            return mapping;
                        }
                    }
                }
                else
                {
                    Console.WriteLine("[X] Note: alg crypt '{0} / 0x{1}' not currently supported!", algCrypt, algCrypt.ToString("X8"));
                    return mapping;
                }
            }
            catch { }
            return mapping;
        }
    }
}