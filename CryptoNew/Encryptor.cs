using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security;
using System.IO;
using static Crypto.Constants;
using static Crypto.CryptoHelpers;

namespace Crypto
{
    class Encryptor
    {
        SymmetricAlgorithm algorithm;
        HashAlgorithm passwordHashAlgorithm;
        EncryptedFileInfo[] filesToEncrypt;
        FileStream fileContainer;
        SecureString password;

        byte[] salt;

        public Encryptor
            (SecureString password, 
            SymmetricAlgorithm encryptionAlgorithm, 
            HashAlgorithm passwordHashAlgorithm,
            string[] filesToEncrypt,
            string encryptedFileContainerName)
        {
            this.password = password;
            this.algorithm = encryptionAlgorithm;
            this.passwordHashAlgorithm = passwordHashAlgorithm;
            this.filesToEncrypt = EncryptedFileInfo.FromFileNameArray(filesToEncrypt);
            this.fileContainer = new FileStream(encryptedFileContainerName, FileMode.Create);
        }

        public void Encrypt()
        {
            //1.
            // įrašom headerį su užšifruotais confirmation baitais
            salt = GenerateRandomBytes(SALT_SIZE);
            algorithm.Key = DeriveKey(salt, password, algorithm, passwordHashAlgorithm.ComputeHash);
            byte[] header = MakeHeader();
            fileContainer.Write(header, 0, header.Length);
            //2.
            // užšifruojam xml metadata
            string xmlFileInfo = EncryptedFileInfo.SerializeFiles(filesToEncrypt);
            EncryptXmlDataString(xmlFileInfo);
            //3.
            // užšifruojam kiekvieną failą
            EncryptFiles();
        }

        private byte[] MakeHeader()
        {
            List<byte> header = new List<byte>(HEADER_SIZE);
            // pagaminam IV headeriui užšifruot
            algorithm.IV = GenerateRandomBytes(algorithm.BlockSize / 8);

            // sudedam viską į vieną listą iš eilės: salt[32], iv[block size / 8], encrypted confirmation bytes
            header.AddRange(salt);
            header.AddRange(algorithm.IV);
            var encryptedConfirmBytes = EncryptConfirmationBytes(algorithm.IV);
            header.AddRange(encryptedConfirmBytes);

            //padinam headerį, kad būtų 512 baitų ilgio
            Random random = new Random(); // TODO: gal pakeist random kažkuo stipresniu
            while (header.Count < HEADER_SIZE)
            {
                header.Add((byte)random.Next());
            }
            return header.ToArray();
        }

        private IEnumerable<byte> EncryptConfirmationBytes(byte[] IV)
        {
            using (MemoryStream memStream = new MemoryStream(64))
            using (CryptoStream cryptStream = new CryptoStream
                (memStream, algorithm.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cryptStream.Write(passConfirmationBytes, 0, passConfirmationBytes.Length);
                cryptStream.FlushFinalBlock(); //svarbu!
                return memStream.GetBuffer().Take((int)memStream.Length);
            }
        }

        void EncryptXmlDataString(string xml)
        {
            // pridedam END_OF_DATA_MARK 
            StringBuilder xmlFileInfo = new StringBuilder(xml);
            xmlFileInfo.Append(END_OF_DATA_MARK);
            byte[] data = GlobalCryptEncoding.GetBytes(xmlFileInfo.ToString()).ToArray();
            MemoryStream dataStream = new MemoryStream(data);

            // įrašom IV priekyje
            algorithm.IV = GenerateRandomBytes(algorithm.BlockSize / 8);
            fileContainer.Write(algorithm.IV, 0, algorithm.IV.Length);

            CryptoStream cryptStream =
                        new CryptoStream(fileContainer, algorithm.CreateEncryptor(),
                        CryptoStreamMode.Write);

            int readByte;
            try
            {
                while ((readByte = dataStream.ReadByte()) != -1)
                {
                    cryptStream.WriteByte((byte)readByte);
                }
            }
            finally
            {
                // įrašom paddingą (pad last block)
                cryptStream.FlushFinalBlock(); //svarbu!
            }
        }

        void EncryptFiles()
        {
            foreach (var file in filesToEncrypt)
            {
                algorithm.IV = GenerateRandomBytes(algorithm.BlockSize / 8);
                fileContainer.Write(algorithm.IV, 0, algorithm.IV.Length);
                CryptoStream cryptStream = new CryptoStream
                    (fileContainer, algorithm.CreateEncryptor(), CryptoStreamMode.Write);
                using (FileStream currentFileStream = new FileStream(file.FullName, FileMode.Open))
                {
                    int readByte = 0;
                    while ((readByte = currentFileStream.ReadByte()) != -1)
                    {
                        cryptStream.WriteByte((byte)readByte);
                    }
                    // įrašom paddingą (pad last block)
                    cryptStream.FlushFinalBlock(); //svarbu!
                }
            }
        }
    }
}
