using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using static Crypto.Constants;
using static Crypto.CryptoHelpers;
using static Crypto.CryptoAlgorithms;
using static Crypto.Unit;

namespace Crypto
{
    class Decryptor
    {
        SymmetricAlgorithm algorithm;
        HashAlgorithm hashAlgorithm;
        SecureString password;
        FileStream encryptedFileContainer;

        EncryptedFileInfo[] encryptedFilesInfo;

        byte[] header;

        public Decryptor(SecureString password, string encryptedFileContainerName)
        {
            this.password = password;
            this.encryptedFileContainer = 
                new FileStream(encryptedFileContainerName, FileMode.Open, FileAccess.ReadWrite
                , FileShare.Read, BUFFER_SIZE);
        }

        public Result<DecryptionSuccess, DecryptionFailure> Decrypt()
        {
            return ReadHeader().Match(
                s => Decrypt(SymmetricAlgorithms).Bind(TryToDecryptXmlMetaData)
                    .Bind(DisplayEncryptedFileInfoAndDecrypt),

                e => Result<DecryptionSuccess, DecryptionFailure>.Error(e)
            );
        }
        
        Result<DecryptionSuccess, DecryptionFailure> Decrypt(Type[] algorithms)
        {
            if (algorithms == Array.Empty<Type>())
            {
                return Result<DecryptionSuccess, DecryptionFailure>.Error
                    (new DecryptionFailure("Failed to decrypt header, password might be invalid," +
                    " corrupted file container, or not an encrypted file container",
                    DecryptionFailure.Error.FailedToDecryptHeader));
            }

            var (nextAlgorithm, tail) = HeadAndTail(algorithms);
            return Decrypt(nextAlgorithm, HashAlgorithms).Match(
                s => Result<DecryptionSuccess, DecryptionFailure>.Success(s),
                e => Decrypt(tail)
            );
        }

        Result<DecryptionSuccess, DecryptionFailure> Decrypt(Type algorithm, Type[] hashes)
        {
            if (hashes == Array.Empty<Type>())
            {
                return Result<DecryptionSuccess, DecryptionFailure>.Error
                    (new DecryptionFailure("Failed to decrypt header, password might be invalid," +
                    " corrupted file container, or not a encrypted file container",
                    DecryptionFailure.Error.FailedToDecryptHeader));
            }
            var (nextHash, tail) = HeadAndTail(hashes);

            this.algorithm = (SymmetricAlgorithm)Activator.CreateInstance(algorithm);
            this.hashAlgorithm = (HashAlgorithm)Activator.CreateInstance(nextHash);
            return TryDecryptHeaderAndConfirmKey().Match(
                s => Result<DecryptionSuccess, DecryptionFailure>.Success(s),
                e => Decrypt(algorithm, tail)
            );
        }

        Result<DecryptionSuccess, DecryptionFailure> ReadHeader()
        {
            if(encryptedFileContainer.Length < HEADER_SIZE)
            {
                return Result<DecryptionSuccess, DecryptionFailure>.Error
                    (new DecryptionFailure("Failed to read header: file size is too small " +
                    "to be a file container", DecryptionFailure.Error.FailedToReadHeader));
            }
            this.header = new byte[HEADER_SIZE];
            try
            {
                encryptedFileContainer.Read(this.header, 0, HEADER_SIZE);
            }
            catch(Exception ex)
            {
                return Result<DecryptionSuccess, DecryptionFailure>.Error
                    (new DecryptionFailure("Failed to read header: " + ex, 
                    DecryptionFailure.Error.FailedToReadHeader));
            }
            return Result<DecryptionSuccess, DecryptionFailure>.Success(DecryptionSuccess.ReadHeader);
        }

        Result<DecryptionSuccess, DecryptionFailure> TryDecryptHeaderAndConfirmKey()
        {
            byte[] salt = this.header.Take(SALT_SIZE).ToArray();
            algorithm.IV = this.header.Skip(SALT_SIZE).Take(algorithm.BlockSize / 8).ToArray();
            algorithm.Key = DeriveKey
                (salt, password, algorithm, hashAlgorithm.ComputeHash);

            int blockPlusSalt = (algorithm.BlockSize / 8) + SALT_SIZE;
            byte[] otherBytes = this.header.Skip
                (blockPlusSalt).Take(this.header.Length - blockPlusSalt).ToArray();

            return TryDecryptConfirmationBytes(otherBytes);
        }
        
        Result<DecryptionSuccess, DecryptionFailure> TryDecryptConfirmationBytes(byte[] encryptedConfirmationBlock)
        {
            try
            {
                using (MemoryStream memStream = new MemoryStream(encryptedConfirmationBlock))
                using (CryptoStream cryptStream = new CryptoStream
                    (memStream, algorithm.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    byte[] arr = new byte[CONFIRMATION_BYTES_SIZE]; 
                    cryptStream.Read(arr, 0, CONFIRMATION_BYTES_SIZE);

                    //TODO: gal reikia patvirtinimo, kad confirmation bytes yra teisingi?
                    return Result<DecryptionSuccess, DecryptionFailure>.Success
                        (DecryptionSuccess.ConfirmedKey);
                }
            }
            catch
            {
                return Result<DecryptionSuccess, DecryptionFailure>.Error
                    (new DecryptionFailure("Failed to decrypt header!", 
                    DecryptionFailure.Error.FailedToDecryptHeader));
            }
        }

        Result<DecryptionSuccess, DecryptionFailure> TryToDecryptXmlMetaData
            (DecryptionSuccess previousResult)
        {
            //(!)   jeigu bandom skaityti iš karto į algorithm.IV buferį
            //   (encryptedFileContainer.Read(algorithm.IV, 0...), 
            //   tai tada feilina nors ir labai keistai: 
            //   pirmi keli baitai būna neteisingai nuskaitomi, o visi kiti - teisingai.
            //   todėl reikia į atskirą bufferį nuskaityt, ir tik tada prilygint algorithm.IV

            byte[] IV = new byte[algorithm.BlockSize / 8];
            int length = encryptedFileContainer.Read(IV, 0, IV.Length);
            algorithm.IV = IV;

            CryptoStream cryptStream =
                        new CryptoStream(encryptedFileContainer, algorithm.CreateDecryptor(),
                        CryptoStreamMode.Read);

            List<byte> readBytesList = new List<byte>();
            int readByte = 0;
            int lastMarkChar = END_OF_DATA_MARK.Last();
            int maxEncodingByteCount = GlobalCryptEncoding.GetMaxByteCount(1);
            bool scannedMarkLastChar = false;
            int encodingCounter = 0;

            try
            {
                //nuskaitom baitą, įdedam į nuskaitytų sąrašą ir tik tada tikrinam ar turi END_OF_DATA_MARK
                readByte = cryptStream.ReadByte();
                while (!IsEnd())
                {
                    readBytesList.Add((byte)readByte);
                    // encoding stuff
                    if (readByte == lastMarkChar)
                    {
                        scannedMarkLastChar = true;
                        encodingCounter = maxEncodingByteCount;
                    }
                    //\encoding stuff

                    readByte = cryptStream.ReadByte();
                }
                cryptStream.Flush();
                string xmlString = GlobalCryptEncoding.GetString(readBytesList.ToArray());
                encryptedFilesInfo = EncryptedFileInfo.DeserializeXML(xmlString.Replace(END_OF_DATA_MARK, ""));
                
                // grįžtam bloku atgal, nes cryptostreamas feilina :)
                encryptedFileContainer.Seek(-(algorithm.BlockSize / 8), SeekOrigin.Current);

                return Result<DecryptionSuccess, DecryptionFailure>.Success
                    (DecryptionSuccess.DecryptedMetadata);
            }
            catch (Exception ex)
            {
                return Result<DecryptionSuccess, DecryptionFailure>.Error
                    (new DecryptionFailure("Xml metadata decryption failed: " + ex,
                    DecryptionFailure.Error.FailedToDecryptMetadata));
            }

            bool ContainsMark()
            {
                //Console.WriteLine("ContainsMark"); //test
                return GlobalCryptEncoding.GetString(readBytesList.ToArray()).Contains(END_OF_DATA_MARK);
            }

            bool IsEnd()
            {
                if (scannedMarkLastChar && ContainsMark())
                {
                    return true;
                }
                else
                {
                    encodingCounter--;
                    if (encodingCounter == 0)
                        scannedMarkLastChar = false;

                    return false;
                }
            }
        }

        Result<DecryptionSuccess, DecryptionFailure> 
            DisplayEncryptedFileInfoAndDecrypt (DecryptionSuccess previousResult)
        {
            Console.WriteLine("Encrypted Files:");
            for (int i = 0; i < encryptedFilesInfo.Length; i++)
            {
                Console.WriteLine($"{i}: {encryptedFilesInfo[i].FileName}");
            }
            Console.Write("Please type indexes of those files you want to decrypt: ");
            string input = Console.ReadLine();
            var filesToDecryptIndexes = ParseInput(input, encryptedFilesInfo.Length - 1);
            return filesToDecryptIndexes.Match(
                s =>
                {
                    Console.Write(s.message);
                    return DecryptFiles(s.indexes);
                },
                e => Result<DecryptionSuccess, DecryptionFailure>.Error
                (new DecryptionFailure("Input is invalid", DecryptionFailure.Error.InputIsInvalid))
            );
        }

        Result<DecryptionSuccess, DecryptionFailure> DecryptFiles(int[] filesToDecryptIndexes)
        {
            Console.WriteLine("Decrypting these files: ");
            foreach (int i in filesToDecryptIndexes)
            {
                Console.WriteLine(encryptedFilesInfo[i].FileName);
            }
            
            // decryptinam i-tąjį failą
            long encryptedFilesStart = encryptedFileContainer.Position;
            foreach (int i in filesToDecryptIndexes)
            {
                // nusistatom i-tojo failo offsetą ir nueinam į to failo pradžią
                long fileOffset = 0;
                for (int j = 0; j < i; j++)
                {
                    fileOffset += CalculateCryptedLength(encryptedFilesInfo[j].FileSize, algorithm, true)
                        + algorithm.BlockSize / 8; // IV ilgis
                }
                encryptedFileContainer.Seek(fileOffset, SeekOrigin.Current);
                try
                {
                    // read IV
                    byte[] IV = new byte[algorithm.BlockSize / 8];
                    encryptedFileContainer.Read(IV, 0, IV.Length);
                    algorithm.IV = IV;

                    CryptoStream cryptoStream =
                        new CryptoStream(encryptedFileContainer, algorithm.CreateDecryptor(),
                        CryptoStreamMode.Read);

                    // atšifruojam i-tąjį failą
                    using (FileStream decryptedFile = new FileStream
                        (encryptedFilesInfo[i].FileName + ".test", FileMode.Create/*New*/,
                        FileAccess.ReadWrite, FileShare.None, BUFFER_SIZE))
                    {
                        long encryptedFileSize = CalculateCryptedLength
                            (encryptedFilesInfo[i].FileSize, this.algorithm, true);

                        //read by block (daug greičiau, negu po baitą)
                        byte[] buffer = new byte[BUFFER_SIZE];
                        while (encryptedFileSize > 0)
                        {
                            int readBlockResult = cryptoStream.Read(buffer, 0, BUFFER_SIZE);
                            decryptedFile.Write(buffer, 0, BUFFER_SIZE);
                            encryptedFileSize -= BUFFER_SIZE;
                        }
                        decryptedFile.SetLength(encryptedFilesInfo[i].FileSize);
                    }
                }
                catch(Exception ex)
                {
                    return Result<DecryptionSuccess, DecryptionFailure>.Error
                        (new DecryptionFailure($"Failed to decrypt file " +
                        $"{encryptedFilesInfo[i].FileName}: {ex}",
                        DecryptionFailure.Error.FailedToDecryptFiles));
                }
                finally
                {
                    encryptedFileContainer.Seek(encryptedFilesStart, SeekOrigin.Begin);
                }
            }

            return Result<DecryptionSuccess, DecryptionFailure>.Success(DecryptionSuccess.DecryptedFiles);
        }

        static Result<(int[] indexes, string message), string> ParseInput(string input, int max)
        {
            StringBuilder sb = new StringBuilder();
            string[] split = input.Split(' ');
            int[] filtered =
                split.Where(s =>
                {
                    if (s == string.Empty)
                        return false;
                    if (!Int32.TryParse(s, out _))
                    {
                        sb.Append($"{s} is not a number.\n");
                        return false;
                    }
                    else return true;
                }).Select(s => Int32.Parse(s)).Where(i =>
                {
                    if (i > max || i < 0)
                    {
                        sb.Append($"{i} is out of index range.\n");
                        return false;
                    }
                    else return true;
                }).Distinct().ToArray();
            if (filtered.Any())
            {
                return Result<(int[], string), string>.Success((filtered, sb.ToString()));
            }
            else
            {
                return Result<(int[], string), string>.Error($"{sb.ToString()} Failed" +
                    $" to parse any index. Please, type only NUMBERS (like 1, 2, 3.. etc.) that are" +
                    $" in range of indexes.");
            }
        }

    }
}
