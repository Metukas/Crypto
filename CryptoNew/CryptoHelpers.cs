using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Crypto
{
    class CryptoHelpers
    {
        internal static byte[] DeriveKey(byte[] salt, SecureString password, SymmetricAlgorithm algorithm, Func<byte[], byte[]> hashFunction)
        {
            List<byte> keyBytes = new List<byte>(new Rfc2898DeriveBytes(HashSecureString(password, hashFunction),
                salt, 0xFF).GetBytes(algorithm.KeySize / 8));
            return keyBytes.ToArray();
        }

        /// <summary>
        /// Suskaičiuoja koks bus baitų masyvo dydis jį užšifravus blokiniu (pvz. aes) šifro algoritmu
        /// </summary>
        /// <param name="arr">Masyvas</param>
        /// <param name="blockSize">Algoritmo bloko dydis bitais</param>
        /// <param name="bytes">Ar atsakymą grąžinti BAITAIS? Jeigu false, atsakymas grąžinamas BITAIS</param>
        /// <returns></returns>
        internal static long CalculateCryptedLength(byte[] arr, long blockSize, bool bytes)
        {
            long plainSize = arr.Length * 8;
            long cryptSize = plainSize + blockSize - (plainSize % blockSize); //būsimas užšifruotų BITŲ kiekis

            //Jeigu bytes == true, grąžina dydį baitais. Jeigu bytes == false - bitais.
            return bytes ? (cryptSize / 8) : cryptSize;
        }

        /// <summary>
        /// Suskaičiuoja koks bus baitų masyvo dydis jį užšifravus blokiniu (pvz. aes) šifro algoritmu
        /// </summary>
        /// <param name="plainSize">Neužšifruotų duomenų dydis baitais</param>
        /// <param name="algorithm">Blokinis šifro algoritmas</param>
        /// <param name="bytes">Ar atsakymą grąžinti BAITAIS? Jeigu false, atsakymas grąžinamas BITAIS</param>
        /// <returns></returns>
        internal static long CalculateCryptedLength(long plainSize, SymmetricAlgorithm algorithm, bool bytes)
        {
            return bytes ?
                plainSize + (algorithm.BlockSize / 8) - (plainSize % (algorithm.BlockSize / 8)) :
                plainSize + algorithm.BlockSize - (plainSize % algorithm.BlockSize);
        }

        internal static byte[] HashSecureString(SecureString ss, Func<byte[], byte[]> hash)
        {
            // Verčiam SecureString į BSRT (unmanaged binary string)
            IntPtr bstr = Marshal.SecureStringToBSTR(ss);

            // 4 baitai prieš BSTR pointerį yra įrašytas BSTR ilgis (Int32 tipo)
            int length = Marshal.ReadInt32(bstr, -4);
            byte[] plainBytes = new byte[length];
            Marshal.Copy(bstr, plainBytes, 0, length);
            Marshal.ZeroFreeBSTR(bstr);

            byte[] hashed = hash(plainBytes);
            // sunaikinam SecureString plaintext baitus
            for (int i = 0; i < length; i++)
            {
                plainBytes[i] = 0;
            }

            return hashed;
        }

        internal static byte[] GenerateRandomBytes(int byteCount)
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] bytes = new byte[byteCount];
                rng.GetNonZeroBytes(bytes);
                return bytes;
            }
        }

        
    }
}
