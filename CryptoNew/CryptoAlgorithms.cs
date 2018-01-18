using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Crypto
{
    class CryptoAlgorithms
    {
        public static Type[] HashAlgorithms;
        public static Type[] SymmetricAlgorithms;

        static CryptoAlgorithms()
        {
            HashAlgorithms = new Type[]
            {
                typeof(MD5CryptoServiceProvider), //plz don't use
                typeof(SHA1Managed),
                typeof(SHA256Managed),
                typeof(SHA384Managed),
                typeof(SHA512Managed),
            };

            SymmetricAlgorithms = new Type[]
            {
                typeof(AesManaged),
                typeof(RijndaelManaged),
                typeof(DESCryptoServiceProvider),
                typeof(TripleDESCryptoServiceProvider),
            };
        }

        public static (Type, Type[]) HeadAndTail(Type[] types)
        {
            if (types.Length == 1)
            {
                return (types[0], Array.Empty<Type>());
            }

            var temp = new Type[types.Length - 1];
            for(int i = 0; i < temp.Length; i++)
            {
                temp[i] = types[i+1];
            }
            return (types[0], temp);
        }
    }
}
