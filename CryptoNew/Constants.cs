using System;
using System.Linq;
using System.Text;

namespace Crypto
{
    public static class Constants
    {
        public const int HEADER_SIZE = 512;
        public const int SALT_SIZE = 32;
        public const int CONFIRMATION_BYTES_SIZE = 64;
        public const int BLOCK_MULTIPLIER = 16;
        public const int BUFFER_SIZE = 0X100_000; //1MB
        public const string END_OF_DATA_MARK = "[END_OF_DATA]";
        public const string CONTAINER_FILE_EXTENSION = ".crypt";

        public static Encoding GlobalCryptEncoding = Encoding.Unicode;
        public static byte[] passConfirmationBytes =
            "1234567890123456789212345678931234567894123456789512345678961234"
            .Select(c => (byte)c).ToArray();

        static Constants()
        {
            if (CONFIRMATION_BYTES_SIZE != passConfirmationBytes.Length)
                throw new Exception("passConfirmationBytes size is invalid!");
        }
    }
}
