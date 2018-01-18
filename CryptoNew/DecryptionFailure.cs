using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crypto
{
    class DecryptionFailure
    {
        public string Message { get; }
        public Error ErrorCode { get; }

        public DecryptionFailure(string message, Error errorCode)
        {
            this.Message = message;
            this.ErrorCode = errorCode;
        }

        public enum Error
        {
            None,
            FailedToReadHeader,
            FailedToDecryptHeader,
            FailedToDecryptMetadata,
            InputIsInvalid,
            FailedToDecryptFiles
        }
    }
}
