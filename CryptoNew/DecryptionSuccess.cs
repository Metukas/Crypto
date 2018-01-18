namespace Crypto
{
    public enum DecryptionSuccess
    {
        None,
        ReadHeader,
        DecryptedHeader,
        ConfirmedKey = DecryptedHeader,
        DecryptedMetadata,
        DisplayingInfo,
        DecryptedFiles,
    }
}