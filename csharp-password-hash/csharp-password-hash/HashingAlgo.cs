namespace CSharpPasswordHash
{
    public enum HashingAlgo
    {
        NONE = 0,
        HMAC_SHA1 = 1,
        MD5 = 2,
        SHA1 = 3,
        SHA256 = 4,
        HMAC_SHA256 = 5,
        SHA512 = 6,
        PBKDF2 = 7,
        MD2=8
}
}
