namespace CSharpPasswordHash
{
    public class HashingConfig
    {
        public HashingAlgo HashingAlgo { get; set; }
        public bool GenratePerPasswordSalt { get; set; }
        public string GlobalSalt { get; set; }

        public string SaltedPasswordFormat { get; set; }
        public EncodingType PasswordHashEncodingType { get; set; }
    }
}