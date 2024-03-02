using System;

namespace CSharpPasswordHash
{
    public class HashingConfig
    {
        public HashingAlgo HashingAlgo { get; set; }
        [ObsoleteAttribute("Use GeneratePerPasswordSalt instead", false)]
        public bool GenratePerPasswordSalt { get { return GeneratePerPasswordSalt; } set { GeneratePerPasswordSalt = value; } }
        public bool GeneratePerPasswordSalt { get; set; }
        public int PerPasswordSaltLength { get; set; }
        public string GlobalSalt { get; set; }

        public string SaltedPasswordFormat { get; set; }
        public EncodingType PasswordHashEncodingType { get; set; }

        public int Pbkdf2Iterations { get; set; }
    }
}