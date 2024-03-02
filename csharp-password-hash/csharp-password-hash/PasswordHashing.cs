using System;

namespace CSharpPasswordHash
{
    public class PasswordHashing
    {
        private (string salt, string passwordHash, string globalFormattedSalt) GetSaltAndHash(HashingConfig passwordEncryption,
            string oldPassword)
        {
            var result = (salt: string.Empty, passwordHash: String.Empty, globalFormattedSalt: string.Empty);

            if (passwordEncryption.GeneratePerPasswordSalt)
            {
                var idx = oldPassword.LastIndexOf(':');
                if (idx != -1)
                {
                    result.passwordHash = oldPassword.Substring(0, idx);
                    result.salt = oldPassword.Substring(idx + 1);
                }

                result.globalFormattedSalt = passwordEncryption.SaltedPasswordFormat;
            }
            else
            {
                result.passwordHash = oldPassword;
                result.globalFormattedSalt = passwordEncryption.SaltedPasswordFormat;
                result.salt = passwordEncryption.GlobalSalt;
            }

            return result;
        }
        private string GetSaltedPassword(string password, string salt, string globalSaltFormat)
        {
            var saltedPassword = globalSaltFormat.Replace(Constants.PasswordPlaceHolder, password).Replace(Constants.SaltPlaceHolder, salt);

            return saltedPassword;
        }

        public bool CheckPassword(string password, HashingConfig passwordEncryption,
            string oldPassword)
        {
            var saltAndHash = GetSaltAndHash(passwordEncryption, password);
            var salt = saltAndHash.salt;
            var passwordHash = saltAndHash.passwordHash;
            var globalFormattedSalt = saltAndHash.globalFormattedSalt;

            var saltedPassword = GetSaltedPassword(oldPassword, salt, globalFormattedSalt);

            var isValidPassword = Hashing.CheckPassword(saltedPassword, salt, passwordHash, passwordEncryption.HashingAlgo,
                passwordEncryption.PasswordHashEncodingType, passwordEncryption.Pbkdf2Iterations);

            return isValidPassword;
        }

        public string GetHash(string password, HashingConfig hashConfig)
        {
            var salt = hashConfig.GeneratePerPasswordSalt
                ? Hashing.GenerateSalt(hashConfig.PerPasswordSaltLength)
                    : hashConfig.GlobalSalt;

            var saltedPassword = GetSaltedPassword(password, salt, hashConfig.SaltedPasswordFormat);

            var passwordHash = Hashing.HashPassword(saltedPassword, salt, hashConfig.HashingAlgo,
                hashConfig.PasswordHashEncodingType, hashConfig.Pbkdf2Iterations);

            return hashConfig.GeneratePerPasswordSalt ? $"{passwordHash}:{salt}" : passwordHash;
        }

        public HashingConfig GetPossibleConfig(string password, string salt, string saltedPasswordFormat, string inputhash)
        {
            var saltedPassword = GetSaltedPassword(password, salt, saltedPasswordFormat);

            var (hashingAlgo, encodingType) = Hashing.GetAlgoDet(saltedPassword, salt, inputhash);
            return new HashingConfig
            {
                HashingAlgo = hashingAlgo,
                PasswordHashEncodingType = encodingType
            };
        }
    }
}
