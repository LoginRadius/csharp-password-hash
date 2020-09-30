using Xunit;

namespace CSharpPasswordHash.Test
{
    public class PasswordHashTest
    {
        private const string GlobalSalt= "SecureSalt";
        private const string CorrectPassword = "CorrectPassword";
        private const string SaltedPasswordFormat = Constants.PasswordPlaceHolder+"--"+Constants.SaltPlaceHolder;

        public class WhenPerPasswordSaltTrue
        {
            [Theory]
            [ClassData(typeof(TestDataGenerator))]
            public void Correct_Password_Should_Match(HashingAlgo hashingAlgo)
            {
                var hashConfig = new HashingConfig
                {
                    GenratePerPasswordSalt = true,
                    GlobalSalt = null,
                    SaltedPasswordFormat = SaltedPasswordFormat,
                    HashingAlgo = hashingAlgo,
                    PasswordHashEncodingType = EncodingType.Default
                };

                var passwordHashing = new PasswordHashing();
                var hash = passwordHashing.GetHash(CorrectPassword, hashConfig);
                var match = passwordHashing.CheckPassword(hash, hashConfig, CorrectPassword);

                Assert.True(match);
            }

            [Theory]
            [ClassData(typeof(TestDataGenerator))]
            public void Wrong_Password_Should_Not_Match(HashingAlgo hashingAlgo)
            {
                var hashConfig = new HashingConfig
                {
                    GenratePerPasswordSalt = true,
                    GlobalSalt = null,
                    SaltedPasswordFormat = SaltedPasswordFormat,
                    HashingAlgo = hashingAlgo,
                    PasswordHashEncodingType = EncodingType.Default
                };

                var passwordHashing = new PasswordHashing();
                var hash = passwordHashing.GetHash(CorrectPassword, hashConfig);
                var match = passwordHashing.CheckPassword(hash, hashConfig, "wrongPassword");

                Assert.False(match);
            }
        }

        public class WhenPerPasswordSaltFalse
        {
            [Theory]
            [ClassData(typeof(TestDataGenerator))]
            public void Correct_Password_Should_Match(HashingAlgo hashingAlgo)
            {
                var hashConfig = new HashingConfig
                {
                    GenratePerPasswordSalt = false,
                    GlobalSalt = GlobalSalt,
                    SaltedPasswordFormat = SaltedPasswordFormat,
                    HashingAlgo = hashingAlgo,
                    PasswordHashEncodingType = EncodingType.Default
                };

                var passwordHashing = new PasswordHashing();
                var hash = passwordHashing.GetHash(CorrectPassword, hashConfig);
                var match = passwordHashing.CheckPassword(hash, hashConfig, CorrectPassword);

                Assert.True(match);
            }

            [Theory]
            [ClassData(typeof(TestDataGenerator))]
            public void Wrong_Password_Should_Not_Match(HashingAlgo hashingAlgo)
            {
                var hashConfig = new HashingConfig
                {
                    GenratePerPasswordSalt = false,
                    GlobalSalt = GlobalSalt,
                    SaltedPasswordFormat = SaltedPasswordFormat,
                    HashingAlgo = hashingAlgo,
                    PasswordHashEncodingType = EncodingType.Default
                };

                var passwordHashing = new PasswordHashing();
                var hash = passwordHashing.GetHash(CorrectPassword, hashConfig);
                var match = passwordHashing.CheckPassword(hash, hashConfig, "wrongPassword");

                Assert.False(match);
            }
        }

        public class HashCheck
        {
            [Theory]
            [ClassData(typeof(TestHashDataGenerator))]
            public void Correct_Hash_Values_Should_Match_GetHash(HashingAlgo hashingAlgo, string expectedHashBase64)
            {
                var hashConfig = new HashingConfig
                {
                    GenratePerPasswordSalt = false,
                    GlobalSalt = GlobalSalt,
                    SaltedPasswordFormat = SaltedPasswordFormat,
                    HashingAlgo = hashingAlgo,
                    PasswordHashEncodingType = EncodingType.Default
                };

                var passwordHashing = new PasswordHashing();
                var hashActual = passwordHashing.GetHash(CorrectPassword, hashConfig);
                var hashExpected = System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(expectedHashBase64));

                Assert.Equal(hashExpected,hashActual);
            }
        }
    }
}
