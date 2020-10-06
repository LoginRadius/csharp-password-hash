using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CSharpPasswordHash
{
    public static class Hashing
    {
        private static string ConvertToHex(byte[] hashBytes)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("x2"));
            }

            return sb.ToString();
        }

        private static string ToHMAC_SHA256(string password, string key, EncodingType encodingType)
        {
            using var hmacSha = new HMACSHA256(Encoding.UTF8.GetBytes(key));

            hmacSha.Initialize();
            return Encode(hmacSha.ComputeHash(Encoding.UTF8.GetBytes(password)), encodingType);
        }

        private static string ToHMAC_SHA1(string password, string key, EncodingType encodingType)
        {
            using var hmacSha = new HMACSHA1(Encoding.UTF8.GetBytes(key));

            hmacSha.Initialize();
            return Encode(hmacSha.ComputeHash(Encoding.UTF8.GetBytes(password)), encodingType);
        }

        private static string ToHashAlgorithm(HashAlgorithm hashAlgorithm, string password, EncodingType encodingType)
        {
            var plainTextBytes = Encoding.UTF8.GetBytes(password);
            using (hashAlgorithm)
            {
                return Encode(hashAlgorithm.ComputeHash(plainTextBytes), encodingType);
            }
        }

        private static string Encode(byte[] bytes, EncodingType encodingType)
        {
            return encodingType switch
            {
                EncodingType.Base64 => Convert.ToBase64String(bytes),
                EncodingType.UTF8 => Encoding.UTF8.GetString(bytes),
                EncodingType.Hex => ConvertToHex(bytes),
                EncodingType.Default => ConvertToHex(bytes),
                _ => ConvertToHex(bytes)
            };
        }

        private static string ToPBKDF2(string str, String salt, EncodingType encodingType, int pbdkf2Iterations)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(str);
            return ToPBKDF2(plainTextBytes, salt, encodingType, pbdkf2Iterations);
        }
        public static string ToPBKDF2(byte[] plainTextBytes, String salt, EncodingType encodingType, int pbdfk2Iterations)
        {
            if (pbdfk2Iterations <= 0)
            {
                pbdfk2Iterations = 1;
            }
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
            const int DerivedKeyLength = 24;
            byte[] hashValue;
            using (var pbkdf2 = new Rfc2898DeriveBytes(plainTextBytes, saltBytes, pbdfk2Iterations))
            {
                hashValue = pbkdf2.GetBytes(DerivedKeyLength);
            }

            return Encode(hashValue, encodingType);
        }

        public static string HashPassword(string password, string salt, HashingAlgo hashingAlgo,
            EncodingType encodingType, int pbkdf2Iterations)
        {
            return hashingAlgo switch
            {
                HashingAlgo.HMAC_SHA1 => ToHMAC_SHA1(password, salt, encodingType),
                HashingAlgo.HMAC_SHA256 => ToHMAC_SHA256(password, salt, encodingType),
                HashingAlgo.SHA1 => ToHashAlgorithm(SHA1.Create(), password, encodingType),
                HashingAlgo.SHA256 => ToHashAlgorithm(SHA256.Create(), password, encodingType),
                HashingAlgo.SHA512 => ToHashAlgorithm(SHA512.Create(), password, encodingType),
                HashingAlgo.MD5 => ToHashAlgorithm(MD5.Create(), password, encodingType),
                HashingAlgo.PBKDF2 => ToPBKDF2(password, salt, encodingType, pbkdf2Iterations),
                HashingAlgo.NONE => password,
                _ => throw new ArgumentOutOfRangeException(nameof(hashingAlgo))
            };
        }

        public static bool CheckPassword(string password, string salt, string hash, HashingAlgo hashingAlgo,
            EncodingType encodingType, int pbdfk2Iterations = 0)
        {
            return hashingAlgo switch
            {
                HashingAlgo.HMAC_SHA1 => ToHMAC_SHA1(password, salt, encodingType) == hash,
                HashingAlgo.HMAC_SHA256 => ToHMAC_SHA256(password, salt, encodingType) == hash,
                HashingAlgo.SHA1 => ToHashAlgorithm(SHA1.Create(), password, encodingType) == hash,
                HashingAlgo.SHA256 => ToHashAlgorithm(SHA256.Create(), password, encodingType) == hash,
                HashingAlgo.SHA512 => ToHashAlgorithm(SHA512.Create(), password, encodingType) == hash,
                HashingAlgo.MD5 => ToHashAlgorithm(MD5.Create(), password, encodingType) == hash,
                HashingAlgo.PBKDF2 => ToPBKDF2(password, salt, encodingType, pbdfk2Iterations) == hash,
                HashingAlgo.NONE => false,
                _ => throw new ArgumentOutOfRangeException(nameof(hashingAlgo))
            }
        }

        public static string GenerateSalt()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
            var random = new Random((int)DateTime.Now.Ticks & 0x0000FFFF);
            return new string(
                Enumerable.Repeat(chars, 8)
                    .Select(s => s[random.Next(s.Length)])
                    .ToArray());
        }

        public static (HashingAlgo hashingAlgo, EncodingType encodingType) GetAlgoDet(string password, string salt, string hash)
        {
            var result = (hashingAlgo: HashingAlgo.NONE, encodingType: EncodingType.Default);
            foreach (string algo in Enum.GetNames(typeof(HashingAlgo)))
            {
                HashingAlgo hashalgo = (HashingAlgo)Enum.Parse(typeof(HashingAlgo), algo);

                foreach (string encodeType in Enum.GetNames(typeof(EncodingType)))
                {
                    EncodingType encodingType = (EncodingType)Enum.Parse(typeof(EncodingType), encodeType);

                    bool isValidAlgo = CheckPassword(password, salt, hash, hashalgo, encodingType);

                    if (isValidAlgo)
                    {
                        result.hashingAlgo = hashalgo;
                        result.encodingType = encodingType;
                        return result;
                    }
                }
            }
            return result;
        }
    }
}
