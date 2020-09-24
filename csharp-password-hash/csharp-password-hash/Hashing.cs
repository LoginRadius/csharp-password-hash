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

        private static string ToMd5(string input, EncodingType encodingType)
        {
            byte[] inputBytes = Encoding.ASCII.GetBytes(input);
            return CreateMd5(inputBytes, encodingType);
        }

        private static string CreateMd5(byte[] inputBytes, EncodingType encodingType)
        {
            var md5 = MD5.Create();
            byte[] hashBytes = md5.ComputeHash(inputBytes);

            switch (encodingType)
            {
                case EncodingType.Default:
                    return ConvertToHex(hashBytes);
                case EncodingType.Base64:
                    return Convert.ToBase64String(hashBytes);
                case EncodingType.UTF8:
                    return Encoding.UTF8.GetString(hashBytes);
                default:
                    return ConvertToHex(hashBytes);
            }
        }
        private static string ToHMAC_SHA256(string password, string key)
        {
            var hmacSha = new HMACSHA256(Encoding.UTF8.GetBytes(key));
            hmacSha.Initialize();
            byte[] hmac = hmacSha.ComputeHash(Encoding.UTF8.GetBytes(password));

            var passwordHash = Encoding.UTF8.GetString(hmac);

            return passwordHash;
        }

        private static string ToHMAC_SHA1(string password, string key)
        {
            using (var hmacSha = new HMACSHA1(Encoding.UTF8.GetBytes(key)))
            {
                hmacSha.Initialize();
                byte[] hmac = hmacSha.ComputeHash(Encoding.UTF8.GetBytes(password));
                
                var passwordHash = Encoding.UTF8.GetString(hmac);

                return passwordHash;
            }
        }

        private static string ToSHA256(string str, EncodingType encodingType)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(str);
            return ToSHA256(plainTextBytes, encodingType);
        }

        private static string ToSHA256(byte[] plainTextBytes, EncodingType encodingType)
        {
            byte[] hashBytes;
            using (var hash = SHA256.Create())
            {
                hashBytes = hash.ComputeHash(plainTextBytes);
            }

            switch (encodingType)
            {
                case EncodingType.Default:
                    return ConvertToHex(hashBytes);
                case EncodingType.Base64:
                    return Convert.ToBase64String(hashBytes);
                case EncodingType.UTF8:
                    return Encoding.UTF8.GetString(hashBytes);
                default:
                    return ConvertToHex(hashBytes);
            }
        }

        private static string ToSHA1(string str, EncodingType encodingType)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(str);
            var sha1Password = ToSHA1(plainTextBytes, encodingType);
            return sha1Password;
        }

        private static string ToSHA1(byte[] plainTextBytes, EncodingType encodingType)
        {
            byte[] hashBytes;
            using (var hash = SHA1.Create())
            {
                hashBytes = hash.ComputeHash(plainTextBytes);
            }

            switch (encodingType)
            {
                case EncodingType.Default:
                    return ConvertToHex(hashBytes);
                case EncodingType.Base64:
                    return Convert.ToBase64String(hashBytes);
                case EncodingType.UTF8:
                    return Encoding.UTF8.GetString(hashBytes);
                default:
                    return ConvertToHex(hashBytes);
            }
        }

        public static string EncryptPassword(string password, string salt, HashingAlgo hashingAlgo,
            EncodingType encodingType)
        {
            switch (hashingAlgo)
            {
                case HashingAlgo.HMAC_SHA1:
                    return ToHMAC_SHA1(password, salt);

                case HashingAlgo.HMAC_SHA256:
                    return ToHMAC_SHA256(password, salt);

                case HashingAlgo.SHA1:
                    return ToSHA1(password, encodingType);

                case HashingAlgo.SHA256:
                    return ToSHA256(password, encodingType);

                case HashingAlgo.MD5:
                    return ToMd5(password, encodingType);

                default:
                    throw new ArgumentOutOfRangeException(nameof(hashingAlgo));
            }
        }

        public static bool CheckPassword(string password, string salt, string hash, HashingAlgo hashingAlgo,
            EncodingType encodingType)
        {
            switch (hashingAlgo)
            {
                case HashingAlgo.HMAC_SHA1:
                    return ToHMAC_SHA1(password, salt) == hash;
                case HashingAlgo.HMAC_SHA256:
                    return ToHMAC_SHA256(password, salt) == hash;
                case HashingAlgo.SHA1:
                    return ToSHA1(password, encodingType) == hash;
                case HashingAlgo.SHA256:
                    return ToSHA256(password, encodingType) == hash;
                case HashingAlgo.MD5:
                    return ToMd5(password, encodingType) == hash;
                default:
                    throw new ArgumentOutOfRangeException(nameof(hashingAlgo));
            }
        }

        public static string GenerateSalt()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
            var random = new Random();
            return new string(
                Enumerable.Repeat(chars, 8)
                    .Select(s => s[random.Next(s.Length)])
                    .ToArray());
        }
    }

}
