using System;
using System.Data.SqlTypes;
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
            using (var md5 = MD5.Create())
            {
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                switch (encodingType)
                {
                    case EncodingType.Default:
                    case EncodingType.Hex:
                        return ConvertToHex(hashBytes);
                    case EncodingType.Base64:
                        return Convert.ToBase64String(hashBytes);
                    case EncodingType.UTF8:
                        return Encoding.UTF8.GetString(hashBytes);
                    default:
                        return ConvertToHex(hashBytes);
                }
            }
        }
        private static string ToHMAC_SHA256(string password, string key)
        {
            using (var hmacSha = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
            {
                hmacSha.Initialize();
                byte[] hmac = hmacSha.ComputeHash(Encoding.UTF8.GetBytes(password));

                var passwordHash = Encoding.UTF8.GetString(hmac);

                return passwordHash;
            }
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
                case EncodingType.Hex:
                    return ConvertToHex(hashBytes);
                case EncodingType.Base64:
                    return Convert.ToBase64String(hashBytes);
                case EncodingType.UTF8:
                    return Encoding.UTF8.GetString(hashBytes);
                default:
                    return ConvertToHex(hashBytes);
            }
        }

        private static string ToSHA512(string str, EncodingType encodingType)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(str);
            return ToSHA512(plainTextBytes, encodingType);
        }

        private static string ToSHA512(byte[] plainTextBytes, EncodingType encodingType)
        {
            byte[] hashBytes;
            using (var hash = SHA512.Create())
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
                case EncodingType.Hex:
                    return ConvertToHex(hashBytes);
                case EncodingType.Base64:
                    return Convert.ToBase64String(hashBytes);
                case EncodingType.UTF8:
                    return Encoding.UTF8.GetString(hashBytes);
                default:
                    return ConvertToHex(hashBytes);
            }
        }
        private static string ToPBKDF2(string str, String salt, EncodingType encodingType, int pbdkf2Iterations)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(str);
            return ToPBKDF2(plainTextBytes, salt, encodingType, pbdkf2Iterations);
        }
        public static string ToPBKDF2(byte[] plainTextBytes, String salt, EncodingType encodingType, int pbdfk2Iterations)
        {   
            if(pbdfk2Iterations <= 0){
                pbdfk2Iterations = 1;
            }
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
            const int DerivedKeyLength = 24;
            byte[] hashValue;
            using (var pbkdf2 = new Rfc2898DeriveBytes(plainTextBytes, saltBytes, pbdfk2Iterations))
            {
                hashValue = pbkdf2.GetBytes(DerivedKeyLength);

            }
            switch (encodingType)
            {
                case EncodingType.Default:
                    return ConvertToHex(hashValue);
                case EncodingType.Base64:
                    return Convert.ToBase64String(hashValue);
                case EncodingType.UTF8:
                    return Encoding.UTF8.GetString(hashValue);
                default:
                    return ConvertToHex(hashValue);
            }
        }

        public static string HashPassword(string password, string salt, HashingAlgo hashingAlgo,
            EncodingType encodingType, int pbkdf2Iterations)
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

                case HashingAlgo.SHA512:
                    return ToSHA512(password, encodingType);
                
                case HashingAlgo.MD5:
                    return ToMd5(password, encodingType);

                case HashingAlgo.PBKDF2:
                    return ToPBKDF2(password, salt, encodingType, pbkdf2Iterations);

                case HashingAlgo.NONE:
                    return password;
                    
                default:
                    throw new ArgumentOutOfRangeException(nameof(hashingAlgo));
            }
        }

        public static bool CheckPassword(string password, string salt, string hash, HashingAlgo hashingAlgo,
            EncodingType encodingType, int pbdfk2Iterations)
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
                case HashingAlgo.SHA512:
                    return ToSHA512(password, encodingType) == hash;
                case HashingAlgo.MD5:
                    return ToMd5(password, encodingType) == hash;
                case HashingAlgo.PBKDF2:
                    return ToPBKDF2(password, salt, encodingType, pbdfk2Iterations) == hash;
                case HashingAlgo.NONE:
                    return false;     
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
        
       public static (HashingAlgo hashingAlgo, EncodingType encodingType) GetAlgoDet(string password, string salt, string hash )
        {
              var isValidAlgo=false;
              var result = (hashingAlgo: HashingAlgo.NONE, encodingType: EncodingType.Default);
              foreach (string algo in Enum.GetNames(typeof(HashingAlgo)))  
                {         
                      HashingAlgo hashalgo = (HashingAlgo)Enum.Parse(typeof(HashingAlgo), algo);              
                         
                        foreach (string encodeType in Enum.GetNames(typeof(EncodingType)))  
                             {                                                       
                               EncodingType encodingType = (EncodingType)Enum.Parse(typeof(EncodingType), encodeType);
                            
                               isValidAlgo = CheckPassword(password, salt, hash, hashalgo, encodingType);
  
                                 if (isValidAlgo == true)
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
