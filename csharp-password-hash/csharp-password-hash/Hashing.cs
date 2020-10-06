using System;
using System.Data.SqlTypes;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using BCrypt.Net;

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
            using (var hmacSha = new HMACSHA256(Encoding.UTF8.GetBytes(key)))
            {
                hmacSha.Initialize();
                return Encode(hmacSha.ComputeHash(Encoding.UTF8.GetBytes(password)), encodingType);
            }
        }

        private static string ToHMAC_SHA1(string password, string key, EncodingType encodingType)
        {
            using (var hmacSha = new HMACSHA1(Encoding.UTF8.GetBytes(key)))
            {
                hmacSha.Initialize();
                return Encode(hmacSha.ComputeHash(Encoding.UTF8.GetBytes(password)), encodingType);
            }
        }

        private static string ToHashAlgorithm(HashAlgorithm hashAlgorithm, byte[] plainTextBytes, EncodingType encodingType)
        {
            using (hashAlgorithm)
            {
                return Encode(hashAlgorithm.ComputeHash(plainTextBytes), encodingType);
            }
        }

        private static string Encode(byte[] bytes, EncodingType encodingType)
        {
            switch (encodingType)
            {
                case EncodingType.Default:
                case EncodingType.Hex:
                    return ConvertToHex(bytes);
                case EncodingType.Base64:
                    return Convert.ToBase64String(bytes);
                case EncodingType.UTF8:
                    return Encoding.UTF8.GetString(bytes);
                default:
                    return ConvertToHex(bytes);
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

        private static ToBCRYPT(string password, string salt)
        {
             return BCrypt.HashPassword(password, salt);     
        }
        
        public static string HashPassword(string password, string salt, HashingAlgo hashingAlgo,
            EncodingType encodingType, int pbkdf2Iterations)
        {
            switch (hashingAlgo)
            {
                case HashingAlgo.HMAC_SHA1:
                    return ToHMAC_SHA1(password, salt, encodingType);

                case HashingAlgo.HMAC_SHA256:
                    return ToHMAC_SHA256(password, salt, encodingType);

                case HashingAlgo.SHA1:
                    return ToHashAlgorithm(SHA1.Create(), Encoding.UTF8.GetBytes(password), encodingType);

                case HashingAlgo.SHA256:
                    return ToHashAlgorithm(SHA256.Create(), Encoding.UTF8.GetBytes(password), encodingType);

                case HashingAlgo.SHA512:
                    return ToHashAlgorithm(SHA512.Create(), Encoding.UTF8.GetBytes(password), encodingType);
                
                case HashingAlgo.MD5:
                    return ToHashAlgorithm(MD5.Create(), Encoding.ASCII.GetBytes(password), encodingType);

                case HashingAlgo.PBKDF2:
                    return ToPBKDF2(password, salt, encodingType, pbkdf2Iterations);

                case HashingAlgo.BCRYPT:
                    return ToBCRYPT(password, salt);

                case HashingAlgo.NONE:
                    return password;
                    
                default:
                    throw new ArgumentOutOfRangeException(nameof(hashingAlgo));
            }
        }

        public static bool CheckPassword(string password, string salt, string hash, HashingAlgo hashingAlgo,
            EncodingType encodingType, int pbdfk2Iterations=0)
        {
            switch (hashingAlgo)
            {
                case HashingAlgo.HMAC_SHA1:
                    return ToHMAC_SHA1(password, salt, encodingType) == hash;
                case HashingAlgo.HMAC_SHA256:
                    return ToHMAC_SHA256(password, salt, encodingType) == hash;
                case HashingAlgo.SHA1:
                    return ToHashAlgorithm(SHA1.Create(), Encoding.UTF8.GetBytes(password), encodingType) == hash;
                case HashingAlgo.SHA256:
                    return ToHashAlgorithm(SHA256.Create(), Encoding.UTF8.GetBytes(password), encodingType) == hash;
                case HashingAlgo.SHA512:
                    return ToHashAlgorithm(SHA512.Create(), Encoding.UTF8.GetBytes(password), encodingType) == hash;
                case HashingAlgo.MD5:
                    return ToHashAlgorithm(MD5.Create(), Encoding.ASCII.GetBytes(password), encodingType) == hash;
                case HashingAlgo.PBKDF2:
                    return ToPBKDF2(password, salt, encodingType, pbdfk2Iterations) == hash;
                case HashingAlgo.BCRYPT:
                    return ToBCRYPT(password, salt) == hash;    
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
