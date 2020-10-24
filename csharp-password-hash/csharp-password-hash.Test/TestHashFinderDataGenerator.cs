using System.Collections;
using System.Collections.Generic;


namespace CSharpPasswordHash.Test
{
    public class TestHashFinderDataGenerator : IEnumerable<object[]>
    {
        private readonly List<object[]> _data = new List<object[]>
        {
            /* Hash values generated using the following HashingConfig
             #PasswordPlaceHolder#: CorrectPassword
             #SaltPlaceHolder#: SecureSalt
            
             {CSharpPasswordHash.HashingConfig}
	         GeneratePerPasswordSalt: false
	         GlobalSalt: "SecureSalt"
	         PasswordHashEncodingType: CSharpPasswordHash.EncodingType.Default/Base64
	         SaltedPasswordFormat: "#PasswordPlaceHolder#--#SaltPlaceHolder#"
             */
            new object[] { HashingAlgo.SHA1, EncodingType.Default, "fe380f9845fd3cf4d9b83422913a0c56ff51ef2e"},
            new object[] { HashingAlgo.SHA1, EncodingType.Base64, "/jgPmEX9PPTZuDQikToMVv9R7y4="},
            new object[] { HashingAlgo.SHA256, EncodingType.Default, "8e508309d85194826dd92cba809a793299905de164be4f5a7aa5232c5ffd9845"},
            new object[] { HashingAlgo.SHA256, EncodingType.Base64, "jlCDCdhRlIJt2Sy6gJp5MpmQXeFkvk9aeqUjLF/9mEU="},
            new object[] { HashingAlgo.HMAC_SHA1, EncodingType.Default, "b64c470ec33564f921da7ccd3223a7800797322b" },
            new object[] { HashingAlgo.HMAC_SHA1, EncodingType.Base64, "tkxHDsM1ZPkh2nzNMiOngAeXMis="},
            new object[] { HashingAlgo.HMAC_SHA256, EncodingType.Default, "2d8b2eb164fd8424860048e63ecde73bdcad8f198ece060416b8481ee851baa6"},
            new object[] { HashingAlgo.HMAC_SHA256, EncodingType.Base64, "LYsusWT9hCSGAEjmPs3nO9ytjxmOzgYEFrhIHuhRuqY="},
            new object[] { HashingAlgo.MD5, EncodingType.Default, "923d89cde8c404a0f182474abb4ddfad" },
            new object[] { HashingAlgo.MD5, EncodingType.Base64, "kj2JzejEBKDxgkdKu03frQ==" }
        };

        public IEnumerator<object[]> GetEnumerator() => _data.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}



