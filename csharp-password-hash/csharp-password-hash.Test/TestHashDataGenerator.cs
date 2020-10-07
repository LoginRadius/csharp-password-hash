using System.Collections;
using System.Collections.Generic;

namespace CSharpPasswordHash.Test
{
    public class TestHashDataGenerator : IEnumerable<object[]>
    {
        private readonly List<object[]> _data = new List<object[]>
        {
            /* Hash values generated using the following HashingConfig
             {CSharpPasswordHash.HashingConfig}
	         GenratePerPasswordSalt: false
	         GlobalSalt: "SecureSalt"
	         HashingAlgo: 
	         PasswordHashEncodingType: CSharpPasswordHash.EncodingType.Default
	         SaltedPasswordFormat: "#PasswordPlaceHolder#--#SaltPlaceHolder#"
             */
            new object[] { HashingAlgo.SHA1, "ZmUzODBmOTg0NWZkM2NmNGQ5YjgzNDIyOTEzYTBjNTZmZjUxZWYyZQ=="},
            new object[] { HashingAlgo.SHA256, "OGU1MDgzMDlkODUxOTQ4MjZkZDkyY2JhODA5YTc5MzI5OTkwNWRlMTY0YmU0ZjVhN2FhNTIzMmM1ZmZkOTg0NQ=="},
            new object[] { HashingAlgo.HMAC_SHA1, "YjY0YzQ3MGVjMzM1NjRmOTIxZGE3Y2NkMzIyM2E3ODAwNzk3MzIyYg=="},
            new object[] { HashingAlgo.HMAC_SHA256, "MmQ4YjJlYjE2NGZkODQyNDg2MDA0OGU2M2VjZGU3M2JkY2FkOGYxOThlY2UwNjA0MTZiODQ4MWVlODUxYmFhNg=="},
            new object[] { HashingAlgo.MD5, "OTIzZDg5Y2RlOGM0MDRhMGYxODI0NzRhYmI0ZGRmYWQ=" }
        };

        public IEnumerator<object[]> GetEnumerator() => _data.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}