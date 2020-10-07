using System.Collections;
using System.Collections.Generic;

namespace CSharpPasswordHash.Test
{
    public class TestDataGenerator : IEnumerable<object[]>
    {
        private readonly List<object[]> _data = new List<object[]>
        {
            new object[] { HashingAlgo.SHA1},
            new object[] { HashingAlgo.SHA256},
            new object[] { HashingAlgo.SHA512},
            new object[] { HashingAlgo.HMAC_SHA1},
            new object[] { HashingAlgo.HMAC_SHA256},
            new object[] { HashingAlgo.MD5 },
            new object[] {HashingAlgo.PBKDF2},
        };

        public IEnumerator<object[]> GetEnumerator() => _data.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}