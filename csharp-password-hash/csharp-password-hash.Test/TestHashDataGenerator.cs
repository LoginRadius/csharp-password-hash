using System.Collections;
using System.Collections.Generic;

namespace CSharpPasswordHash.Test
{
    public class TestHashDataGenerator : IEnumerable<object[]>
    {
        private readonly List<object[]> _data = new List<object[]>
        {
            new object[] { HashingAlgo.SHA1, "MzI4MDBhZGZlZGZmMzVjZTJlMTM1MTBjYjQ0ZDUzMmI3Nzg4NDQ1MjozdTB0WTR1Ug=="},
            new object[] { HashingAlgo.SHA256, "MGQ0OTEwYzM4MzhlMjkwMDUwYmM1MTBmZjBhMzQyMWU2M2ExZmE1OWIyYWUwMjAzNzU1MTlkZmM1OTdkYWIyOTpzM0xGUTlkRw=="},
            new object[] { HashingAlgo.HMAC_SHA1, "Je+/vSTvv73vv71dWu+/vTfvv702f++/vRvvv73vv71PHe+/vTU6WHE1Q2NSaXc="},
            new object[] { HashingAlgo.HMAC_SHA256, "77+9J++/vRLvv70T77+9WU1DRz3vv702G++/vXco77+9cO+/vV1977+9Nu+/vQpA77+977+9fO+/vTpQcTZEQmp5Tw=="},
            new object[] { HashingAlgo.MD5, "YTc3MTQ4NGU5NDU5MGY5MjhhYWIwOTA2NDY2NDdkZjg6djNUdHc0aE4=" }
        };

        public IEnumerator<object[]> GetEnumerator() => _data.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}