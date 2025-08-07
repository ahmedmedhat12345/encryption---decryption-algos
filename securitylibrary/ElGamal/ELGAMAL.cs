using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            // throw new NotImplementedException();
            List<long> result = new List<long>();
            long c1 = ModuloExponentiation(alpha, k, q);
            result.Add(c1);
            long c2 = (m * ModuloExponentiation(y, k, q)) % q;
            result.Add(c2);
            return result;

        }
        public long ModuloExponentiation(int baseValue, int exponent, int mod)
        {
            long result = 1;
            long basepow = baseValue % mod;

            while (exponent > 0)
            {
                if (exponent % 2 == 1)
                    result = (result * basepow) % mod;

                exponent = exponent / 2;
                basepow = (basepow * basepow) % mod;
            }

            return result;
        }

        public int Decrypt(int c1, int c2, int x, int q)
        {
            // throw new NotImplementedException();
            long s = ModuloExponentiation(c1, q - 1 - x, q);
            long m = (c2 * s) % q;
            return (int)m;
        }
    }
}
