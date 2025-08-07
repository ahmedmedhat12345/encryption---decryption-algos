using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
   
    public class RSA
    {
        private static long Pow(long baseValue, int exponent, long modulus)
        {

            if (exponent == 0)
                return 1;

            long result = 1;
            long currentBase = baseValue % modulus;

            while (exponent > 0)
            {
                if ((exponent % 2) == 1)
                {
                    result = (result * currentBase) % modulus;
                }
                currentBase = (currentBase * currentBase) % modulus;
                exponent /= 2;
            }

            return result;
        }

        public int Encrypt(int p, int q, int M, int e)
        {
            //throw new NotImplementedException();
            long n = (long)p * q;
            long phi = (long)(p - 1) * (q - 1);
            long cipher = Pow(M, e, n);
            return (int)cipher;

        }

        public int Decrypt(int p, int q, int C, int e)
        {
            long n = (long)p * q;
            long phi = (long)(p - 1) * (q - 1);
            int d = 1;
            while ((d * e) % phi != 1)
                d++;
            long plain = Pow(C, d, n);
            return (int)plain;

        }
    }
}
