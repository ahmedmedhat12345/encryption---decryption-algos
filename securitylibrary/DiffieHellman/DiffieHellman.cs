using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public int privatefetch(int generator, int private_key, int prime)
        {
            int mm = 0;
            int secretkbuild = 1;
            for (; mm < private_key; mm++)
            {
                secretkbuild = (secretkbuild * generator) % prime;
            }
            return secretkbuild;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> secretk = new List<int>();
            int secondsecretk = 0;
            int firstsecretk = 0;
            int nextfetch = privatefetch(alpha, xb, q);
            int primaryfetch = privatefetch(alpha, xa, q);
            secondsecretk = privatefetch(nextfetch, xa, q);
            firstsecretk = privatefetch(primaryfetch, xb, q);




            secretk.Add(firstsecretk);
            secretk.Add(secondsecretk);

            return secretk;
        }
    }
}

