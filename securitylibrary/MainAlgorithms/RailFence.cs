using System;
using System.Collections.Generic;
using System.Text;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int secretkey = 2;
            int signal = 0;
            while (secretkey < plainText.Length)
            {
                StringBuilder outcome = new StringBuilder();
                string originaltext = plainText.ToUpper();
                var encryptedtextlist = new List<StringBuilder>();
              

                int indexofcolumn = 0;
                do
                {
                    StringBuilder createcencryptedtext = new StringBuilder();
                    encryptedtextlist.Add(createcencryptedtext);
                    indexofcolumn++;
                } while (indexofcolumn < secretkey);

                int path = 1;
                int instantL = 0;
                int d = 0;
                while (d < originaltext.Length)
                {
                    encryptedtextlist[instantL].Append(originaltext[d]);

                    if (instantL == 0)
                        path++;

                    instantL += 1;
                    if (instantL == secretkey)
                        instantL = 0;

                    d++;
                }

                int s = 0;
                while (s < secretkey)
                {
                    string lastencryptedtext = encryptedtextlist[s].ToString();
                    outcome.Append(lastencryptedtext);
                    s++;
                }

                string encryptedtext = outcome.ToString();
                if (encryptedtext == cipherText)
                {
                    signal = secretkey;
                    break;
                }

                secretkey++;  
            }

            return signal;

        }

        public string Decrypt(string cipherText, int key)
        {
            int encryptedtextsize = cipherText.Length;

            double encrypted = (double)(encryptedtextsize);
            encrypted /= (double)(key);
            int sizeofarray = (int)Math.Ceiling((encrypted));

            char[,] texttable;
            texttable = new char[key, sizeofarray];
            int n = 0;
            int indexofR = 0;

            for (indexofR = 0; indexofR < key; indexofR++)
            {
                int k = 0;
                while (k < sizeofarray)
                {
                    if (n != encryptedtextsize)
                    {
                        texttable[indexofR, k] = cipherText[n];
                        n++;
                    }
                    k++;
                }
            }

            int encryptedsize = 0;
            string original = "";
            for (encryptedsize = 0; encryptedsize < sizeofarray; encryptedsize++)
            {
                int t = 0;
                while (t < key)
                {
                    original += texttable[t, encryptedsize];
                    t++;
                }
            }
            return original;
        }

        public string Encrypt(string plainText, int key)
        {
            char[,] encryptedtextcreation;
            int indexofcolumn = 0;
            int originaltextsize = plainText.Length;
            int z = 0;
            encryptedtextcreation = new char[key, originaltextsize];
            for (indexofcolumn = 0; indexofcolumn < originaltextsize; indexofcolumn++)
            {
                int k = 0;
                while (k < key)
                {
                    if (z != originaltextsize)
                    {
                        encryptedtextcreation[k, indexofcolumn] = plainText[z];
                        z++;
                    }
                    k++;
                }
            }

            int size = 0;
            string outcomeofencryptedtext = "";
            do
            {
                int v = 0;
                while (v < originaltextsize)
                {
                    if (encryptedtextcreation[size, v] != '0')
                    {
                        outcomeofencryptedtext += encryptedtextcreation[size, v];
                    }
                    v++;
                }

                size++;
            } while (size < key);

            return outcomeofencryptedtext;
        }
    }
}
