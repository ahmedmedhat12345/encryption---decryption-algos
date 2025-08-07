using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            // throw new NotImplementedException();
            DES des = new DES();
            int length = key.Count();
            string plainText = "";
            if (length == 2)
            {
                plainText = des.Decrypt(cipherText, key[1]);
                plainText = des.Encrypt(plainText, key[0]);
                plainText = des.Decrypt(plainText, key[1]);
            }
            else if (length == 3)
            {
                plainText = des.Decrypt(cipherText, key[2]);
                plainText = des.Encrypt(plainText, key[1]);
                plainText = des.Decrypt(plainText, key[0]);

            }
            return plainText;


        }

        public string Encrypt(string plainText, List<string> key)
        {
            //throw new NotImplementedException();
            DES des = new DES();
            int length = key.Count();
            string cipherText = "";
            if(length == 2)
            {
                cipherText = des.Encrypt(plainText, key[0]);
                cipherText = des.Decrypt(cipherText, key[1]);
                cipherText = des.Encrypt(cipherText, key[0]);
            }
            else if (length == 3)
            {
                cipherText = des.Encrypt(plainText, key[0]);
                cipherText = des.Decrypt(cipherText, key[1]);
                cipherText = des.Encrypt(cipherText, key[2]);

            }
            return cipherText;

        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
