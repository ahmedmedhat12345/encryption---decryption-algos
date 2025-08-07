using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            int keyChar;
            string keyText = "";
            char plainChar;
            char cipherChar;
            int j = 0;
            bool stop = false;

            for (int i = 0; i < plainText.Length; i++)
            {
                plainChar = char.ToUpper(plainText[i]);
                cipherChar = char.ToUpper(cipherText[i]);
                keyChar = (((cipherChar) - (plainChar) + 26) % 26) + 'A';
                if (char.ToUpper(plainText[j]) == (char)keyChar)
                {
                    if (stop == false)
                    {
                        stop = true;
                        j++;
                    }
                    else
                    {

                        return keyText;
                    }
                }
                else
                {
                    keyText += (char)keyChar;
                }
            }



            return keyText;
        }



        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            string plainText = "";
            char cipherChar;
            char keyChar;
            int plainChar;


            for (int i = 0; i < cipherText.Length; i++)
            {
                cipherChar = char.ToUpper(cipherText[i]);
                keyChar = char.ToUpper(key[i]);
                plainChar = (((cipherText[i]) - (keyChar) + 26) % 26) + 'A';
                plainText += (char)plainChar;


                key += (char)plainChar;
            }

            return plainText;
        }


        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            string keyText = "";
            string cipherText = "";
            int j = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (i < key.Length)
                {
                    keyText += key[i];
                }
                else
                {
                    keyText += plainText[j];
                    j++;
                }
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                char plainChar = char.ToUpper(plainText[i]);
                char keyChar = char.ToUpper(keyText[i]);
                int cipherChar = (((plainChar) + (keyChar)) % 26) + 'A';
                cipherText += (char)cipherChar;
            }
            return cipherText;
        }
    }
}
