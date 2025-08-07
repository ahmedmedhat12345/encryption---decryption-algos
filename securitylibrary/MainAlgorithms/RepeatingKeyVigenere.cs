using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        // char[,] arr = new char[26, 26];
        //string letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        public string Analyse(string plainText, string cipherText)
        {
            int[] keyStream = new int[plainText.Length];
            int[] key = new int[plainText.Length];
            char[] keyText = new char[plainText.Length];

            // Getting keyStream
            for (int i = 0; i < plainText.Length; i++)
            {
                keyStream[i] = (((char.ToUpper(cipherText[i])) - (char.ToUpper(plainText[i])) + 26) % 26);
            }

            // Finding the key
            bool found;
            bool flag;
            int temp;

            for (int i = 0; i < keyStream.Length; i++)
            {
                found = false;

                for (int k = 0; k < i; k++)
                {
                    if (keyStream[i] == keyStream[k])
                    {
                        found = true;
                        break;
                    }
                }

                if (found)
                {
                    flag = true;
                    temp = i;

                    for (int k = 0; k < keyStream.Length - i; k++)
                    {
                        if (keyStream[k] != keyStream[temp])
                        {
                            flag = false;
                            break;
                        }
                        temp++;
                    }

                    if (flag)
                    {
                        key = new int[i]; // Resize key array
                        keyText = new char[i]; // Resize keyText array

                        for (int l = 0; l < i; l++)
                        {
                            key[l] = keyStream[l];
                            keyText[l] = (char)('A' + key[l]);
                        }
                        break; // Stop once the key is found
                    }
                }
            }
            return (new String(keyText));
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            //getting keyStream
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            char[] keyStream = new char[cipherText.Length];
            int[] plainInt = new int[cipherText.Length];
            char[] plainText = new char[cipherText.Length];
            //string keyStreamString;
            // Generate the repeating key stream
            for (int i = 0; i < cipherText.Length; i++)
            {
                keyStream[i] = key[i % key.Length];
            }
            //Decryption

            for (int i = 0; i < cipherText.Length; i++)
            {
                plainInt[i] = (((char.ToUpper(cipherText[i])) - (char.ToUpper(keyStream[i])) + 26) % 26);
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                plainText[i] = (char)('A' + plainInt[i]);
            }

            return new String(plainText);
        }
        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            char[] keyStream = new char[plainText.Length];
            int[] cipherInt = new int[plainText.Length];
            char[] cipherText = new char[plainText.Length];
            // Generate the repeating key stream
            for (int i = 0; i < plainText.Length; i++)
            {
                keyStream[i] = key[i % key.Length];
            }
            //Encryption

            for (int i = 0; i < plainText.Length; i++)
            {
                cipherInt[i] = (((char.ToUpper(plainText[i])) - 'A') + (char.ToUpper(keyStream[i])) - 'A') % 26;

            }
            for (int i = 0; i < plainText.Length; i++)
            {
                cipherText[i] = (char)('A' + cipherInt[i]);
            }
            return new String(cipherText);
        }
    }
}