using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string englishchars = "abcdefghijklmnopqrstuvwxyz";
        private int endl;

        public int chars(char c)
        {
            int y = 0;
            do
            {
                if (c == englishchars[y])
                {
                    return y;
                }
                y++;
            } while (y < 26);

            return -1;
        }

        public string Encrypt(string plainText, int key)
        {

            int x = 0;
            string encrypted = "";
            string original = plainText;
            string upperc = englishchars.ToUpper();
            do
            {
                if (char.IsLetter(original[x]))
                {
                    int completekey = (key + chars(original[x]));
                    int charposition = (completekey % 26);
                    encrypted += upperc[charposition];
                }
                else
                {
                    encrypted += original[x];
                }
                x++;
            } while (x < original.Length);

            return encrypted;
        }


        public string Decrypt(string cipherText, int key)
        {
            string original = "";
            int k = 0;


            string encrypted = cipherText.ToLower();
            while (k < encrypted.Length)
            {
                if (char.IsLetter(encrypted[k]))
                {
                    int completek = (chars(encrypted[k]) - key);
                    int charpos = (completek % 26);

                    for (; charpos < 0; charpos += 26) ;

                    original += englishchars[charpos];
                }
                else
                {
                    original += encrypted[k];
                }
                k++;
            }
            return original;
        }


        public int Analyse(string plainText, string cipherText)
        {
            int a = 20;
            string encrypted = cipherText;
            string original = plainText;
            if (original.Length != encrypted.Length)
            {
                return -1;
            }
            int b = 20;
            char firstencrypted = char.ToLower(encrypted[0]);
            char firstoriginal = original[0];
            int encryptedpos;
            int originalpos;
            int c = 20;
            encryptedpos = chars(firstencrypted);
            originalpos = chars(firstoriginal);
            int foundkey = (encryptedpos - originalpos);
            int d = 20;
            if (foundkey < 0)
            {
                return (foundkey) + 26;
            }
            else
            {
                return (foundkey) % 26;
            }
            
        }
    }
}