using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {

        public string Analyse(string plainText, string cipherText)
        {
            //  throw new NotImplementedException();
            string secretk = null,
                 encrypted = cipherText.ToLower(),
            englishletters = "abcdefghijklmnopqrstuvwxyz",
            blanksecretk = "                          ";
            char[] paragraph = plainText.ToCharArray();
            char[] secretks = blanksecretk.ToCharArray();
            //Remove duplicate letters from originalparagraph
            int j = 0;
            while (j < plainText.Length)
            {
                int z = j + 1;
                while (z < plainText.Length)
                {
                    if (paragraph[j] == paragraph[z])
                    {
                        paragraph[z] = ' ';
                    }
                    z++;
                }
                j++;
            }
            // Populate character array keye with encrypted text
            int k = 0;
            string fillerparagraph = null;
            while (k < paragraph.Length)
            {
                int mm = 0;
                while (mm < 26)
                {
                    if (paragraph[k] == englishletters[mm])
                    {
                        secretks[mm] = encrypted[k];
                        fillerparagraph += encrypted[k];
                        break;
                    }
                    mm++;
                }
                k++;
            }
            // Populate rest of slots in keye with letters
            int l = 0;
            while (l < 26)
            {
                if (secretks[l] == ' ')
                {
                    int z = 0;
                    while (z < 26)
                    {
                        if (!fillerparagraph.Contains(englishletters[z]))
                        {
                            secretks[l] = englishletters[z];
                            fillerparagraph += englishletters[z];
                            break;
                        }
                        z++;
                    }
                }
                l++;
            }
            // // Convert keye chars to string and obtain the last secretk
            int d = 0;
            while (d < 26)
            {
                secretk += secretks[d];
                d++;
            }

            return secretk;
        }


        public string Decrypt(string cipherText, string key)
        { // ensure all small
            string encrypted = cipherText.ToLower();

            //   throw new NotImplementedException();

            string originalparagraph = null;
            string englishletters = "abcdefghijklmnopqrstuvwxyz";
            int cnt = 0;
            while (cnt < encrypted.Length)
            {
                // Retrieve position of char of encrypted from secretk
                int o = 0;
                while (o < key.Length)
                {
                    if (key[o] == encrypted[cnt])
                    {
                        originalparagraph += englishletters[o];
                        break;
                    }
                    o++;
                }
                cnt++;
            }


            return originalparagraph;
        }

        public string Encrypt(string plainText, string key)
        {
            // ensure all small
            string original = plainText.ToUpper();
            int cnt = 0;
            //  throw new NotImplementedException();
            string encryptedparagraph = null;


            while (cnt < original.Length)
            {
                encryptedparagraph += key[((int)original[cnt] - 65)];
                cnt++;
            }
            return encryptedparagraph.ToUpper();

        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            // throw new NotImplementedException();
            int[] encryptedrepeat2 = new int[26];
            char[] repeatedletters = { 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w', 'y', 'b', 'v', 'k', 'x', 'j', 'q', 'z' };
            string originalparapgraph = null;
            char[] encryptedparagraph = cipher.ToLower().ToCharArray();
            int[] encryptedrepeat = new int[26];



            // get repition counter of chars in encrypted paragraph
            int letter = 'a';
            while (letter <= 'z')
            {
                int z = 0;
                int repetitioncount = 0;


                while (z < encryptedparagraph.Length)
                {
                    if (letter == encryptedparagraph[z])
                    {
                        repetitioncount++;
                    }
                    z++;
                }

                encryptedrepeat[((int)letter - 97)] = repetitioncount;
                encryptedrepeat2[((int)letter - 97)] = repetitioncount;

                letter++;
            }
            int j = 0;
            string paragraph = null;
            // Organize the frequency array in a top-down manner
            Array.Sort(encryptedrepeat2);
            Array.Reverse(encryptedrepeat2);
            //Retrieve the most frequent characters highest first

            while (j < 26)
            {
                int z = 0;
                while (z < 26)
                {
                    if ((encryptedrepeat2[j] == encryptedrepeat[z]))
                    {
                        paragraph += (char)(z + 97);
                        break;
                    }
                    z++;
                }
                j++;
            }

            // Associate characters and extract the plaintext
            j = 0;
            while (j < encryptedparagraph.Length)
            {
                int z = 0;
                while (z < 26)
                {
                    if (encryptedparagraph[j] == paragraph[z])
                    {
                        encryptedparagraph[j] = repeatedletters[z];
                        break;
                    }
                    z++;
                }
                j++;
            }

            // Change the char array to a string to reconstruct the original paragraph
            int v = 0;
            while (v < encryptedparagraph.Length)
            {
                originalparapgraph += encryptedparagraph[v];
                v++;
            }

            return originalparapgraph;
        }
    }
}
