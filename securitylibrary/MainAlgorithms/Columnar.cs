using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            int col = 0;
            List<int> Key = new List<int>();
            for (int l = 3; l <= 7; l++)
            {
                List<string> rownames_cipher = Enumerable.Repeat("", 15).ToList();
                List<string> columnnames_plain = Enumerable.Repeat("", 15).ToList();
                List<string> test = Enumerable.Repeat("", 15).ToList();
                Key = new List<int>();
                col = l;
                int count = 0;
                //#rows is cipherext.Length/col
                int rows = plainText.Length / col;
                for (int k = 0; k < col; k++)
                {
                    if (count < cipherText.Length)
                    {
                        //cti,psc,oee,mrn,uce
                        for (int j = count; j < count + rows; j++)
                        {
                            rownames_cipher[k] += cipherText[j];
                        }
                        count += rows;

                    }
                }


                for (int i = 0; i < col; i++)
                {
                    count = 0;
                    for (int j = 0; j < rows; j++)
                    {
                        columnnames_plain[i] += plainText[count + i];
                        count += col;
                    }

                }
                int J = 0;
                string cipher = "";
                foreach (string x in columnnames_plain)
                {
                    if (J < col)
                    {
                        int index = rownames_cipher.FindIndex(n => n.Equals(x, StringComparison.InvariantCultureIgnoreCase));
                        if (index >= 0)
                        {
                            test[index] = x;
                        }
                        Key.Add(index + 1);
                    }
                    J++;
                }

                foreach (string x in test)
                {
                    cipher += x;
                }

                if (cipher.Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
                {
                    break;
                }

            }
            return Key;

        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int size = key.Count();
            int index = 0;
            char[,] arr = new char[size, size];
            int rows = cipherText.Length % size == 0 ? cipherText.Length / size : (cipherText.Length / size) + 1;
            for (int i = 0; i < size; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    if (index < cipherText.Length)
                    {
                        arr[i, j] = cipherText[index];
                        index++;
                    }
                }
            }
            string plainText = "";
            int count = 0, x = 0;
            char[,] original_arr = new char[size, size];
            while (count < size)
            {
                for (int i = 0; i < size; i++)
                {
                    if (count + 1 == key[i])
                    {
                        x = i;
                        break;
                    }
                }
                for (int i = 0; i < size; i++)
                {
                    original_arr[i, x] = arr[count, i];
                }

                count++;

            }
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    if (!(original_arr[i, j].Equals('x')))
                    {
                        plainText += original_arr[i, j];
                    }
                }
            }
            return plainText;


        }



        public string Encrypt(string plainText, List<int> key)
        {

            int size = key.Count();
            int rows = plainText.Length % size == 0 ? plainText.Length / size : (plainText.Length / size) + 1;
            char[,] arr = new char[size, size];
            int index = 0;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < size; j++)
                {
                    if (index < plainText.Length)
                    {
                        arr[i, j] = plainText[index];
                        index++;
                    }
                    else
                    {
                        arr[i, j] = 'x';
                    }
                }
            }

            string CipherdText = "";
            int count = 0;
            while (count < size)
            {
                int x = 0;
                for (int k = 0; k < size; k++)
                {
                    if (count == key[k] - 1)
                    {
                        x = k;
                        break;
                    }
                }
                for (int i = 0; i < rows; i++)
                {
                    CipherdText += arr[i, x];
                }
                count++;
            }
            return CipherdText;
        }

    }

}
