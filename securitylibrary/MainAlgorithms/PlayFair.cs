using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        private char[,] creategridplay(string secretk)
        {
            // delete spaces and repeated chars from secret k
            secretk = secretk.Replace(" ", "").ToLower();
            secretk = new string(secretk.Distinct().ToArray());

            // setup the grid with the secret k
            char[,] grid = new char[5, 5];
            int index = 0;
            int y = 0;
            int x = 0;


            // populate the grid with secret k
            while (index < secretk.Length)
            {
                grid[x, y] = secretk[index];
                y++;
                index++;
                if (y == 5)
                {
                    x++;
                    y = 0;
                }
            }

            // complete the grid by adding the leftover chars
            index = 0;
            string englishletters = "abcdefghiklmnopqrstuvwxyz";


            while (index < englishletters.Length)
            {
                char c = englishletters[index];
                if (!secretk.Contains(c))
                {
                    grid[x, y] = c;
                    y++;
                    if (y == 5)
                    {
                        x++;
                        y = 0;
                    }
                }
                index++;
            }

            return grid;
        }




        public string Decrypt(string encryptedparagraph, string key)
        {
            // create the gridplay matrix
            char[,] grid = creategridplay(key);

            // clean paragraph by keeping only letters and change  to small case 
            encryptedparagraph = new string(encryptedparagraph.Where(char.IsLetter).ToArray()).ToLower();

            // substitute any 'j'  with 'i'
            encryptedparagraph = encryptedparagraph.Replace("j", "i");

            // ensure even length of original paragraph by adding x if needed 
            if (encryptedparagraph.Length % 2 == 1)
            {
                encryptedparagraph += "x";
            }

            // Decrypt the encrypted paragraph two letters at a time 
            string originalparagraph = "";
            int t = 0;
            while (t < encryptedparagraph.Length)
            {
                char L1 = encryptedparagraph[t];
                char L2 = encryptedparagraph[t + 1];
                int rowone = 0, columnonepos = 0, rowtwo = 0, columntwopos = 0;

                // determine matrix coordinates of the two chars 
                int horizontal = 0;
                while (horizontal < 5)
                {
                    int vertical = 0;
                    while (vertical < 5)
                    {
                        if (grid[horizontal, vertical] == L1)
                        {
                            rowone = horizontal;
                            columnonepos = vertical;
                        }
                        if (grid[horizontal, vertical] == L2)
                        {
                            rowtwo = horizontal;
                            columntwopos = vertical;
                        }
                        vertical++;
                    }
                    horizontal++;
                }

                // process the chars based on their positions same horizontal R ,same vertical C or different   
                if (rowone == rowtwo)
                {
                    originalparagraph += grid[rowone, (columnonepos + 4) % 5];
                    originalparagraph += grid[rowtwo, (columntwopos + 4) % 5];
                }
                else if (columnonepos == columntwopos)
                {
                    originalparagraph += grid[(rowone + 4) % 5, columnonepos];
                    originalparagraph += grid[(rowtwo + 4) % 5, columntwopos];
                }
                else
                {
                    originalparagraph += grid[rowone, columntwopos];
                    originalparagraph += grid[rowtwo, columnonepos];
                }

                t += 2;
            }

            // Strip out any inserted 'x' characters placed between repeated letters
            string original = originalparagraph;
            if (originalparagraph[originalparagraph.Length - 1] == 'x')
            {
                original = original.Remove(originalparagraph.Length - 1);
            }
            int z = 0;
            int y = 0;
            while (y < original.Length)
            {
                if (originalparagraph[y] == 'x')
                {
                    if (originalparagraph[y - 1] == originalparagraph[y + 1])
                    {
                        if (y + z < original.Length && (y - 1) % 2 == 0)
                        {
                            original = original.Remove(y + z, 1);
                            z--;
                        }
                    }
                }
                y++;
            }

            return original;
        }



        public string Encrypt(string originalparagraph, string key)
        {
            //  creategridplay
            char[,] grid = creategridplay(key);

            // Sanitize the text by keeping only letters and change to smallcase
            originalparagraph = new string(originalparagraph.Where(char.IsLetter).ToArray()).ToLower();

            // Insert x between repeated consecutive letters
            int j = 0;
            while (j < originalparagraph.Length - 1)
            {
                if (originalparagraph[j] == originalparagraph[j + 1])
                {
                    originalparagraph = originalparagraph.Insert(j + 1, "x");
                }
                j += 2;
            }

            // Ensure an evenlength of originalparagraph by adding x if needed
            if (originalparagraph.Length % 2 == 1)
            {
                originalparagraph += "x";
            }

            // Encrypt originalparagrahw
            j = 0;
            string encryptedparagraph = "";

            while (j < originalparagraph.Length - 1)
            {
                char l1 = originalparagraph[j];
                char l2 = originalparagraph[j + 1];
                int encrypt1pos = 0;
                int encrypt2pos = 0;
                int x2 = 0;
                int x1 = 0;


                // Determine the matrix coordinates for each char
                int horizontalline = 0;
                while (horizontalline < 5)
                {
                    int verticalC = 0;
                    while (verticalC < 5)
                    {
                        if (grid[horizontalline, verticalC] == l1)
                        {
                            x1 = horizontalline;
                            encrypt1pos = verticalC;
                        }
                        if (grid[horizontalline, verticalC] == l2)
                        {
                            x2 = horizontalline;
                            encrypt2pos = verticalC;
                        }
                        verticalC++;
                    }
                    horizontalline++;
                }

                // Process the chars based on their positions same horizontalR , same verticalC, or different.
                if (x1 == x2)
                {
                    encryptedparagraph += grid[x1, (encrypt1pos + 1) % 5];
                    encryptedparagraph += grid[x2, (encrypt2pos + 1) % 5];
                }
                else if (encrypt1pos == encrypt2pos)
                {
                    encryptedparagraph += grid[(x1 + 1) % 5, encrypt1pos];
                    encryptedparagraph += grid[(x2 + 1) % 5, encrypt2pos];
                }
                else
                {
                    encryptedparagraph += grid[x1, encrypt2pos];
                    encryptedparagraph += grid[x2, encrypt1pos];
                }

                j += 2;
            }

            return encryptedparagraph;
        }

        public string Analyse(string largeCipher)
        {
            throw new NotImplementedException();
        }
    }
}
