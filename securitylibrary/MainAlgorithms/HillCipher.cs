using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

public class HillCipher
{
    public class InvalidAnlysisException : Exception
    {
        public InvalidAnlysisException(string message) : base(message)
        {
        }

    }
    public List<int> Encrypt(List<int> plainText, List<int> key)
    {
        List<int> final_word = new List<int>();
        int size = Convert.ToInt32(Math.Sqrt(key.Count));
        int[,] matrix = new int[size, size];

        int count = 0;
        for (int i = 0; i < size; i++)
        {
            for (int j = 0; j < size; j++)
            {
                matrix[i, j] = key[count];
                count++;
            }
        }

        int reset = 0;
        int[,] text = new int[size, 1];

        for (int i = 0; i < plainText.Count; i++)
        {
            text[reset, 0] = plainText[i];

            if (i == plainText.Count - 1)
            {
                while (reset <= size - 2)
                {
                    text[reset + 1, 0] = 0; // Padding with zeroes
                    reset++;
                }
            }

            if (reset == size - 1)
            {
                int[] arr2 = new int[size];

                for (int x = 0; x < size; x++)
                {
                    arr2[x] = text[x, 0];
                }

                for (int j = 0; j < size; j++)
                {
                    int res = 0;
                    for (int k = 0; k < size; k++)
                    {
                        res += matrix[j, k] * arr2[k];
                    }

                    res %= 26;
                    final_word.Add(res);
                }
                reset = 0;
            }
            else
            {
                reset++;
            }
        }

        return final_word;
    }

    public List<int> Decrypt(List<int> cipherText, List<int> key)
    {
        List<int> final_word = new List<int>();
        int MatSize = Convert.ToInt32(Math.Sqrt(key.Count));

        // Compute determinant
        int deter = 0;
        if (MatSize == 2)
        {
            deter = (key[0] * key[3]) - (key[1] * key[2]);
        }
        else if (MatSize == 3)
        {
            deter = key[0] * (key[4] * key[8] - key[5] * key[7])
                  - key[1] * (key[3] * key[8] - key[5] * key[6])
                  + key[2] * (key[3] * key[7] - key[4] * key[6]);
        }

        deter %= 26;
        if (deter < 0) deter += 26;

        int modInverse = ModularInverse(deter, 26);

        // Compute cofactor matrix
        List<int> cofactorMatrix = new List<int>();
        for (int i = 0; i < key.Count; i++)
        {
            int row = i / MatSize;
            int col = i % MatSize;
            List<int> minor;
            if (MatSize == 2)
            {
                minor = new List<int>(MatSize - 1);
            }
            else
            {
                minor = new List<int>(MatSize + 1);
            }

            for (int j = 0; j < key.Count; j++)
            {
                if (j / MatSize == row || j % MatSize == col)
                    continue;
                minor.Add(key[j]);
            }

            int determinant;
            if (key.Count == 4)
            {
                determinant = minor[0];
            }
            else
            {
                determinant = (minor[0] * minor[3]) - (minor[1] * minor[2]);
            }
            int signedCofactor = determinant * (int)Math.Pow(-1, row + col);
            cofactorMatrix.Add(signedCofactor);
        }

        // Compute adjugate (transpose of cofactor matrix)
        List<int> adjugate = new List<int>(new int[cofactorMatrix.Count]);
        for (int i = 0; i < MatSize; i++)
        {
            for (int j = 0; j < MatSize; j++)
            {
                adjugate[(i * MatSize) + j] = cofactorMatrix[(j * MatSize) + i];
            }
        }

        // Multiply by modular inverse
        for (int i = 0; i < adjugate.Count; i++)
        {
            adjugate[i] = (adjugate[i] * modInverse) % 26;
            if (adjugate[i] < 0) adjugate[i] += 26;
        }

        // Decrypt the ciphertext
        int reset = 0;
        int[,] text = new int[MatSize, 1];

        for (int i = 0; i < cipherText.Count; i++)
        {
            text[reset, 0] = cipherText[i];

            if (i == cipherText.Count - 1)
            {
                while (reset <= MatSize - 2)
                {
                    text[reset + 1, 0] = 0;
                    reset++;
                }
            }

            if (reset == MatSize - 1)
            {
                int[] arr2 = new int[MatSize];

                for (int x = 0; x < MatSize; x++)
                {
                    arr2[x] = text[x, 0];
                }

                for (int j = 0; j < MatSize; j++)
                {
                    int res = 0;
                    for (int k = 0; k < MatSize; k++)
                    {
                        res += adjugate[j * MatSize + k] * arr2[k];
                    }

                    res %= 26;
                    final_word.Add(res);
                }

                reset = 0;
            }
            else
            {
                reset++;
            }
        }

        return final_word;
    }

    public static int ModularInverse(int a, int mod)
    {
        int m0 = mod, t, q;
        int x0 = 0, x1 = 1;

        if (mod == 1) return 0; // No inverse exists

        while (a > 1)
        {
            q = a / mod;
            t = mod;

            // Update mod and a
            mod = a % mod;
            a = t;
            t = x0;

            // Update x0 and x1
            x0 = x1 - q * x0;
            x1 = t;
        }
        return x1; // This allows negative values
    }
    public static int GCD(int a, int b)
    {
        return b == 0 ? a : GCD(b, a % b);
    }

    public List<int> Analyse(List<int> plainText, List<int> cipherText)
    {
        // Check if plainText and cipherText have the same length and are non-empty
        if (plainText.Count != cipherText.Count || plainText.Count == 0)
            throw new InvalidAnlysisException("Plaintext and ciphertext must have the same length and be non-empty.");

        // Iterate through the plaintext and ciphertext in blocks of 4 elements
        for (int i = 0; i <= plainText.Count - 4; i++)
        {
            // Extract a 4-element block from plaintext and ciphertext
            List<int> plainBlock = plainText.GetRange(i, 4);
            List<int> cipherBlock = cipherText.GetRange(i, 4);

            try
            {
                List<int> key = AnalyseBlock(plainBlock, cipherBlock);
                return key;
            }
            catch (InvalidAnlysisException)
            {
                continue;
            }
        }

        throw new SecurityLibrary.InvalidAnlysisException("No valid 4-element block found to recover the key.");
    }

    private static List<int> AnalyseBlock(List<int> plainBlock, List<int> cipherBlock)
    {
        // Construct the plaintext matrix P
        int[,] P = new int[2, 2];
        P[0, 0] = plainBlock[0];
        P[1, 0] = plainBlock[1];
        P[0, 1] = plainBlock[2];
        P[1, 1] = plainBlock[3];

        // Compute the determinant of P
        int detP = (P[0, 0] * P[1, 1]) - (P[0, 1] * P[1, 0]);
        detP = detP % 26;
        if (detP < 0) detP += 26;

        // Console.WriteLine(detP);

        if (detP == 0)
            throw new InvalidAnlysisException("Plaintext matrix is not invertible.");
        int gcd = GCD(detP, 26);
        if (gcd != 1)
        {
            throw new InvalidAnlysisException($"Plaintext matrix is not invertible. gcd({detP}, 26) = {gcd}");
        }

        int modInverse = ModularInverse(detP, 26);
        // Compute the inverse of P
        int[,] PInv = new int[2, 2];
        PInv[0, 0] = (P[1, 1] * modInverse) % 26;
        PInv[1, 1] = (P[0, 0] * modInverse) % 26;
        PInv[0, 1] = (-P[0, 1] * modInverse) % 26;
        PInv[1, 0] = (-P[1, 0] * modInverse) % 26;

        // Ensure all values in the inverse matrix are non-negative
        for (int i = 0; i < 2; i++)
        {
            for (int j = 0; j < 2; j++)
            {
                if (PInv[i, j] < 0)
                    PInv[i, j] += 26;
            }
        }

        // Construct the ciphertext matrix C
        int[,] C = new int[2, 2];
        C[0, 0] = cipherBlock[0];
        C[1, 0] = cipherBlock[1];
        C[0, 1] = cipherBlock[2];
        C[1, 1] = cipherBlock[3];

        // Compute the key matrix K = C * PInv
        int[,] K = new int[2, 2];
        for (int i = 0; i < 2; i++)
        {
            for (int j = 0; j < 2; j++)
            {
                K[i, j] = 0;
                for (int k = 0; k < 2; k++)
                {
                    K[i, j] += C[i, k] * PInv[k, j];
                }
                K[i, j] = K[i, j] % 26;
                if (K[i, j] < 0)
                    K[i, j] += 26;
            }
        }

        // Flatten the key matrix into a list
        List<int> key = new List<int>
    {
        K[0, 0],
        K[0, 1],
        K[1, 0],
        K[1, 1]
    };

        return key;
    }

    public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
    {
        throw new NotImplementedException();
    }
    public static void Main(string[] args)
    {
        List<int> plain = new List<int> { 6, 24, 1, 13, 16, 10, 20, 17 };
        List<int> cipher = new List<int> { 8, 5, 10, 21, 21, 8, 19, 24 };


        HillCipher hillCipher = new HillCipher();
        List<int> t;

        try
        {
            t = hillCipher.Analyse(cipher, plain);
            Console.WriteLine
                ("recoverd key: " + string.Join(" ", t));
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }
    }

}