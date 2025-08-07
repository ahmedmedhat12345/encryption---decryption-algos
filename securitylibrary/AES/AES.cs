using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        static readonly string[] SBox = new string[]
 {
    "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76",
    "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0",
    "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15",
    "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75",
    "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84",
    "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF",
    "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8",
    "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2",
    "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73",
    "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB",
    "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79",
    "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08",
    "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A",
    "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E",
    "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF",
    "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"
 };
        static readonly string[] InvSBox = new string[]
        {
    "52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB",
    "7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB",
    "54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E",
    "08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25",
    "72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92",
    "6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84",
    "90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06",
    "D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B",
    "3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73",
    "96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E",
    "47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B",
    "FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4",
    "1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F",
    "60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF",
    "A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61",
    "17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D"
        };
        static readonly string[] Rcon = new string[] { "01", "02", "04", "08", "10", "20", "40", "80", "1B", "36" };

        static int HexToNumber(string hex)
        {
            hex = hex.ToUpper();
            int result = 0;
            for (int i = 0; i < hex.Length; i++)
            {
                result = result * 16;
                char c = hex[i];
                if (c >= '0' && c <= '9')
                    result = result + (c - '0');
                if (c >= 'A' && c <= 'F')
                    result = result + (c - 'A' + 10);
            }
            return result;
        }

        static string NumberToHex(int value)
        {
            if (value < 0)
                value = value + 256;
            if (value >= 256)
                value = value - 256;
            string hex = "";
            int first = value / 16;
            int second = value % 16;
            if (first >= 0 && first <= 9)
                hex = hex + (char)('0' + first);
            if (first >= 10 && first <= 15)
                hex = hex + (char)('A' + first - 10);
            if (second >= 0 && second <= 9)
                hex = hex + (char)('0' + second);
            if (second >= 10 && second <= 15)
                hex = hex + (char)('A' + second - 10);
            return hex;
        }

        static string HexXor(string a, string b)
        {
            int aNum = HexToNumber(a);
            int bNum = HexToNumber(b);
            int result = 0;
            for (int i = 0; i < 8; i++)
            {
                int aBit = GetBit(aNum, i);
                int bBit = GetBit(bNum, i);
                if (aBit != bBit)
                    result = SetBit(result, i);
            }
            return NumberToHex(result);
        }

        static int GetBit(int num, int position)
        {
            return (num / (int)Math.Pow(2, position)) % 2;
        }

        static int SetBit(int num, int position)
        {
            return num + (int)Math.Pow(2, position);
        }

        static string MultiplyBy2(string x)
        {
            int num = HexToNumber(x);
            int msb = GetBit(num, 7);
            num = num * 2;
            if (msb == 1)
                num = AddInGF(num, HexToNumber("1B"));
            return NumberToHex(num);
        }

        static int AddInGF(int a, int b)
        {
            int result = 0;
            for (int i = 0; i < 8; i++)
            {
                int aBit = GetBit(a, i);
                int bBit = GetBit(b, i);
                if (aBit != bBit)
                    result = SetBit(result, i);
            }
            return result;
        }

        static string Gf(string a, string b)
        {
            int bVal = HexToNumber(b);
            int result = 0;

            switch (a.ToUpper())
            {
                case "01":
                    result = bVal;
                    break;
                case "02":
                    result = HexToNumber(MultiplyBy2(b));
                    break;
                case "03":
                    result = AddInGF(HexToNumber(MultiplyBy2(b)), bVal);
                    break;
                case "09":
                    result = AddInGF(HexToNumber(MultiplyBy2(MultiplyBy2(MultiplyBy2(b)))), bVal);
                    break;
                case "0B":
                    result = AddInGF(
                        AddInGF(HexToNumber(MultiplyBy2(MultiplyBy2(MultiplyBy2(b)))),
                                HexToNumber(MultiplyBy2(b))),
                        bVal);
                    break;
                case "0D":
                    result = AddInGF(
                        AddInGF(HexToNumber(MultiplyBy2(MultiplyBy2(MultiplyBy2(b)))),
                                HexToNumber(MultiplyBy2(MultiplyBy2(b)))),
                        bVal);
                    break;
                case "0E":
                    result = AddInGF(
                        AddInGF(HexToNumber(MultiplyBy2(MultiplyBy2(MultiplyBy2(b)))),
                                HexToNumber(MultiplyBy2(MultiplyBy2(b)))),
                        HexToNumber(MultiplyBy2(b)));
                    break;
                default:
                    throw new ArgumentException("Unsupported multiplier for AES GF multiplication");
            }

            return NumberToHex(result);
        }

        static string RotWord(string word)
        {
            return word.Substring(2, 6) + word.Substring(0, 2);
        }

        static string SubWord(string word)
        {
            string result = "";
            for (int i = 0; i < 4; i++)
            {
                string hex = word.Substring(i * 2, 2);
                int index = HexToNumber(hex);
                result = result + SBox[index];
            }
            return result;
        }

        static void SubBytes(string[,] state)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int index = HexToNumber(state[i, j]);
                    state[i, j] = SBox[index];
                }
            }
        }

        static void ShiftRows(string[,] state)
        {
            int shifts = 0;
            string[,] temp = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int new_col = (j + shifts) % 4;
                    temp[i, j] = state[i, new_col];
                }
                shifts++;
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i, j] = temp[i, j];
                }
            }
        }

        public static void MixColumns(string[,] state)
        {
            string[,] matrix = new string[,]
            {
        { "02", "03", "01", "01" },
        { "01", "02", "03", "01" },
        { "01", "01", "02", "03" },
        { "03", "01", "01", "02" }
            };
            string[,] result = new string[4, 4];
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    string sum = "00";
                    for (int i = 0; i < 4; i++)
                    {
                        string product = Gf(matrix[row, i], state[i, col]);
                        sum = HexXor(sum, product);
                    }
                    result[row, col] = sum;
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i, j] = result[i, j];
                }
            }
        }

        static void InverseSubBytes(string[,] state)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int index = HexToNumber(state[i, j]);
                    state[i, j] = InvSBox[index];
                }
            }
        }

        static void InverseShiftRows(string[,] state)
        {
            int shifts = 0;
            string[,] temp = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int new_col = (j + shifts) % 4;
                    temp[i, new_col] = state[i, j];
                }
                shifts++;
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i, j] = temp[i, j];
                }
            }
        }

        static void InverseMixColumns(string[,] state)
        {
            string[,] matrix = new string[,]
            {
        { "0E", "0B", "0D", "09" },
        { "09", "0E", "0B", "0D" },
        { "0D", "09", "0E", "0B" },
        { "0B", "0D", "09", "0E" }
            };
            string[,] result = new string[4, 4];
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    string sum = "00";
                    for (int i = 0; i < 4; i++)
                    {
                        string product = Gf(matrix[row, i], state[i, col]);
                        sum = HexXor(sum, product);
                    }
                    result[row, col] = sum;
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i, j] = result[i, j];
                }
            }
        }

        static string[] KeyExpansion(string key)
        {
            string[] roundKeys = new string[44];
            for (int i = 0; i < 4; i++)
            {
                roundKeys[i] = key.Substring(i * 8, 8);
            }
            for (int i = 4; i < 44; i++)
            {
                string temp = roundKeys[i - 1];
                if (i % 4 == 0)
                {
                    temp = RotWord(temp);
                    temp = SubWord(temp);
                    string firstByte = HexXor(temp.Substring(0, 2), Rcon[i / 4 - 1]);
                    temp = firstByte + temp.Substring(2);
                }
                string prev = roundKeys[i - 4];
                string result = "";
                for (int j = 0; j < 4; j++)
                {
                    string bytePrev = prev.Substring(j * 2, 2);
                    string byteTemp = temp.Substring(j * 2, 2);
                    result = result + HexXor(bytePrev, byteTemp);
                }
                roundKeys[i] = result;
            }
            return roundKeys;
        }

        static void AddRoundKey(string[,] state, string[] roundKeys, int round)
        {
            string keyBytes = roundKeys[round * 4] + roundKeys[round * 4 + 1] +
                              roundKeys[round * 4 + 2] + roundKeys[round * 4 + 3];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int index = (i + j * 4) * 2;
                    string keyByte = keyBytes.Substring(index, 2);
                    state[i, j] = HexXor(state[i, j], keyByte);
                }
            }
        }

        public override string Decrypt(string ciphertext, string key)
        {
            if (ciphertext.Length >= 2)
            {
                if (ciphertext[0] == '0' && (ciphertext[1] == 'x' || ciphertext[1] == 'X'))
                    ciphertext = ciphertext.Substring(2);
            }
            if (key.Length >= 2)
            {
                if (key[0] == '0' && (key[1] == 'x' || key[1] == 'X'))
                    key = key.Substring(2);
            }
            if (ciphertext.Length != 32)
                return "Error: Ciphertext must be 32 hex characters (after removing 0x)!";
            if (key.Length != 32)
                return "Error: Key must be 32 hex characters (after removing 0x)!";
            string upperCipher = ciphertext.ToUpper();
            string upperKey = key.ToUpper();
            for (int i = 0; i < 32; i++)
            {
                char c = upperCipher[i];
                if ((c < '0' || c > '9') && (c < 'A' || c > 'F'))
                    return "Error: Ciphertext must be hex (0-9, A-F)!";
                c = upperKey[i];
                if ((c < '0' || c > '9') && (c < 'A' || c > 'F'))
                    return "Error: Key must be hex (0-9, A-F)!";
            }
            string[] roundKeys = KeyExpansion(upperKey);
            string[,] state = new string[4, 4];
            for (int i = 0; i < 16; i++)
            {
                state[i % 4, i / 4] = upperCipher.Substring(i * 2, 2);
            }
            AddRoundKey(state, roundKeys, 10);
            for (int round = 9; round >= 1; round--)
            {
                InverseShiftRows(state);
                InverseSubBytes(state);
                AddRoundKey(state, roundKeys, round);
                InverseMixColumns(state);
            }
            InverseShiftRows(state);
            InverseSubBytes(state);
            AddRoundKey(state, roundKeys, 0);
            string result = "";
            for (int i = 0; i < 16; i++)
            {
                result = result + state[i % 4, i / 4];
            }
            return "0x" + result;
        }

        public override string Encrypt(string plaintext, string key)
        {
            if (plaintext.Length >= 2)
            {
                if (plaintext[0] == '0' && (plaintext[1] == 'x' || plaintext[1] == 'X'))
                    plaintext = plaintext.Substring(2);
            }
            if (key.Length >= 2)
            {
                if (key[0] == '0' && (key[1] == 'x' || key[1] == 'X'))
                    key = key.Substring(2);
            }
            if (plaintext.Length != 32)
                return "Error: Plaintext must be 32 hex characters (after removing 0x)!";
            if (key.Length != 32)
                return "Error: Key must be 32 hex characters (after removing 0x)!";
            string upperPlain = plaintext.ToUpper();
            string upperKey = key.ToUpper();
            for (int i = 0; i < 32; i++)
            {
                char c = upperPlain[i];
                if ((c < '0' || c > '9') && (c < 'A' || c > 'F'))
                    return "Error: Plaintext must be hex (0-9, A-F)!";
                c = upperKey[i];
                if ((c < '0' || c > '9') && (c < 'A' || c > 'F'))
                    return "Error: Key must be hex (0-9, A-F)!";
            }
            string[] roundKeys = KeyExpansion(upperKey);
            string[,] state = new string[4, 4];
            for (int i = 0; i < 16; i++)
            {
                state[i % 4, i / 4] = upperPlain.Substring(i * 2, 2);
            }
            AddRoundKey(state, roundKeys, 0);
            for (int round = 1; round <= 9; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, roundKeys, round);
            }
            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, roundKeys, 10);
            string result = "";
            for (int i = 0; i < 16; i++)
            {
                result = result + state[i % 4, i / 4];
            }
            return "0x" + result;
        }
    }
}
