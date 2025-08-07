using System;
using System.Collections.Generic;
using System.Linq;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        int[,] bsubistions =
{
            {
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
            },
            {
                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
            },
            {
                10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
            },
            {
                7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
            },
            {
                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
            },
            {
                12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
            },
            {
                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
            },
            {
                13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
            }
        };
        char hexaConversion(string binaryBits)
        {
            if (binaryBits == "0000")
                return '0';
            else if (binaryBits == "0001")
                return '1';
            else if (binaryBits == "0010")
                return '2';
            else if (binaryBits == "0011")
                return '3';
            else if (binaryBits == "0100")
                return '4';
            else if (binaryBits == "0101")
                return '5';
            else if (binaryBits == "0110")
                return '6';
            else if (binaryBits == "0111")
                return '7';
            else if (binaryBits == "1000")
                return '8';
            else if (binaryBits == "1001")
                return '9';
            else if (binaryBits == "1010")
                return 'A';
            else if (binaryBits == "1011")
                return 'B';
            else if (binaryBits == "1100")
                return 'C';
            else if (binaryBits == "1101")
                return 'D';
            else if (binaryBits == "1110")
                return 'E';
            else
                return 'F';
        }
        int binary4BitToDecimal(string binaryValue)
        {
            if (binaryValue == "0000")
                return 0;
            else if (binaryValue == "0001")
                return 1;
            else if (binaryValue == "0010")
                return 2;
            else if (binaryValue == "0011")
                return 3;
            else if (binaryValue == "0100")
                return 4;
            else if (binaryValue == "0101")
                return 5;
            else if (binaryValue == "0110")
                return 6;
            else if (binaryValue == "0111")
                return 7;
            else if (binaryValue == "1000")
                return 8;
            else if (binaryValue == "1001")
                return 9;
            else if (binaryValue == "1010")
                return 10;
            else if (binaryValue == "1011")
                return 11;
            else if (binaryValue == "1100")
                return 12;
            else if (binaryValue == "1101")
                return 13;
            else if (binaryValue == "1110")
                return 14;
            else
                return 15;
        }

        int binaryToDecimal(string binaryString)
        {
            if (binaryString == "00")
            {
                return 0;
            }
            else if (binaryString == "10")
            {
                return 2;
            }
            else if (binaryString == "01")
            {
                return 1;
            }
            else
            {
                return 3;
            }
        }

        char xorOperation(char bit1, char bit2)
        {
            switch (bit1)
            {
                case '0':
                    switch (bit2)
                    {
                        case '1': return '1';
                        default: return '0';
                    }
                    break;

                case '1':
                    switch (bit2)
                    {
                        case '0': return '1';
                        default: return '0';
                    }
                    break;

                default:
                    return '0';
            }
        }

        int[] InverseTableofintialpermutation =
      {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };
        int[] matrixofpermutation =
              {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
        };



        int[] Tableofextenstion =
        {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };

        int[] permutudInput =
         {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };
        int[] orderingoption2 =
    {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };//p_c2



        int[] orderingoption1 =
        {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };//p_c1
        string[] zerosandonesconversion =
        {
            "0000","0001","0010","0011","0100","0101","0110","0111",
            "1000","1001","1010","1011","1100","1101","1110","1111"
        };

        int[] rotationschedule = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };







        public override string Encrypt(string plainText, string key)
        {
            string binary; int m = 0;
            int l = 0;
            string encryptedtext = String.Empty;
            int f = 2;

            StringBuilder extendedrighthalf;
            int h = 0;
            StringBuilder xoroperationoutcome;
            int d = 0;
            StringBuilder outcomeofpermutation;


            int position;
            int v = 2;
            StringBuilder key01 = new StringBuilder();
            int n = 1;
            StringBuilder outcomeofsbox;
            int segment;
            //switch key to  binarystring 

            int o = 0;//

            do
            {
                key01.Append(zerosandonesconversion[int.Parse(key[f].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
                f++;
            } while (f < key.Length);


            //ordering option1
            StringBuilder keyofpermutationchoice1 = new StringBuilder();

            do
            {
                keyofpermutationchoice1.Append(key01[orderingoption1[o] - 1]);
                o++;
            } while (o < orderingoption1.Length);
            //permutation choice1

            //compute righthalf and lefthalf 
            string[] lefttKeyHalf = new string[17];
            lefttKeyHalf[0] = keyofpermutationchoice1.ToString().Substring(28, 28);
            string[] RightKeyHalf = new string[17];
            RightKeyHalf[0] = keyofpermutationchoice1.ToString().Substring(0, 28);
            string leftKeyHalfshifted = lefttKeyHalf[0];
            char finalBit;
            string RightKeyHalfshifted = RightKeyHalf[0];

            for (m = 0; m < 16; m++)
            {
                for (int j = 0; j < rotationschedule[m]; j++)
                {
                    finalBit = RightKeyHalfshifted[0];
                    RightKeyHalfshifted = RightKeyHalfshifted.Remove(0, 1);
                    RightKeyHalfshifted += finalBit;

                    finalBit = leftKeyHalfshifted[0];
                    leftKeyHalfshifted = leftKeyHalfshifted.Remove(0, 1);
                    leftKeyHalfshifted += finalBit;
                }
                RightKeyHalf[m + 1] = RightKeyHalfshifted;
                lefttKeyHalf[m + 1] = leftKeyHalfshifted;
            }


            //compute subkey
            string[] arraykey = new string[16];
            StringBuilder[] sessionkey = new StringBuilder[16];
            int len = arraykey.Length;
            do
            {
                arraykey[l] = RightKeyHalf[l + 1] + lefttKeyHalf[l + 1];
                l++;
            } while (l < len);

            //orderingoption2


            for (int i = 0; i < len; i++)
            {
                sessionkey[i] = new StringBuilder();
                int j = 0;
                while (j < orderingoption2.Length)
                {
                    sessionkey[i].Append(arraykey[i][orderingoption2[j] - 1]);
                    j++;
                }
            }//permuationchoice2

            //enciphering begining 
            StringBuilder originaltxt01format = new StringBuilder();
            StringBuilder firstPermutation = new StringBuilder();

            //switch original txtto array of binary values


            do
            {
                originaltxt01format.Append(zerosandonesconversion[int.Parse(plainText[v].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
                v++;
            } while (v < key.Length);


            //firstpermutation


            for (d = 0; d < permutudInput.Length; d++)
            {
                firstPermutation.Append(originaltxt01format[permutudInput[d] - 1]);
            }


            //compute righthalf and lefthalf
            string[] right = new string[17];
            right[0] = firstPermutation.ToString().Substring(32, 32);
            string[] left = new string[17];
            left[0] = firstPermutation.ToString().Substring(0, 32);



            //Iterate for sixteen times
            for (n = 1; n < 17; n++)
            {
                extendedrighthalf = new StringBuilder();
                left[n] = right[n - 1];
                outcomeofpermutation = new StringBuilder();
                xoroperationoutcome = new StringBuilder();
                int uu = 0;
                int permindex = 0;
                int index = 0;
                outcomeofsbox = new StringBuilder();
                //right half Bit expansion 
                int qq = 0;
                while (uu < Tableofextenstion.Length)
                {
                    extendedrighthalf.Append(right[n - 1][Tableofextenstion[uu] - 1]);
                    uu++;
                }
                // perform XOR between expanded Ri and Ki
                int k = 0;
                while (qq < extendedrighthalf.Length)
                {
                    xoroperationoutcome.Append(xorOperation(extendedrighthalf[qq], sessionkey[n - 1][qq]));
                    qq++;
                }

                // perform boxestransformation

                do
                {
                    binary = xoroperationoutcome.ToString().Substring(6 * k, 6);
                    segment = binaryToDecimal(binary[0] + string.Empty + binary[5]);
                    position = binary4BitToDecimal(binary.Substring(1, 4));
                    outcomeofsbox.Append(zerosandonesconversion[bsubistions[k, (segment * 16) + position]]);
                    k++;
                } while (k < 8);//substitutionbox

                //perform ordering

                while (permindex < matrixofpermutation.Length)
                {
                    outcomeofpermutation.Append(outcomeofsbox[matrixofpermutation[permindex] - 1]);
                    permindex++;
                }//premutation

                // Determine the value of Ri

                xoroperationoutcome = new StringBuilder();

                while (index < outcomeofpermutation.Length)
                {
                    xoroperationoutcome.Append(xorOperation(left[n - 1][index], outcomeofpermutation[index]));
                    index++;
                }

                right[n] = xoroperationoutcome.ToString();
            }
            StringBuilder encryptedtxt01format = new StringBuilder();
            string left16bitright16bit = right[16] + left[16];

            //  Perform the (P⁻¹) inverse permutation 
            int s = 0;
            encryptedtext += "0x";
            while (s < InverseTableofintialpermutation.Length)
            {
                encryptedtxt01format.Append(left16bitright16bit[InverseTableofintialpermutation[s] - 1]);
                s++;
            }
            //hex format result

            for (h = 0; h < 16; h++)
            {
                encryptedtext += hexaConversion(encryptedtxt01format.ToString().Substring(4 * h, 4));
            }

            return encryptedtext;
        }
        public override string Decrypt(string cipherText, string key)
        {
            int k = 2;
            //transfrom secretk to binary
            StringBuilder secretkzerosandones = new StringBuilder();
            string originalparagraph = String.Empty;
            originalparagraph += "0x";




            while (k < key.Length)
            {
                secretkzerosandones.Append(zerosandonesconversion[int.Parse(key[k].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
                k++;
            }

            //  do orderingoption1
            StringBuilder orderingoption1 = new StringBuilder();
            for (int x = 0; x < this.orderingoption1.Length; x++)
            {
                orderingoption1.Append(secretkzerosandones[this.orderingoption1[x] - 1]);
            }
            int x1 = 0;
            //compute part c and part d 
            string[] partd = new string[17];
            string[] partc = new string[17];

            partd[0] = orderingoption1.ToString().Substring(28, 28);
            partc[0] = orderingoption1.ToString().Substring(0, 28);


            string movedpartd = partd[0];
            char lastontheright;
            string movedpartc = partc[0];



            while (x1 < 16)
            {
                for (int x2 = 0; x2 < rotationschedule[x1]; x2++)
                {
                    lastontheright = movedpartc[0];
                    movedpartc = movedpartc.Remove(0, 1);
                    movedpartc += lastontheright;

                    lastontheright = movedpartd[0];
                    movedpartd = movedpartd.Remove(0, 1);
                    movedpartd += lastontheright;
                }
                partd[x1 + 1] = movedpartd;
                partc[x1 + 1] = movedpartc;

                x1++;
            }


            int j = 0;
            //compute subsecretk
            string[] secretk = new string[16];


            while (j < secretk.Length)
            {
                secretk[j] = partc[j + 1] + partd[j + 1];
                j++;
            }

            StringBuilder[] subsecretk = new StringBuilder[16];
            //get orderingoption2 and do it
            for (int v1 = 0; v1 < secretk.Length; v1++)
            {
                subsecretk[v1] = new StringBuilder();

                for (int v2 = 0; v2 < orderingoption2.Length; v2++)
                {
                    subsecretk[v1].Append(secretk[v1][orderingoption2[v2] - 1]);
                }
            }

            // Deciphering 

            //tranform original paragraph to binary
            StringBuilder encryptedtxtzerosandones = new StringBuilder();
            for (int y = 2; y < key.Length; y++)
            {
                encryptedtxtzerosandones.Append(zerosandonesconversion[int.Parse(cipherText[y].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
            }

            //do the ordering



            StringBuilder priliminaryordering = new StringBuilder();
            for (int c = 0; c < permutudInput.Length; c++)
            {
                priliminaryordering.Append(encryptedtxtzerosandones[permutudInput[c] - 1]);
            }

            //compute partontheleft and partontheright
            string[] partontheright = new string[17];
            string[] partontheleft = new string[17];

            partontheright[0] = priliminaryordering.ToString().Substring(32, 32);
            partontheleft[0] = priliminaryordering.ToString().Substring(0, 32);

            int verticalL;
            int horizontalL;
            string numberofzerosandones;
            StringBuilder ordering;
            StringBuilder btransform;
            StringBuilder bitwiseeitheroroperation;
            StringBuilder partontherightextended;









            //do the same thing sixteen times
            int counter = 1;
            while (counter < 17)
            {
                int m = 0; int bitindex = 0; int box = 0; int oederingone = 0;
                partontherightextended = new StringBuilder();
                partontheleft[counter] = partontheright[counter - 1];

                btransform = new StringBuilder();
                ordering = new StringBuilder();
                bitwiseeitheroroperation = new StringBuilder();





                //partontherightextended

                while (m < Tableofextenstion.Length)
                {
                    partontherightextended.Append(partontheright[counter - 1][Tableofextenstion[m] - 1]);
                    m++;
                }

                // bitwiseeitheroroperation partontherightextended with subsecretkofi

                while (bitindex < partontherightextended.Length)
                {
                    bitwiseeitheroroperation.Append(xorOperation(partontherightextended[bitindex], subsecretk[15 - (counter - 1)][bitindex]));
                    bitindex++;
                }

                // doing boxes transformation

                while (box < 8)
                {
                    numberofzerosandones = bitwiseeitheroroperation.ToString().Substring(6 * box, 6);
                    horizontalL = binaryToDecimal(numberofzerosandones[0] + string.Empty + numberofzerosandones[5]);
                    verticalL = binary4BitToDecimal(numberofzerosandones.Substring(1, 4));
                    btransform.Append(zerosandonesconversion[bsubistions[box, (horizontalL * 16) + verticalL]]);
                    box++;
                }

                //doing ordering

                while (oederingone < matrixofpermutation.Length)
                {
                    ordering.Append(btransform[matrixofpermutation[oederingone] - 1]);
                    oederingone++;
                }

                //compute partontheright
                bitindex = 0;
                int orderingsize = ordering.Length;
                bitwiseeitheroroperation = new StringBuilder();


                while (bitindex < orderingsize)
                {
                    bitwiseeitheroroperation.Append(xorOperation(partontheleft[counter - 1][bitindex], ordering[bitindex]));
                    bitindex++;
                }
                partontheright[counter] = bitwiseeitheroroperation.ToString();

                counter++;
            }
            StringBuilder originalzerosandones = new StringBuilder();
            string combinedblock = partontheright[16] + partontheleft[16];

            int index = 0;
            //do reverse ordering 
            int reverseorderingsize = InverseTableofintialpermutation.Length;

            while (index < reverseorderingsize)
            {
                originalzerosandones.Append(combinedblock[InverseTableofintialpermutation[index] - 1]);
                index++;
            }

            // hexa format result 
            for (int hexindex = 0; hexindex < 16; hexindex++)
            {
                originalparagraph += hexaConversion(originalzerosandones.ToString().Substring(4 * hexindex, 4));
            }

            return originalparagraph;
        }
    }
}