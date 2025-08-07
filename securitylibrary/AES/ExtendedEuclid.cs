using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>

        //throw new NotImplementedException();
        public int GetMultiplicativeInverse(int number, int baseN)
        {

            int output;
            int thirdbuffer;
            int divisionResult;
            int firstbuffer;
            int x2 = 0;
            int secondbuffer;
            int y1 = 0;
            int divisor = number;
            int dividend = baseN;
            int y2 = 1;
            int x1 = 1;


            for (; divisor != 0 && divisor != 1;)
            {
                divisionResult = dividend / divisor;
                thirdbuffer = divisor;
                divisor = dividend % thirdbuffer;
                dividend = thirdbuffer;
                secondbuffer = y2;
                firstbuffer = y1;

                y2 = x2 - y2 * divisionResult;
                y1 = x1 - y1 * divisionResult;
                x2 = secondbuffer;
                x1 = firstbuffer;
            }



            switch (divisor)
            {
                case 0:
                    return -1;
                case 1:
                    output = (y2 + baseN) % baseN;
                    return output;
                default:
                    return -1;
            }
        }
    }
}


