using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crypto
{
    /// <summary>
    /// Funkcinio programavimo atitikmena void'ui
    /// </summary>
    class Unit
    {
        public static Unit unit = new Unit();

        public override string ToString()
        {
            return "()";
        }

        public static Unit Print(string message)
        {
            Console.WriteLine(message);
            return unit;
        }
    }
}
