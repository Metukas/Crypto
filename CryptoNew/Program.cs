//#define Debug
//#define Encrypt
#define Decrypt

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using System.Reflection;
using System.Security;
using System.Runtime.InteropServices;
using static Crypto.Constants;
using static Crypto.Unit;

namespace Crypto
{
    class Program
    {
        
        enum AppMode
        {
            None,
            Encrypt,
            Decrypt,
        }

        static AppMode currentAppMode = AppMode.None;

        static void Main(string[] args)
        {
            /////////////////////////////////////////////////////////////////////////////

            //test
#if Debug && Encrypt
            args = new string[3];
            args[0] = "test1.txt";
            args[1] = "test2.txt";
            args[2] = "test3.txt";
#endif
#if Debug && Decrypt
            args = new string[1];
            args[0] = "Test.crypt";
#endif
            //\test

            Console.WriteLine("Files:");
            foreach(string s in args)
            {
                Console.WriteLine(s);
            }

            if (args.Any())
            {
                if(args.Length == 1)
                {
                    if (args[0].EndsWith(CONTAINER_FILE_EXTENSION))
                    {
                        //decrypt
                        currentAppMode = AskToDoCrypt(args[0], AppMode.Decrypt, AppMode.None, "Do you want to decrypt this container? Y/N");
                    }
                    else
                    {
                        // encrypt or decrypt
                        currentAppMode = AskIfEncryptOrDecrypt();
                    }
                }

                if(currentAppMode == AppMode.None)
                {
                    currentAppMode = AskToDoCrypt(args[0], AppMode.Encrypt, AppMode.None, "Do you want to encrypt these files? Y/N");
                }
            }
            else
            {
                Console.WriteLine("Please drag and drop on the program executable" +
                    " file(s) you want to encrypt or file container to decrypt!");
                return;
            }

            SecureString password;
            switch (currentAppMode)
            {
                case AppMode.Encrypt:
                    password = AskForPasswordTwice
                        ("Input password:", "Confirm password:", "Please try again");

                    string containerName = AskForContainerName("Input container file name");
                    Type encryptionAlgType = ChooseAlgorithm
                        ("Choose one of encryption algorithm (type index)", CryptoAlgorithms.SymmetricAlgorithms);
                    SymmetricAlgorithm encryptionAlg = 
                        (SymmetricAlgorithm)Activator.CreateInstance(encryptionAlgType);

                    Type hashAlgType = ChooseAlgorithm
                        ("Choose one of hash algorithm (type index)", CryptoAlgorithms.HashAlgorithms);
                    HashAlgorithm hashAlg = (HashAlgorithm) Activator.CreateInstance(hashAlgType);

                    Encryptor encryptor = new Encryptor
                        (password, encryptionAlg, hashAlg, args, containerName);
                    encryptor.Encrypt();
                    break;

                case AppMode.Decrypt:
                    password = AskForPassword("Please input password to decrypt container");
                    Decryptor decryptor = new Decryptor(password, args[0]);
                    decryptor.Decrypt().Match(
                        s => Print("Successfully decrypted files!"),
                        e => Print($"Failed to decrypt files: {e.Message} Error code: {e.ErrorCode}")
                    );
                    break;

                case AppMode.None:
                    //panic!
                    throw new Exception("What? (App mode set to None)");
            }

            Console.ReadKey(true);
        }

        private static Type ChooseAlgorithm(string message, Type[] algorithms)
        {
            Console.WriteLine(message);

            for(int i = 0; i < algorithms.Length; i++)
            {
                Console.WriteLine($"{i} {algorithms[i].Name}");
            }
            int index = ParseNum();
            return algorithms[index];

            int ParseNum()
            {
                int max = algorithms.Length - 1;
                ConsoleKeyInfo readKey = Console.ReadKey(true);
                //parse num
                int num = readKey.KeyChar - 0x30; //ASCII 0x30..0x39 yra skaičiai 1..9

                // TODO: kol kas grąžina nulinį, padaryt gražiau :)
                if (num > max)
                    return 0;

                return num;
            }
        }

        private static string AskForContainerName(string message)
        {
            Console.WriteLine(message);
            // TODO: išfiltruoti negalimus failų vardus
            return Console.ReadLine() + CONTAINER_FILE_EXTENSION;
        }

        static AppMode AskIfEncryptOrDecrypt()
        {
            Console.WriteLine("Do you want to encrypt or decrypt e/d?");
            ConsoleKey key;
            do
            {
                key = Console.ReadKey(true).Key;
            } while (key != ConsoleKey.E && key != ConsoleKey.D);
            if (key == ConsoleKey.E)
            {
                return AppMode.Encrypt;
            }
            else if (key == ConsoleKey.D)
            {
                return AppMode.Decrypt;
            }
            // neturėtų taip būti, bet mažą ką :)
            else
            {
                return AppMode.None;
            }
        }

        static AppMode AskToDoCrypt(string fileName, AppMode OnYes, AppMode OnNo, string message)
        {
            Console.WriteLine(message);
            ConsoleKey key;
            do
            {
                key = Console.ReadKey(true).Key;
            } while (key != ConsoleKey.Y && key != ConsoleKey.N);
            if (key == ConsoleKey.Y)
            {
                return OnYes;
            }
            else if (key == ConsoleKey.N)
            {
                return OnNo;
            }
            // neturėtų taip būti, bet mažą ką :)
            else
            {
                return AppMode.None;
            }
        }

        static SecureString AskForPassword(string message)
        {
            Console.WriteLine(message);

            SecureString passwordas = new SecureString();
            ConsoleKeyInfo consKey;
            const int printableCharStart = 0x20;
            while ((consKey = Console.ReadKey(true)).Key != ConsoleKey.Enter)
            {
                char KeyChar = consKey.KeyChar;
                if (KeyChar >= printableCharStart)
                {
                    passwordas.AppendChar(consKey.KeyChar);
                    KeyChar = '\0';
                }

                //jeigu backspace
                else if (consKey.Key == ConsoleKey.Backspace && passwordas.Length > 0)
                    // tada ištrinam simbolį iš stringo:
                    passwordas.RemoveAt(passwordas.Length - 1);

            }
            return passwordas;
        }

        static SecureString AskForPasswordTwice(string message1, string message2, string tryAgainMessage)
        {
            SecureString pass1 = AskForPassword(message1);
            SecureString pass2 = AskForPassword(message2);
            // jeigu slaptažodžiai nesutampa
            while(!pass1.IsEqualTo(pass2))
            {
                Console.WriteLine(tryAgainMessage);
                pass1 = AskForPassword(message1);
                pass2 = AskForPassword(message2);
            }

            // čia jau patvirtinom, kad abu slaptažodžiai vienodi tai galim bet kurį grąžint
            return pass1;
        }
    }
}
