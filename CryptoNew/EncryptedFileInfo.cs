using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;

namespace Crypto
{
    /// <summary>
    /// Užšifruojamų-(uotų) failų metaduomenys
    /// </summary>
    [Serializable]
    public class EncryptedFileInfo
    {
        [XmlIgnore]
        public string FullName { get; set; }
        public string FileName { get; set; }
        public long FileSize { get; set; } = -1;
        public bool IsReadOnly { get; set; }
        public DateTime CreationTime { get; set; }
        public DateTime LastAccessTime { get; set; }
        public DateTime LastWriteTime { get; set; }
        public FileAttributes Attributes { get; set; }

        public EncryptedFileInfo() { }

        public EncryptedFileInfo(string fileName)
        {
            FileInfo fInfo = new FileInfo(fileName);

            this.FullName = fInfo.FullName;
            this.FileName = fInfo.Name;

            this.IsReadOnly = fInfo.IsReadOnly;
            this.CreationTime = fInfo.CreationTime;
            this.LastAccessTime = fInfo.LastAccessTime;
            this.LastWriteTime = fInfo.LastWriteTime;
            this.Attributes = fInfo.Attributes;
            this.FileSize = fInfo.Length;
        }

        public static EncryptedFileInfo[] FromFileNameArray(string[] fileNames)
        {
            EncryptedFileInfo[] temp = new EncryptedFileInfo[fileNames.Length];

            for (int i = 0; i < fileNames.Length; i++)
            {
                temp[i] = new EncryptedFileInfo(fileNames[i]);
            }

            return temp;
        }

        public static string SerializeFiles(EncryptedFileInfo[] files)
        {
            XmlSerializer xmlSerializer = new XmlSerializer(files.GetType());
            string xmlString = "";

            using (StringWriter textWriter = new StringWriter())
            {
                xmlSerializer.Serialize(textWriter, files);
                return xmlString = textWriter.ToString();
            }
        }


        public static EncryptedFileInfo[] DeserializeXML(string xmlString)
        {
            EncryptedFileInfo[] xmlObj;
            XmlSerializer serializer = new XmlSerializer(typeof(EncryptedFileInfo[]));
            using (StringReader textReader = new StringReader(xmlString))
            {
                xmlObj = (EncryptedFileInfo[])serializer.Deserialize(textReader);
            }
            return xmlObj;
        }
    }
}
