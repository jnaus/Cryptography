using System;
using System.Diagnostics.Contracts;
using System.IO;
using System.Security.Cryptography;

namespace jj.Cryptography
{
  public class AESCryptography
  {
    /// <summary>
    /// Encrypt the given string using AES.  The string can be decrypted using 
    /// DecryptStringAES().  The password parameters must match.
    /// The salt size must be 8 bytes or larger.
    /// </summary>
    /// <param name="plainText">The text to encrypt.</param>
    /// <param name="password">A password used to generate a key for encryption.</param>
    /// <param name="salt">The key salt used to derive the key. </param>
    /// <returns></returns>
    public static string EncryptStringAES(string plainText, string password, byte[] salt)
    {
      Contract.Requires(plainText != null);
      Contract.Requires(plainText.Length > 0);
      Contract.Requires(password != null);
      Contract.Requires(password.Length > 0);
      Contract.Requires(salt != null);
      Contract.Requires<ArgumentOutOfRangeException>(salt.Length >= 8, "salt length must be 8 bytes or larger");

      string outStr = null;                 // Encrypted string to return
      RijndaelManaged aesAlg = null;        // RijndaelManaged object used to encrypt the data.

      try
      {
        // generate the key from the shared secret and the salt
        Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt);

        // Create a RijndaelManaged object
        // with the specified key and IV.
        aesAlg = new RijndaelManaged();
        aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
        aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8);

        // Create a decrytor to perform the stream transform.
        ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        // Create the streams used for encryption.
        using (MemoryStream msEncrypt = new MemoryStream())
        {
          using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
          {
            using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
            {
              //Write all data to the stream.
              swEncrypt.Write(plainText);
            }
          }
          outStr = Convert.ToBase64String(msEncrypt.ToArray());
        }
      }
      finally
      {
        // Clear the RijndaelManaged object.
        if (aesAlg != null)
          aesAlg.Clear();
      }

      // Return the encrypted bytes from the memory stream.
      return outStr;
      
    }

    /// <summary>
    /// Decrypt the given string.  Assumes the string was encrypted using 
    /// EncryptStringAES(), using an identical sharedSecret.
    /// The salt size must be 8 bytes or larger.
    /// </summary>
    /// <param name="cipherText">Text to decrypt</param>
    /// <param name="password">A password used to generate a key for encryption.</param>
    /// <param name="salt">The key salt used to derive the key. </param>
    /// <returns></returns>
    public static string DecryptStringAES(string cipherText, string password, byte[] salt)
    {      
      Contract.Requires(cipherText != null);
      Contract.Requires(cipherText.Length > 0);
      Contract.Requires(password != null);
      Contract.Requires(password.Length > 0);
      Contract.Requires(salt != null);
      Contract.Requires<ArgumentOutOfRangeException>(salt.Length >= 8, "salt length must be 8 bytes or larger");
      
      RijndaelManaged aesAlg = null;
      string plaintext = null;

      try
      {
        // generate the key from the shared secret and the salt
        Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt);

        // Create a RijndaelManaged object
        // with the specified key and IV.
        aesAlg = new RijndaelManaged();
        aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
        aesAlg.IV = key.GetBytes(aesAlg.BlockSize / 8);

        // Create a decrytor to perform the stream transform.
        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
        // Create the streams used for decryption.                
        byte[] bytes = Convert.FromBase64String(cipherText);
        using (MemoryStream msDecrypt = new MemoryStream(bytes))
        {
          using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
          {
            using (StreamReader srDecrypt = new StreamReader(csDecrypt))

              // Read the decrypted bytes from the decrypting stream
              // and place them in a string.
              plaintext = srDecrypt.ReadToEnd();
          }
        }
      }
      finally
      {
        // Clear the RijndaelManaged object.
        if (aesAlg != null)
          aesAlg.Clear();
      }

      return plaintext;
    }
  }
}
