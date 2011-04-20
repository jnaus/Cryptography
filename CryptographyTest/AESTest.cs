using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using jj.Cryptography;
using System.Security.Cryptography;
using System.Diagnostics.Contracts;

namespace CryptographyTest
{
  [TestClass]
  public class AESTest
  {
    private string plainText = "This just some text to encrypt";
    private string pass;
    private byte[] salt;

    [TestInitialize]
    public void Initialize()
    {
      pass = "This is some password";
      salt = Encoding.ASCII.GetBytes("aaaabbbbcccc");
    }
    
    [TestMethod]
    public void AESCreateTest()
    {
      var aes = new AESCryptography();
    }

    [TestMethod]
    public void EncryptStringAESTest()
    {
      var aesString = AESCryptography.EncryptStringAES(plainText,pass,salt);
      Assert.IsNotNull(aesString);
    }

    [TestMethod]
    public void DecryptStringAESTest()
    {
      var cipherText = EncryptString();
      Assert.IsNotNull(cipherText);

      var decryptedText = AESCryptography.DecryptStringAES(cipherText, pass, salt);
      Assert.AreEqual(plainText, decryptedText);
    }

    [TestMethod]
    public void LongDecryptTest()
    {
      var inputText = @"
              Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus viverra facilisis sapien ut commodo. Pellentesque porttitor tellus ut dui facilisis tincidunt. Phasellus sed mi enim. Fusce non orci diam. Vestibulum non felis sit amet neque ultrices consequat in ac dolor. Ut at lorem ac nunc gravida vestibulum sit amet in mauris. Quisque eleifend venenatis velit, pulvinar tempor velit sodales nec. Phasellus id mi lacus. Donec sed magna ligula, ut suscipit libero. Sed aliquet feugiat tristique. In nec metus lacus. Etiam malesuada gravida urna eu sagittis. Maecenas pretium feugiat felis eu ornare. Phasellus venenatis urna id turpis facilisis at eleifend turpis accumsan. Quisque sit amet elit nisl, sagittis pellentesque lorem. Mauris accumsan vestibulum neque, ut mollis dolor convallis nec. Suspendisse ornare vulputate justo at molestie.

              Aliquam ut fringilla leo. Nulla facilisi. Fusce placerat rutrum velit a tincidunt. Etiam quis massa metus. Praesent scelerisque tincidunt lectus et fermentum. In in ligula lectus, quis faucibus velit. Vivamus lacus eros, aliquet non viverra in, pharetra quis lacus. Sed mollis, eros non viverra tincidunt, magna metus blandit neque, a venenatis lectus lorem sit amet tortor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla arcu ipsum, tempor in euismod et, imperdiet vel augue. Etiam id nulla in lorem tristique volutpat non nec augue. Ut dignissim tincidunt lectus, semper dictum tellus suscipit vel. In rhoncus mollis leo, sit amet facilisis sapien volutpat quis. Cras viverra lorem ut erat facilisis molestie. Nunc id erat et libero rhoncus pharetra. Aenean sodales mauris ut metus lacinia consectetur.

              Sed varius tincidunt lorem, id porttitor odio tincidunt sed. Duis pellentesque, diam sit amet sodales imperdiet, sapien risus pellentesque eros, vitae condimentum nunc nibh sit amet purus. Maecenas nec metus id justo vulputate ullamcorper et ut ante. Sed commodo consequat diam, quis aliquet odio laoreet in. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Duis sed ipsum quam, quis congue sem. Nunc et nulla tortor. Curabitur at porttitor leo. Nullam varius tempus urna, vel lobortis mi malesuada nec. Sed mi diam, posuere eu aliquam vel, porttitor suscipit tellus. Vestibulum porttitor, nisl in blandit egestas, eros quam dictum risus, a interdum ipsum mauris non sem. Cras felis diam, elementum vel dictum in, fringilla et ipsum. Vivamus tristique mauris at dolor consequat in porta diam imperdiet. Donec arcu nisl, vestibulum a placerat sit amet, porttitor id est.

              Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Nulla mattis nisl vel lorem bibendum facilisis at quis tellus. Ut vehicula lorem et leo scelerisque sollicitudin. Nulla facilisi. Phasellus vehicula malesuada nulla eu tincidunt. Ut lobortis libero quis metus condimentum at placerat magna ornare. Duis scelerisque fringilla lorem non luctus. Aliquam facilisis lacus id magna fermentum laoreet in ultrices erat. Etiam ac odio porta libero volutpat pulvinar. Praesent vel facilisis massa. Curabitur nulla nisl, dignissim vitae consequat a, venenatis in erat. Etiam a nisi eu sem lobortis sollicitudin. Donec ante massa, tristique eu dapibus id, vehicula sit amet urna. Sed a arcu nunc. Mauris volutpat, metus eget vehicula interdum, nisl nisl bibendum enim, sit amet vehicula turpis sem eu magna.

              Mauris venenatis, arcu id accumsan faucibus, eros urna mattis leo, et viverra sapien urna et dui. Nunc risus tellus, congue nec tempus ac, pharetra semper neque. Nam pharetra semper faucibus. Sed in tortor nec mauris porttitor mattis nec sit amet lectus. Nulla non dignissim neque. Curabitur neque enim, ultricies vitae tempor ut, aliquet ut quam. Aliquam sed sapien et odio rhoncus pharetra vel at dui. Fusce consequat, arcu et feugiat vulputate, tellus turpis tempus elit, eget sodales diam ante id nibh. Donec ornare pellentesque lectus vitae tempor. Nulla ac lorem eros, quis volutpat justo. Donec egestas justo quis mi ullamcorper ornare. Sed sit amet ligula at nunc commodo rhoncus.
              ";

      var cipherText = EncryptString(inputText);
      Assert.IsNotNull(cipherText);

      var decryptedText = AESCryptography.DecryptStringAES(cipherText, pass, salt);
      Assert.AreEqual(inputText, decryptedText);
    }

    [TestMethod]
    [ExpectedException(typeof(CryptographicException),
      "Bad password was inappropriately allowed")]
    public void BadPasswordTest()
    {
      var cipherText = EncryptString();
      var decryptedText = AESCryptography.DecryptStringAES(cipherText,"A bad password", salt);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentOutOfRangeException),
      "Bad salt was inappropriately allowed")]
    public void SaltOutOfRangeTest()
    {
      var cipherText = EncryptString();
      var badSalt = Encoding.ASCII.GetBytes("bad");
      var decryptedText = AESCryptography.DecryptStringAES(cipherText, pass, badSalt);
    }

    [TestMethod]
    [ExpectedException(typeof(CryptographicException),
      "Bad salt was inappropriately allowed")]
    public void BadSaltTest()
    {
      var cipherText = EncryptString();
      var badSalt = Encoding.ASCII.GetBytes("11112222");
      var decryptedText = AESCryptography.DecryptStringAES(cipherText, pass, badSalt);
    }

    private string EncryptString()
    {
      return EncryptString(plainText);
    }

    private string EncryptString(string inputText)
    {     
      var cipherText = AESCryptography.EncryptStringAES(inputText, pass, salt);
      return cipherText;
    }

  }
}
