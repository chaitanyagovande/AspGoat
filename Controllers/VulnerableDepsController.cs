using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using YamlDotNet.Serialization;
using ICSharpCode.SharpZipLib.Zip;
using log4net;

namespace AspGoat.Controllers;

[Authorize]
public class VulnerableDepsController : Controller
{
    private static readonly ILog _log = LogManager.GetLogger(typeof(VulnerableDepsController));

    // ── YAML Deserialization ──────────────────────────────────────────────────
    // CVE-2022-25578 (YamlDotNet < 11.2.1)
    // DeserializerBuilder with no type restrictions allows a crafted YAML
    // document to instantiate arbitrary .NET types, enabling DoS or RCE.
    // Contextual analysis trigger: Deserialize<object>() called on user input.

    [HttpGet]
    public IActionResult YamlDeserialization()
    {
        return View();
    }

    [HttpPost]
    public IActionResult YamlDeserialization(string yamlInput)
    {
        try
        {
            // Vulnerable: no SafeSchemaNodeTypeResolver — any .NET type can be
            // instantiated via YAML type tags, e.g. !!System.Diagnostics.Process
            var deserializer = new DeserializerBuilder().Build();
            var result = deserializer.Deserialize<object>(yamlInput ?? "");
            ViewData["Result"] = System.Text.Json.JsonSerializer.Serialize(result,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        }
        catch (Exception ex)
        {
            ViewData["Result"] = $"Error: {ex.Message}";
        }

        return View();
    }

    // ── Zip Path Traversal ────────────────────────────────────────────────────
    // CVE-2022-48208 (SharpZipLib < 1.4.2)
    // ZipEntry.Name is not sanitised before being used as a file-system path.
    // A malicious archive can write files outside the intended output directory
    // using entries like ../../etc/passwd or C:\Windows\System32\evil.dll.
    // Contextual analysis trigger: ZipFile + GetInputStream called with
    // unsanitised entry.Name used in Path.Combine.

    [HttpGet]
    public IActionResult ZipExtraction()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> ZipExtraction(IFormFile archive)
    {
        if (archive == null || archive.Length == 0)
        {
            ViewData["Result"] = "No file uploaded.";
            return View();
        }

        var tempArchive = Path.GetTempFileName();
        var outputDir   = Path.Combine(Path.GetTempPath(), "aspgoat-extract", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outputDir);

        try
        {
            using (var fs = new FileStream(tempArchive, FileMode.Create))
                await archive.CopyToAsync(fs);

            var extracted = new List<string>();

            using var zip = new ZipFile(tempArchive);
            foreach (ZipEntry entry in zip)
            {
                if (!entry.IsFile) continue;

                // Vulnerable: entry.Name is attacker-controlled and not normalised.
                // A zip-slip payload like ../../sensitive.txt escapes outputDir.
                var destPath = Path.Combine(outputDir, entry.Name);

                Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);

                using var input  = zip.GetInputStream(entry);
                using var output = System.IO.File.Create(destPath);
                await input.CopyToAsync(output);

                extracted.Add(entry.Name);
            }

            ViewData["Result"] = $"Extracted {extracted.Count} file(s) to {outputDir}:\n" +
                                  string.Join("\n", extracted);
        }
        catch (Exception ex)
        {
            ViewData["Result"] = $"Error: {ex.Message}";
        }
        finally
        {
            if (System.IO.File.Exists(tempArchive))
                System.IO.File.Delete(tempArchive);
        }

        return View();
    }

    // ── Log Injection + XXE via log4net ──────────────────────────────────────
    // CVE-2018-1285 (log4net < 2.0.10)
    // log4net's XmlConfigurator parses XML without disabling DTD processing.
    // When attacker-controlled XML reaches XmlConfigurator.Configure() the
    // parser resolves external entities, enabling XXE (file read, SSRF).
    // Additionally, logging unsanitised user input enables log injection.
    //
    // Contextual analysis triggers:
    //   log4net.Config.XmlConfigurator.Configure   ← called in ConfigureLogging
    //   log4net.Config.XmlConfigurator.ConfigureAndWatch ← not used here

    [HttpGet]
    public IActionResult LogActivity()
    {
        return View();
    }

    [HttpGet]
    public IActionResult LogActivity(string message, string level = "info")
    {
        if (string.IsNullOrEmpty(message))
        {
            ViewData["Result"] = "No message provided.";
            return View();
        }

        // Vulnerable: user input logged directly — enables log injection / log forging
        switch (level.ToLower())
        {
            case "warn":
                _log.Warn(message);
                break;
            case "error":
                _log.Error(message);
                break;
            default:
                _log.Info(message);
                break;
        }

        ViewData["Result"] = $"Logged at level '{level}': {message}";
        return View();
    }

    // ── XXE via log4net XmlConfigurator ───────────────────────────────────────
    // CVE-2018-1285: XmlConfigurator.Configure(Stream) parses XML with DTD
    // processing enabled. Supplying an XXE payload as the config reloads
    // the logger configuration while resolving external entities.
    //
    // Example XXE payload:
    //   <?xml version="1.0"?>
    //   <!DOCTYPE log4net [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    //   <log4net><root><level value="&xxe;" /></root></log4net>
    //
    // Contextual analysis trigger: XmlConfigurator.Configure(stream) called
    // with a Stream derived from user-controlled input.

    [HttpGet]
    public IActionResult ConfigureLogging()
    {
        var defaultConfig = @"<?xml version=""1.0"" encoding=""utf-8"" ?>
<log4net>
  <root>
    <level value=""INFO"" />
    <appender-ref ref=""ConsoleAppender"" />
  </root>
  <appender name=""ConsoleAppender"" type=""log4net.Appender.ConsoleAppender"">
    <layout type=""log4net.Layout.PatternLayout"">
      <conversionPattern value=""%date [%thread] %-5level %logger - %message%newline"" />
    </layout>
  </appender>
</log4net>";
        ViewData["DefaultConfig"] = defaultConfig;
        return View();
    }

    [HttpPost]
    public IActionResult ConfigureLogging(string xmlConfig)
    {
        try
        {
            // Vulnerable: user-supplied XML is passed directly to XmlConfigurator.Configure.
            // DTD processing is enabled in log4net < 2.0.10, so an XXE payload in xmlConfig
            // causes the parser to resolve external entities (file read, SSRF).
            using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(xmlConfig ?? ""));
            log4net.Config.XmlConfigurator.Configure(stream);

            ViewData["Result"] = "Logger reconfigured successfully.";
        }
        catch (Exception ex)
        {
            ViewData["Result"] = $"Error: {ex.Message}";
        }

        return View();
    }
}
