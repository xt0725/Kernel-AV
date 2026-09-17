using System.Text.Json;
using KernelAV.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

if (args.Contains("--self-test", StringComparer.OrdinalIgnoreCase))
{
    var path = Path.Combine(Path.GetTempPath(), $"kernel-av-self-test-{Guid.NewGuid():N}.txt");
    try
    {
        await File.WriteAllTextAsync(path, "Kernel-AV native service self-test");
        var result = await new ScanEngine().ScanAsync(path, CancellationToken.None);
        Console.WriteLine(JsonSerializer.Serialize(result));
        return result.Verdict == Verdict.Clean ? 0 : 1;
    }
    finally
    {
        File.Delete(path);
    }
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "KernelAV");
builder.Services.AddSingleton<ScanEngine>();
builder.Services.AddSingleton<ActivityDetector>();
builder.Services.AddHostedService<Worker>();

await builder.Build().RunAsync();
return 0;

