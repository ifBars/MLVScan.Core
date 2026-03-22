namespace MLVScan.Tools.SchemaGen;

public static class Program
{
    public static int Main(string[] args)
    {
        return SchemaGeneratorCli.Run(args, Console.Out, AppContext.BaseDirectory);
    }
}
