namespace MLVScan.Tools.SchemaGen;

internal sealed record StringUnionSpec(string Name, IReadOnlyList<string> Values, bool IsConst)
{
    public static StringUnionSpec CreateEnum<TEnum>(string name)
        where TEnum : struct, Enum
    {
        return new StringUnionSpec(name, Enum.GetNames<TEnum>(), false);
    }

    public static StringUnionSpec CreateUnion(string name, params string[] values)
    {
        return new StringUnionSpec(name, values, false);
    }

    public static StringUnionSpec CreateConst(string name, string value)
    {
        return new StringUnionSpec(name, new[] { value }, true);
    }
}
