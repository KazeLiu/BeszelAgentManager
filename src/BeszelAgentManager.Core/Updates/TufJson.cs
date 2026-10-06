using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace BeszelAgentManager.Core.Updates;

// OLPC canonical JSON used by TUF/securesystemslib. This is not JCS or ordinary
// compact JSON: only quotes/backslashes are escaped, and floats are forbidden.
public static class TufJson
{
    public const int MaximumMetadataBytes = 256 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly IComparer<string> KeyComparer = Comparer<string>.Create(
        (left, right) => StrictUtf8.GetBytes(left).AsSpan().SequenceCompareTo(StrictUtf8.GetBytes(right)));

    public static JsonElement Parse(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length is 0 or > MaximumMetadataBytes)
            throw new UpdateMetadataException("Metadata size is outside the allowed range.");
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
            Validate(document.RootElement);
            return document.RootElement.Clone();
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or EncoderFallbackException)
        {
            throw new UpdateMetadataException("Metadata is not unambiguous UTF-8 JSON.", ex);
        }
    }

    public static byte[] Canonicalize(JsonElement element)
    {
        Validate(element);
        var output = new StringBuilder();
        Write(element, output);
        return StrictUtf8.GetBytes(output.ToString());
    }

    public static string Sha256(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    private static void Validate(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in element.EnumerateObject())
                {
                    if (!names.Add(property.Name))
                        throw new UpdateMetadataException("Duplicate JSON member rejected.");
                    _ = StrictUtf8.GetByteCount(property.Name);
                    Validate(property.Value);
                }
                break;
            case JsonValueKind.Array:
                foreach (var value in element.EnumerateArray()) Validate(value);
                break;
            case JsonValueKind.Number:
                if (!element.TryGetInt64(out _))
                    throw new UpdateMetadataException("Only bounded integers are supported in metadata.");
                break;
            case JsonValueKind.String:
                _ = StrictUtf8.GetByteCount(element.GetString()!);
                break;
            case JsonValueKind.True:
            case JsonValueKind.False:
            case JsonValueKind.Null:
                break;
            default:
                throw new UpdateMetadataException("Unsupported JSON value.");
        }
    }

    private static void Write(JsonElement element, StringBuilder output)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                output.Append('{');
                var first = true;
                foreach (var property in element.EnumerateObject().OrderBy(p => p.Name, KeyComparer))
                {
                    if (!first) output.Append(',');
                    first = false;
                    WriteString(property.Name, output);
                    output.Append(':');
                    Write(property.Value, output);
                }
                output.Append('}');
                break;
            case JsonValueKind.Array:
                output.Append('[');
                var separator = false;
                foreach (var value in element.EnumerateArray())
                {
                    if (separator) output.Append(',');
                    separator = true;
                    Write(value, output);
                }
                output.Append(']');
                break;
            case JsonValueKind.String:
                WriteString(element.GetString()!, output);
                break;
            case JsonValueKind.Number:
                output.Append(element.GetInt64().ToString(CultureInfo.InvariantCulture));
                break;
            default:
                output.Append(element.GetRawText());
                break;
        }
    }

    private static void WriteString(string value, StringBuilder output) => output.Append('"')
        .Append(value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal))
        .Append('"');
}

public sealed class UpdateMetadataException(string message, Exception? inner = null) : Exception(message, inner);
