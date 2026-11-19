using System.Text.Json;
using System.Text.Json.Serialization;

namespace BeszelAgentManager.WinUI.Services;

internal sealed class UiLanguageConverter : JsonConverter<string>
{
    public UiLanguageConverter() { }

    public override string Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String) return reader.GetString()!;
        reader.Skip();
        return "en-US";
    }

    public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options) => writer.WriteStringValue(value);
}
