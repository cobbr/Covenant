using System;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;

using Covenant.Core;
using YamlDotNet.Serialization;

namespace Covenant.Models
{
    public interface ILoggable
    {
        public string ToLog(LogAction action);
    }

    public enum LogAction
    {
        Create,
        Edit,
        Delete
    }

    public interface IYamlSerializable<T>
    {
        public string ToYaml() => new SerializerBuilder().Build().Serialize(this);
        public static T FromYaml(string yaml) => new DeserializerBuilder().Build().Deserialize<T>(yaml);
        public static IEnumerable<T> FromYamlEnumerable(string yaml) => new DeserializerBuilder().Build().Deserialize<IEnumerable<T>>(yaml);
        public static string ToYamlEnumerable(IEnumerable<T> enumerable) => new SerializerBuilder().Build().Serialize(enumerable);
    }

    public static class YamlUtilities
    {
        public static string ToYaml<T>(this IYamlSerializable<T> myInterface) => myInterface.ToYaml();
        public static T FromYaml<T>(this IYamlSerializable<T> myInterface, string yaml) => myInterface.FromYaml(yaml);
        public static string ToYaml<T>(this IEnumerable<T> myEnumerable) => IYamlSerializable<T>.ToYamlEnumerable(myEnumerable);
        public static IEnumerable<T> FromYaml<T>(string yaml) => IYamlSerializable<T>.FromYamlEnumerable(yaml);
    }

    public class ParsedParameter
    {
        public int Position { get; set; }
        public bool IsLabeled { get; set; }
        public string Label { get; set; }
        public string Value { get; set; }

        public static List<ParsedParameter> GetParsedCommandParameters(string command)
        {
            List<ParsedParameter> ParsedParameters = new List<ParsedParameter>();

            // ("surrounded by quotes") | (/labeled:"with or without quotes") | (orseperatedbyspace)
            List<string> matches = Regex
                .Matches(command, @"""[^""\\]*(?:\\.[^""\\]*)*""|(/[^""\\/:]*:[""][^""\\]*(?:\\.[^""\\]*)*[""]|[^ ]+)|[^ ]+")
                .Cast<Match>()
                .Select(M => M.Value)
                .ToList();
            for (int i = 0; i < matches.Count; i++)
            {
                if (matches[i].StartsWith("/", StringComparison.Ordinal) && matches[i].IndexOf(":", StringComparison.Ordinal) != -1)
                {
                    int labelIndex = matches[i].IndexOf(":", StringComparison.Ordinal);
                    string label = matches[i].Substring(1, labelIndex - 1);
                    string val = matches[i].Substring(labelIndex + 1, matches[i].Length - labelIndex - 1);
                    ParsedParameters.Add(new ParsedParameter
                    {
                        Position = i,
                        IsLabeled = true,
                        Label = label,
                        Value = val.TrimOnceSymmetric('"').Replace("\\\"", "\"")
                    });
                }
                else
                {
                    ParsedParameters.Add(new ParsedParameter
                    {
                        Position = i,
                        IsLabeled = false,
                        Label = "",
                        Value = matches[i].Trim('"')
                    });
                }
            }
            return ParsedParameters;
        }
    }
}
