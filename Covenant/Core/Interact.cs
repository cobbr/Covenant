using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text.RegularExpressions;

using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;

using Covenant.Hubs;
using Covenant.Models;
using Covenant.Models.Covenant;
using Covenant.Models.Grunts;

namespace Covenant.Core
{
    public class ParsedParameter
    {
        public int Position { get; set; }
        public bool IsLabeled { get; set; }
        public string Label { get; set; }
        public string Value { get; set; }
    }

    public class Interaction
    {
        private readonly CovenantContext _context;
        private readonly IHubContext<GruntHub> _grunthub;
        private readonly IHubContext<EventHub> _eventhub;

        public Interaction(CovenantContext context, IHubContext<GruntHub> grunthub, IHubContext<EventHub> eventhub)
        {
            _context = context;
            _grunthub = grunthub;
            _eventhub = eventhub;
        }

        private static string GetUsage(GruntTask task)
        {
            string usage = "Usage: " + task.Name;
            foreach (var option in task.Options)
            {
                if (option.Optional)
                {
                    usage += "[ <" + option.Name.ToLower() + "> ]";
                }
                else
                {
                    usage += " <" + option.Name.ToLower() + ">";
                }
            }
            return usage;
        }

        private static IEnumerable<ParsedParameter> ParseParameters(string command)
        {
            List<ParsedParameter> ParsedParameters = new List<ParsedParameter>();

            // ("surrounded by quotes") | (/labeled:"with or without quotes") | (orseperatedbyspace)
            List<string> matches = Regex
                .Matches(command, @"""[^""\\]*(?:\\.[^""\\]*)*""|(/[^""\\/:]*:[""][^""\\]*(?:\\.[^""\\]*)*[""]|[^ ]+)|[^ ]+")
                .Cast<Match>()
                .Select(M => M.Value)
                .ToList();
            for(int i = 0; i < matches.Count; i++)
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
                        Value = (val.StartsWith("\"", StringComparison.Ordinal) && val.EndsWith("\"", StringComparison.Ordinal)) ? val.Trim('"') : val
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

        public void GetSuggestionRecursive(GruntTask task, int index, string progress, ref List<string> suggestions)
        {
            if (index >= task.Options.Count)
            {
                return;
            }
            foreach (var s in task.Options[index].SuggestedValues)
            {
                suggestions.Add(progress + " " + s);
                GetSuggestionRecursive(task, index + 1, progress + " " + s, ref suggestions);
            }
        }

        public async Task<List<string>> GetSuggestions(string GruntName)
        {
            Grunt grunt = await _context.Grunts.FirstOrDefaultAsync(G => G.Name.Equals(GruntName, StringComparison.OrdinalIgnoreCase));
            IEnumerable<GruntTasking> taskings = await _context.GetGruntTaskingsForGrunt(grunt.Id);
            List<string> suggestions = new List<string>();
            foreach (var task in await _context.GetGruntTasks())
            {
                if (!task.Name.StartsWith("SharpShell-", StringComparison.Ordinal))
                {
                    suggestions.Add(task.Name);
                    GetSuggestionRecursive(task, 0, task.Name, ref suggestions);
                    foreach (var altname in task.AlternateNames)
                    {
                        suggestions.Add(altname);
                        GetSuggestionRecursive(task, 0, altname, ref suggestions);
                    }
                }
            }
            suggestions.AddRange(new List<string> { "Show", "Note", "History" });
            suggestions.AddRange(taskings.Select(GT => $"History {GT.Name}"));
            return suggestions;
        }

        private static string GetCommandFromInput(string UserInput)
        {
            if (UserInput.StartsWith("Assembly", StringComparison.OrdinalIgnoreCase) ||
                UserInput.StartsWith("AssemblyReflect", StringComparison.OrdinalIgnoreCase) ||
                UserInput.StartsWith("Upload", StringComparison.OrdinalIgnoreCase))
            {
                List<ParsedParameter> parameters = ParseParameters(UserInput).ToList();
                if (parameters.Count >= 3)
                {
                    return UserInput.Replace(parameters[2].Value, "");
                }
            }
            else if (UserInput.StartsWith("PowerShellImport", StringComparison.OrdinalIgnoreCase))
            {
                List<ParsedParameter> parameters = ParseParameters(UserInput).ToList();
                if (parameters.Count >= 2)
                {
                    return UserInput.Replace(parameters[1].Value, "");
                }
            }
            return UserInput;
        }

        public async Task<GruntCommand> Input(CovenantUser user, Grunt grunt, string UserInput)
        {
            GruntCommand GruntCommand = await _context.CreateGruntCommand(new GruntCommand
            {
                Command = GetCommandFromInput(UserInput),
                CommandTime = DateTime.UtcNow,
                User = user,
                GruntId = grunt.Id,
                Grunt = grunt,
                CommandOutputId = 0,
                CommandOutput = new CommandOutput()
            }, _grunthub, _eventhub);
            try
            {
                List<ParsedParameter> parameters = ParseParameters(UserInput).ToList();
                GruntTask commandTask = null;
                try
                {
                    commandTask = await _context.GetGruntTaskByName(parameters.FirstOrDefault().Value);
                    if (commandTask.Options.Count == 1 && new List<string> { "Command", "ShellCommand", "PowerShellCommand", "Code" }.Contains(commandTask.Options[0].Name))
                    {
                        parameters = new List<ParsedParameter>
                        {
                            new ParsedParameter
                            {
                                Value = commandTask.Name, Label = "", IsLabeled = false, Position = 0
                            },
                            new ParsedParameter
                            {
                                Value = UserInput.Substring(UserInput.IndexOf(" ", StringComparison.Ordinal) + 1).Trim('"'),
                                Label = "", IsLabeled = false, Position = 0
                            }
                        };
                    }
                }
                catch (ControllerNotFoundException) { }

                string output = "";
                if (parameters.FirstOrDefault().Value.ToLower() == "show")
                {
                    output = await Show(grunt);
                }
                else if (parameters.FirstOrDefault().Value.ToLower() == "help")
                {
                    output = await Help(parameters);
                }
                else if (parameters.FirstOrDefault().Value.ToLower() == "exit")
                {
                    output = await Exit(grunt, GruntCommand, parameters);
                }
                else if (parameters.FirstOrDefault().Value.ToLower() == "history")
                {
                    output = await History(grunt, parameters);
                }
                else if (parameters.FirstOrDefault().Value.ToLower() == "jobs")
                {
                    output = await Jobs(grunt, GruntCommand, parameters);
                }
                else if (parameters.FirstOrDefault().Value.ToLower() == "note")
                {
                    grunt.Note = string.Join(" ", parameters.Skip(1).Select(P => P.Value).ToArray());
                    await _context.EditGrunt(grunt, user, _grunthub, _eventhub);
                    output = "Note: " + grunt.Note;
                }
                else if (commandTask != null)
                {
                    parameters = parameters.Skip(1).ToList();
                    if (parameters.Count() < commandTask.Options.Count(O => !O.Optional))
                    {
                        _context.Entry(GruntCommand).State = EntityState.Detached;
                        GruntCommand.CommandOutput.Output = EliteConsole.PrintFormattedErrorLine(GetUsage(commandTask));
                        return await _context.EditGruntCommand(GruntCommand, _grunthub, _eventhub);
                    }
                    // All options begin unassigned
                    List<bool> OptionAssignments = commandTask.Options.Select(O => false).ToList();
                    commandTask.Options.ForEach(O => O.Value = "");
                    for (int i = 0; i < parameters.Count; i++)
                    {
                        if (parameters[i].IsLabeled)
                        {
                            var option = commandTask.Options.FirstOrDefault(O => O.Name.Equals(parameters[i].Label, StringComparison.OrdinalIgnoreCase));
                            option.Value = parameters[i].Value;
                            OptionAssignments[commandTask.Options.IndexOf(option)] = true;
                        }
                        else
                        {
                            GruntTaskOption nextOption = null;
                            // Find next unassigned option
                            for (int j = 0; j < commandTask.Options.Count; j++)
                            {
                                if (!OptionAssignments[j])
                                {
                                    nextOption = commandTask.Options[j];
                                    OptionAssignments[j] = true;
                                    break;
                                }
                            }
                            if (nextOption == null)
                            {
                                // This is an extra parameter
                                _context.Entry(GruntCommand).State = EntityState.Detached;
                                GruntCommand.CommandOutput.Output = EliteConsole.PrintFormattedErrorLine(GetUsage(commandTask));
                                return await _context.EditGruntCommand(GruntCommand, _grunthub, _eventhub);
                            }
                            nextOption.Value = parameters[i].Value;
                        }
                    }

                    // Check for unassigned required options
                    for (int i = 0; i < commandTask.Options.Count; i++)
                    {
                        if (!OptionAssignments[i] && !commandTask.Options[i].Optional)
                        {
                            // This is an extra parameter
                            StringBuilder toPrint = new StringBuilder();
                            toPrint.Append(EliteConsole.PrintFormattedErrorLine(commandTask.Options[i].Name + " is required."));
                            toPrint.Append(EliteConsole.PrintFormattedErrorLine(GetUsage(commandTask)));
                            _context.Entry(GruntCommand).State = EntityState.Detached;
                            GruntCommand.CommandOutput.Output = toPrint.ToString();
                            return await _context.EditGruntCommand(GruntCommand, _grunthub, _eventhub);
                        }
                    }
                    // Parameters have parsed successfully
                    commandTask = await _context.EditGruntTask(commandTask);
                    await StartTask(grunt, commandTask, GruntCommand);
                }
                else
                {
                    output = EliteConsole.PrintFormattedErrorLine("Unrecognized command");
                }
                _context.Entry(GruntCommand).State = EntityState.Detached;
                GruntCommand.CommandOutput.Output = output;
                return await _context.EditGruntCommand(GruntCommand, _grunthub, _eventhub);
            }
            catch (Exception e)
            {
                _context.Entry(GruntCommand).State = EntityState.Detached;
                GruntCommand.CommandOutput.Output = EliteConsole.PrintFormattedErrorLine($"{e.Message}{Environment.NewLine}{e.StackTrace}");
                return await _context.EditGruntCommand(GruntCommand, _grunthub, _eventhub);
            }
        }

        public async Task<string> Show(Grunt grunt)
        {
            List<Grunt> children = new List<Grunt>();
            foreach (string guid in grunt.Children)
            {
                children.Add(await _context.Grunts.FirstOrDefaultAsync(G => G.GUID == guid));
            }
            List<GruntTasking> tasks = await _context.GruntTaskings.Where(GT => GT.GruntId == grunt.Id).ToListAsync();

            EliteConsoleMenu menu = new EliteConsoleMenu(EliteConsoleMenu.EliteConsoleMenuType.Parameter, "Grunt: " + grunt.Name);
            menu.Rows.Add(new List<string> { "Name:", grunt.Name });
            menu.Rows.Add(new List<string> { "CommType:", grunt.ImplantTemplate.CommType.ToString() });
            menu.Rows.Add(new List<string> { "Connected Grunts:", String.Join(",", children.Select(C => C.Name)) });
            menu.Rows.Add(new List<string> { "Hostname:", grunt.Hostname });
            menu.Rows.Add(new List<string> { "IPAdress:", grunt.IPAddress });
            menu.Rows.Add(new List<string> { "User:", grunt.UserDomainName + "\\" + grunt.UserName });
            menu.Rows.Add(new List<string> { "Status:", grunt.Status.ToString() });
            menu.Rows.Add(new List<string> { "LastCheckIn:", grunt.LastCheckIn.ToString() });
            menu.Rows.Add(new List<string> { "ActivationTime:", grunt.ActivationTime.ToString() });
            menu.Rows.Add(new List<string> { "Integrity:", grunt.Integrity.ToString() });
            menu.Rows.Add(new List<string> { "OperatingSystem:", grunt.OperatingSystem });
            menu.Rows.Add(new List<string> { "Process:", grunt.Process });
            menu.Rows.Add(new List<string> { "Delay:", grunt.Delay.ToString() });
            menu.Rows.Add(new List<string> { "JitterPercent:", grunt.JitterPercent.ToString() });
            menu.Rows.Add(new List<string> { "ConnectAttempts:", grunt.ConnectAttempts.ToString() });
            menu.Rows.Add(new List<string> { "KillDate:", grunt.KillDate.ToString() });
            menu.Rows.Add(new List<string> { "Tasks Assigned:", String.Join(",", tasks.Select(T => T.Name)) });
            menu.Rows.Add(new List<string> { "Tasks Completed:",
                String.Join(",", tasks.Where(GT => GT.Status == GruntTaskingStatus.Completed).Select(T => T.Name))
            });
            return menu.Print();
        }

        public async Task<string> Help(List<ParsedParameter> parameters)
        {
            string Name = "Help";
            if ((parameters.Count() != 1 && parameters.Count() != 2 ) || !parameters[0].Value.Equals(Name, StringComparison.OrdinalIgnoreCase))
            {
                StringBuilder toPrint1 = new StringBuilder();
                toPrint1.Append(EliteConsole.PrintFormattedErrorLine("Usage: Help <task_name>"));
                return toPrint1.ToString();
            }
            StringBuilder toPrint = new StringBuilder();
            foreach (GruntTask t in await _context.GetGruntTasks())
            {
                if (parameters.Count() == 1)
                {
                    toPrint.AppendLine($"{t.Name}\t\t{t.Description}");
                }
                else if(parameters.Count() == 2 && t.Name.Equals(parameters[1].Value, StringComparison.CurrentCultureIgnoreCase))
                {
                    string usage = t.Name;
                    t.Options.ForEach(O =>
                    {
                        usage += O.Optional ? $" [ <{O.Name.Replace(" ", "_").ToLower()}> ]" : $" <{O.Name.Replace(" ", "_").ToLower()}>";
                    });
                    string libraries = string.Join(",", t.ReferenceSourceLibraries.Select(RSL => RSL.Name));
                    string assemblies = string.Join(",", t.ReferenceAssemblies.Select(RA => RA.Name));
                    string resources = string.Join(",", t.EmbeddedResources.Select(ER => ER.Name));
                    toPrint.AppendLine($"Name: {t.Name}");
                    toPrint.AppendLine($"Description: {t.Description}");
                    toPrint.AppendLine($"Usage: {usage}");
                    toPrint.AppendLine($"ReferenceSourceLibraries: " + (string.IsNullOrEmpty(libraries) ? "None" : libraries));
                    toPrint.AppendLine($"ReferenceAssemblies: " + (string.IsNullOrEmpty(assemblies) ? "None" : assemblies));
                    toPrint.AppendLine($"EmbeddedResources: " + (string.IsNullOrEmpty(resources) ? "None" : resources));
                    if (!string.IsNullOrEmpty(t.Help))
                    {
                        toPrint.AppendLine($"Help: {t.Help}");
                    }
                    break;
                }
            }
            return toPrint.ToString();
        }

        public async Task<GruntTasking> StartTask(Grunt grunt, GruntTask task, GruntCommand command)
        {
            return await _context.CreateGruntTasking(new GruntTasking
            {
                GruntTaskId = task.Id,
                GruntId = grunt.Id,
                Type = task.TaskingType,
                Status = GruntTaskingStatus.Uninitialized,
                GruntCommandId = command.Id,
                GruntCommand = command
            }, _grunthub);
        }

        public async Task<string> Exit(Grunt grunt, GruntCommand command, List<ParsedParameter> parameters)
        {
            if (parameters.Count() != 1)
            {
                StringBuilder toPrint = new StringBuilder();
                toPrint.Append(EliteConsole.PrintFormattedErrorLine("Usage: Exit"));
                return toPrint.ToString();
            }
            GruntTask exitTask = await _context.GetGruntTaskByName("Exit");
            await _context.CreateGruntTasking(new GruntTasking
            {
                Id = 0,
                GruntId = grunt.Id,
                GruntTaskId = exitTask.Id,
                GruntTask = exitTask,
                Name = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10),
                Status = GruntTaskingStatus.Uninitialized,
                Type = GruntTaskingType.Exit,
                GruntCommand = command,
                GruntCommandId = command.Id
            }, _grunthub);
            return "";
        }

        public async Task<string> History(Grunt grunt, List<ParsedParameter> parameters)
        {
            string Name = "History";
            if (parameters.Count() != 2 || !parameters[0].Value.Equals(Name, StringComparison.OrdinalIgnoreCase))
            {
                StringBuilder toPrint1 = new StringBuilder();
                toPrint1.Append(EliteConsole.PrintFormattedErrorLine("Usage: History <tasking_name>"));
                return toPrint1.ToString();
            }
            StringBuilder toPrint = new StringBuilder();
            GruntTasking tasking = await _context.GruntTaskings.FirstOrDefaultAsync(GT => GT.Name == parameters[1].Value);
            if (tasking == null)
            {
                toPrint.Append(EliteConsole.PrintFormattedErrorLine("Invalid History command, invalid tasking name. Usage is: History [ <tasking_name> ]"));
            }
            else
            {
                GruntCommand command = await _context.GruntCommands
                    .Include(GC => GC.CommandOutput)
                    .Include(GC => GC.User)
                    .FirstOrDefaultAsync(GC => GC.Id == tasking.GruntCommandId);
                toPrint.Append(EliteConsole.PrintFormattedInfoLine("[" + tasking.CompletionTime + " UTC] Grunt: " + grunt.Name + " " + "GruntTasking: " + tasking.Name));
                toPrint.Append(EliteConsole.PrintInfoLine("(" + command.User.UserName + ") > " + command.Command));
                toPrint.Append(EliteConsole.PrintInfoLine(command.CommandOutput.Output));
            }
            return toPrint.ToString();
        }

        public async Task<string> Jobs(Grunt grunt, GruntCommand command, List<ParsedParameter> parameters)
        {
            string Name = "Jobs";
            if (parameters.Count != 1 || !parameters[0].Value.Equals(Name, StringComparison.OrdinalIgnoreCase))
            {
                return EliteConsole.PrintFormattedErrorLine("Usage: Jobs");
            }
            GruntTask jobsTask = await _context.GetGruntTaskByName("Jobs");
            await _context.CreateGruntTasking(new GruntTasking
            {
                Id = 0,
                GruntId = grunt.Id,
                GruntTaskId = jobsTask.Id,
                GruntTask = jobsTask,
                Name = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10),
                Status = GruntTaskingStatus.Uninitialized,
                Type = GruntTaskingType.Jobs,
                Parameters = new List<string> { "Jobs" },
                GruntCommand = command,
                GruntCommandId = command.Id
            }, _grunthub);
            return "";
        }
    }

    public class EliteConsoleMenu
    {
        public enum EliteConsoleMenuType
        {
            Menu,
            Parameter,
            List
        }

        public EliteConsoleMenuType MenuType { get; set; } = EliteConsoleMenuType.Menu;
        public string Title { get; set; } = "";
        public List<string> Columns { get; set; } = new List<string>();
        public List<List<string>> Rows { get; set; } = new List<List<string>>();
        public bool PrintEndBuffer { get; set; } = true;
        public bool ShouldShortenFields { get; set; } = true;

        private static string Spacer { get; } = "     ";
        private static int MaxFieldLength { get; } = 80;
        private static string Elipsis { get; } = "...";

        public EliteConsoleMenu(EliteConsoleMenuType MenuType = EliteConsoleMenuType.Menu, string Title = "")
        {
            this.MenuType = MenuType;
            this.Title = Title;
        }

        public string Print()
        {
            StringBuilder toPrint = new StringBuilder();
            // Ensure enough columns for given rows
            if (Rows.Count > 0)
            {
                while (Rows.Select(R => R.Count).Max() > Columns.Count)
                {
                    Columns.Add("");
                }
                // Shortens overly lengthy fields
                this.ShortenFields();
            }
            // Calculate max Column Lengths
            List<int> ColumnsMaxLengths = Columns.Select(C => 0).ToList();
            for (int i = 0; i < Rows.Count; i++)
            {
                for (int j = 0; j < Rows[i].Count; j++)
                {
                    ColumnsMaxLengths[j] = Math.Max(ColumnsMaxLengths[j], Rows[i][j].Length);
                }
            }
            bool empty = !(ColumnsMaxLengths.Max() > 0);
            for (int i = 0; i < ColumnsMaxLengths.Count; i++)
            {
                // Remove empty columns, if it is not a completely empty menu
                if (ColumnsMaxLengths[i] == 0 && !empty)
                {
                    Rows.ForEach(R => R.RemoveAt(i));
                    Columns.RemoveAt(i);
                    ColumnsMaxLengths.RemoveAt(i);
                    i--;
                }
                else
                {
                    // Column name is the max, if longer than all the column's fields
                    ColumnsMaxLengths[i] = Math.Max(ColumnsMaxLengths[i], Columns[i].Length);
                }
            }

            toPrint.Append(EliteConsole.PrintInfoLine());
            toPrint.Append(EliteConsole.PrintInfoLine());
            switch (this.MenuType)
            {
                case EliteConsoleMenuType.Menu:
                    toPrint.Append(PrintMenuType(ColumnsMaxLengths));
                    break;
                case EliteConsoleMenuType.Parameter:
                    toPrint.Append(PrintParameterType(ColumnsMaxLengths));
                    break;
                case EliteConsoleMenuType.List:
                    toPrint.Append(PrintListType(ColumnsMaxLengths));
                    break;
            }
            if (this.PrintEndBuffer)
            {
                toPrint.Append(EliteConsole.PrintInfoLine());
                toPrint.Append(EliteConsole.PrintInfoLine());
            }
            return toPrint.ToString();
        }

        private string PrintMenuType(List<int> ColumnsMaxLengths)
        {
            StringBuilder toPrint = new StringBuilder();
            toPrint.Append(EliteConsole.PrintInfo(Spacer));
            toPrint.Append(EliteConsole.PrintHighlightLine(this.Title));
            toPrint.Append(EliteConsole.PrintInfo(Spacer));
            toPrint.Append(EliteConsole.PrintInfoLine(new String('=', ColumnsMaxLengths.Sum() + Columns.Count - 1)));
            foreach (List<string> row in Rows)
            {
                toPrint.Append(EliteConsole.PrintInfo(Spacer));
                for (int i = 0; i < row.Count; i++)
                {
                    toPrint.Append(EliteConsole.PrintInfo(row[i]));
                    toPrint.Append(EliteConsole.PrintInfo(new String(' ', ColumnsMaxLengths[i] - row[i].Length + 1)));
                }
                toPrint.Append(EliteConsole.PrintInfoLine());
            }
            return toPrint.ToString();
        }

        private string PrintParameterType(List<int> ColumnsMaxLengths)
        {
            StringBuilder toPrint = new StringBuilder();
            toPrint.Append(EliteConsole.PrintInfo(Spacer));
            toPrint.Append(EliteConsole.PrintHighlightLine(this.Title));
            toPrint.Append(EliteConsole.PrintInfo(Spacer));
            toPrint.Append(EliteConsole.PrintInfoLine(new String('=', ColumnsMaxLengths.Sum() + Columns.Count - 1)));
            foreach (List<string> row in Rows)
            {
                toPrint.Append(EliteConsole.PrintInfo(Spacer));
                for (int i = 0; i < row.Count; i++)
                {
                    toPrint.Append(EliteConsole.PrintInfo(row[i]));
                    toPrint.Append(EliteConsole.PrintInfo(new String(' ', ColumnsMaxLengths[i] - row[i].Length + 1)));
                }
                toPrint.Append(EliteConsole.PrintInfoLine());
            }
            return toPrint.ToString();
        }

        private string PrintListType(List<int> ColumnsMaxLengths)
        {
            StringBuilder toPrint = new StringBuilder();
            toPrint.Append(EliteConsole.PrintInfo(Spacer));
            for (int i = 0; i < Columns.Count; i++)
            {
                toPrint.Append(EliteConsole.PrintInfo(Columns[i]));
                toPrint.Append(EliteConsole.PrintInfo(new String(' ', ColumnsMaxLengths[i] - Columns[i].Length + 1)));
            }
            toPrint.Append(EliteConsole.PrintInfoLine());
            toPrint.Append(EliteConsole.PrintInfo(Spacer));
            for (int i = 0; i < Columns.Count; i++)
            {
                toPrint.Append(EliteConsole.PrintInfo(new String('-', Columns[i].Length)));
                toPrint.Append(EliteConsole.PrintInfo(new String(' ', ColumnsMaxLengths[i] - Columns[i].Length + 1)));
            }
            toPrint.Append(EliteConsole.PrintInfoLine());
            foreach (List<string> row in Rows)
            {
                toPrint.Append(EliteConsole.PrintInfo(Spacer));
                for (int i = 0; i < row.Count; i++)
                {
                    toPrint.Append(EliteConsole.PrintInfo(row[i]));
                    toPrint.Append(EliteConsole.PrintInfo(new String(' ', ColumnsMaxLengths[i] - row[i].Length + 1)));
                }
                toPrint.Append(EliteConsole.PrintInfoLine());
            }
            return toPrint.ToString();
        }

        private void ShortenFields()
        {
            for (int i = 0; i < Columns.Count; i++)
            {
                Columns[i] = Short(Columns[i]);
            }
            for (int i = 0; i < Rows.Count; i++)
            {
                for (int j = 0; j < Rows[i].Count; j++)
                {
                    Rows[i][j] = Short(Rows[i][j]);
                }
            }
        }

        private string Short(string toShorten = "")
        {
            if (toShorten == null) { toShorten = ""; }
            if (!this.ShouldShortenFields) { return toShorten; }
            if (toShorten.Length > MaxFieldLength)
            {
                return toShorten.Substring(0, MaxFieldLength) + Elipsis;
            }
            return toShorten;
        }
    }

    public static class EliteConsole
    {
        private static readonly ConsoleColor InfoColor = ConsoleColor.Gray;
        private static readonly ConsoleColor HighlightColor = ConsoleColor.Cyan;
        private static readonly ConsoleColor WarningColor = ConsoleColor.Yellow;
        private static readonly ConsoleColor ErrorColor = ConsoleColor.Red;

        private static readonly string InfoLabel = "[+]";
        private static readonly string HighlightLabel = "[*]";
        private static readonly string WarningLabel = "[-]";
        private static readonly string ErrorLabel = "[!]";
        private static readonly object _ConsoleLock = new object();

        public static void SetForegroundColor(ConsoleColor color)
        {
            lock (_ConsoleLock)
            {
                Console.ForegroundColor = color;
            }
        }

        private static string PrintColor(string ToPrint = "", ConsoleColor color = ConsoleColor.DarkGray)
        {
            string toReturn;
            SetForegroundColor(color);
            lock (_ConsoleLock)
            {
                toReturn = ToPrint;
                Console.ResetColor();
            }
            return toReturn;
        }

        private static string PrintColorLine(string ToPrint = "", ConsoleColor color = ConsoleColor.DarkGray)
        {
            string toReturn;
            lock (_ConsoleLock)
            {
                Console.ForegroundColor = color;
                toReturn = ToPrint + Environment.NewLine;
                Console.ResetColor();
            }
            return toReturn;
        }

        public static string PrintInfo(string ToPrint = "")
        {
            return PrintColor(ToPrint, EliteConsole.InfoColor);
        }

        public static string PrintInfoLine(string ToPrint = "")
        {
            return PrintColorLine(ToPrint, EliteConsole.InfoColor);
        }

        public static string PrintFormattedInfo(string ToPrint = "")
        {
            return PrintColor(EliteConsole.InfoLabel + " " + ToPrint, EliteConsole.InfoColor);
        }

        public static string PrintFormattedInfoLine(string ToPrint = "")
        {
            return PrintColorLine(EliteConsole.InfoLabel + " " + ToPrint, EliteConsole.InfoColor);
        }

        public static string PrintHighlight(string ToPrint = "")
        {
            return PrintColor(ToPrint, EliteConsole.HighlightColor);
        }

        public static string PrintHighlightLine(string ToPrint = "")
        {
            return PrintColorLine(ToPrint, EliteConsole.HighlightColor);
        }

        public static string PrintFormattedHighlight(string ToPrint = "")
        {
            return PrintColor(EliteConsole.HighlightLabel + " " + ToPrint, EliteConsole.HighlightColor);
        }

        public static string PrintFormattedHighlightLine(string ToPrint = "")
        {
            return PrintColorLine(EliteConsole.HighlightLabel + " " + ToPrint, EliteConsole.HighlightColor);
        }

        public static string PrintWarning(string ToPrint = "")
        {
            return PrintColor(ToPrint, EliteConsole.WarningColor);
        }

        public static string PrintWarningLine(string ToPrint = "")
        {
            return PrintColorLine(ToPrint, EliteConsole.WarningColor);
        }

        public static string PrintFormattedWarning(string ToPrint = "")
        {
            return PrintColor(EliteConsole.WarningLabel + " " + ToPrint, EliteConsole.WarningColor);
        }

        public static string PrintFormattedWarningLine(string ToPrint = "")
        {
            return PrintColorLine(EliteConsole.WarningLabel + " " + ToPrint, EliteConsole.WarningColor);
        }

        public static string PrintError(string ToPrint = "")
        {
            return PrintColor(ToPrint, EliteConsole.ErrorColor);
        }

        public static string PrintErrorLine(string ToPrint = "")
        {
            return PrintColorLine(ToPrint, EliteConsole.ErrorColor);
        }

        public static string PrintFormattedError(string ToPrint = "")
        {
            return PrintColorLine(EliteConsole.ErrorLabel + " " + ToPrint, EliteConsole.ErrorColor);
        }

        public static string PrintFormattedErrorLine(string ToPrint = "")
        {
            return PrintColorLine(EliteConsole.ErrorLabel + " " + ToPrint, EliteConsole.ErrorColor);
        }
    }
}
