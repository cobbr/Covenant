using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Diagnostics.CodeAnalysis;
using Newtonsoft.Json;

namespace Covenant.Models.Grunts
{
    public interface IFolderFileNode
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        [Required]
        public string FullName { get; set; }
        [Required]
        public string Name { get; set; }
        public long Length { get; set; }
        public DateTime CreationTime { get; set; }
        public DateTime LastAccessTime { get; set; }
        public DateTime LastWriteTime { get; set; }

        public int? ParentId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public Folder Parent { get; set; }

        public int GruntId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public Grunt Grunt { get; set; }
    }

    public abstract class FolderFileNode
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }

        [Required]
        public string FullName { get; set; }
        [Required]
        public string Name { get; set; }
        public long Length { get; set; }
        public DateTime CreationTime { get; set; }
        public DateTime LastAccessTime { get; set; }
        public DateTime LastWriteTime { get; set; }

        public bool Enumerated { get; set; } = false;

        public int? ParentId { get; set; }

        public int GruntId { get; set; }
        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public Grunt Grunt { get; set; }
    }

    public class Folder : FolderFileNode
    {
        public IList<FolderFileNode> Nodes { get; set; } = new List<FolderFileNode>();

        [JsonIgnore, System.Text.Json.Serialization.JsonIgnore]
        public Grunt RootGrunt { get; set; }
    }

    public class FolderFile : FolderFileNode { }
}
