// <auto-generated>
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Covenant.API.Models
{
    using Microsoft.Rest;
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    public partial class Folder
    {
        /// <summary>
        /// Initializes a new instance of the Folder class.
        /// </summary>
        public Folder()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the Folder class.
        /// </summary>
        public Folder(string fullName, string name, int? id = default(int?), long? length = default(long?), System.DateTime? creationTime = default(System.DateTime?), System.DateTime? lastAccessTime = default(System.DateTime?), System.DateTime? lastWriteTime = default(System.DateTime?), bool? enumerated = default(bool?), int? parentId = default(int?), int? gruntId = default(int?), IList<FolderFileNode> nodes = default(IList<FolderFileNode>))
        {
            Id = id;
            FullName = fullName;
            Name = name;
            Length = length;
            CreationTime = creationTime;
            LastAccessTime = lastAccessTime;
            LastWriteTime = lastWriteTime;
            Enumerated = enumerated;
            ParentId = parentId;
            GruntId = gruntId;
            Nodes = nodes;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "id")]
        public int? Id { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "fullName")]
        public string FullName { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "name")]
        public string Name { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "length")]
        public long? Length { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "creationTime")]
        public System.DateTime? CreationTime { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "lastAccessTime")]
        public System.DateTime? LastAccessTime { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "lastWriteTime")]
        public System.DateTime? LastWriteTime { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "enumerated")]
        public bool? Enumerated { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "parentId")]
        public int? ParentId { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "gruntId")]
        public int? GruntId { get; set; }

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "nodes")]
        public IList<FolderFileNode> Nodes { get; set; }

        /// <summary>
        /// Validate the object.
        /// </summary>
        /// <exception cref="ValidationException">
        /// Thrown if validation fails
        /// </exception>
        public virtual void Validate()
        {
            if (FullName == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "FullName");
            }
            if (Name == null)
            {
                throw new ValidationException(ValidationRules.CannotBeNull, "Name");
            }
            if (Nodes != null)
            {
                foreach (var element in Nodes)
                {
                    if (element != null)
                    {
                        element.Validate();
                    }
                }
            }
        }
    }
}
