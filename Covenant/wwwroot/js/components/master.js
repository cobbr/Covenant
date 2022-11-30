window.GetValue = (selector) => {
    return $(selector).val();
}

window.SetValue = (selector, value) => {
    return $(selector).val(value);
}

window.SetAttr = (selector, property, value) => {
    $(selector).attr(property, value);
}

window.RedirectToUrl = (url) => {
    window.location.href = url;
}

window.ReloadPage = () => {
    window.location.reload();
}

window.Toast = (selector, command) => {
    $(selector).toast(command);
}

window.DownloadFile = (filename, mediatype, base64) => {
    var link = document.createElement('a');
    link.download = filename;
    link.href = "data:" + mediatype + ";base64," + base64;
    document.body.appendChild(link); // Needed for Firefox
    link.click();
    document.body.removeChild(link);
}

window.ScrollToBottom = (selector) => {
    $(selector).animate({
        scrollTop: $(selector)[0].scrollHeight
    }, 1000, function () { });
};

window.TypeAheadSelectedValue = {};

window.InitializeTypeahead = (typeaheadselector, suggestions) => {
    var substringMatcher = function (strs) {
        return function findMatches(q, cb) {
            var matches, substrRegex;

            // an array that will be populated with substring matches
            matches = [];

            // regex used to determine if a string contains the substring `q`
            substrRegex = new RegExp(q, 'i');

            // iterate through the pool of strings and for any string that
            // contains the substring `q`, add it to the `matches` array
            $.each(strs, function (i, str) {
                if (substrRegex.test(str) && str.toLowerCase() != q.toLowerCase()) {
                    matches.push(str);
                }
            });

            cb(matches);
        };
    };

    $(typeaheadselector).typeahead({
        hint: true,
        highlight: true,
        minLength: 1
    },
        {
            name: 'suggestions',
            limit: 20,
            source: substringMatcher(suggestions)
        });

    $(typeaheadselector).on('typeahead:selected', function (event, selection) {
        window.TypeAheadSelectedValue[typeaheadselector] = selection;
    });
}

window.ClearSelectedTypeaheadVal = (typeaheadselector) => {
    window.TypeAheadSelectedValue[typeaheadselector] = "";
}

window.GetSelectedTypeaheadVal = (typeaheadselector) => {
    var val = window.TypeAheadSelectedValue[typeaheadselector];
    window.TypeAheadSelectedValue[typeaheadselector] = "";
    return val;
}

window.TypeAheadHasSuggestions = (typeaheadselector) => {
    if ($(typeaheadselector + " ~ .tt-menu").has(".tt-suggestion").length != 0) {
        return true;
    }
    return false;
}

window.SetTypeaheadVal = (typeaheadselector, val) => {
    $(typeaheadselector).typeahead('val', val);
}

window.InitializeCodeMirror = (element, theme, codereadonly) => {
    var editor;
    if (theme == undefined) {
        theme = "default";
    }
    if (codereadonly === undefined) {
        codereadonly = false;
    }
    if (element.classList.contains("code-mirror-csharp")) {
        editor = CodeMirror.fromTextArea(element, {
            lineNumbers: true,
            mode: "text/x-csharp",
            readOnly: codereadonly,
            theme: theme
        });
    }
    else if (element.classList.contains("code-mirror-html")) {
        editor = CodeMirror.fromTextArea(element, {
            lineNumbers: true,
            mode: "htmlmixed",
            theme: theme
        });
    }
    if (editor != undefined) {
        editor.on('change', function () {
            editor.save();
            var event = new Event('change');
            element.dispatchEvent(event);
        });
    }
    $(document).on('shown.bs.tab', 'a[data-toggle="tab"]', function () {
        editor.refresh();
    });
}

window.InitializeSelectPicker = (selectpickerselector, value) => {
    if (value == undefined) {
        $(selectpickerselector).selectpicker();
    }
    else {
        $(selectpickerselector).selectpicker('val', value);
    }
}

window.RefreshSelectPicker = (selector) => {
    $(selector).selectpicker('refresh');
}

window.ShowTab = (selector) => {
    $(selector).tab('show');
}

window.ActivateModal = (selector) => {
    $(selector).modal();
}

window.ModalCommand = (selector, command) => {
    $(selector).modal(command);
}

window.SetWindowLocation = (location) => {
    window.location.href = location;
}

window.CopyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
}

window.InitializeDateTimePicker = (datetimeid) => {
    $(datetimeid).datetimepicker({
        icons: {
            time: "fa fa-clock-o",
            date: "fa fa-calendar",
            up: "fa fa-arrow-up",
            down: "fa fa-arrow-down",
            previous: "fa fa-chevron-left",
            next: "fa fa-chevron-right",
            today: "fa fa-clock-o",
            clear: "fa fa-trash-o"
        }
    });
}

window.hierarchyArray = [];
const root_node = { id: 0, name: "Covenant", fill: "#232323" };
if(!window.hierarchyArray.includes(root_node)) {
        window.hierarchyArray.push(root_node);
    }

window.ClearGraph = (selector) => {
    window.hierarchyArray = [];
    const root_node = { id: 0, name: "Covenant", fill: "#232323" };
    if(!window.hierarchyArray.includes(root_node)) {
        window.hierarchyArray.push(root_node);
    }
}

window.HierarchyAddListener = (listenerId, listenerName) => {
    const node = { id: listenerId, name: listenerName, fill: "#D52728", parentId: 0 };
    if(!window.hierarchyArray.includes(node)) {
        window.hierarchyArray.push(node);
    }
}

window.HierarchyAddGruntToListener = (listenerId, gruntId, gruntName) => {
    const node = { id: gruntId, name: gruntName, fill: "#007BFF", parentId: listenerId };
    if(!window.hierarchyArray.includes(node)) {
        window.hierarchyArray.push(node);
    }
}

window.HierarchyAddGruntToListener_Inactive = (listenerId, gruntId, gruntName) => {
    const node = { id: gruntId, name: gruntName, fill: "#384A5E", parentId: listenerId };
    if(!window.hierarchyArray.includes(node)) {
        window.hierarchyArray.push(node);
    }
}

window.HierarchyAddGruntToGrunt = (parentGruntId, gruntId, gruntName) => {
    const node = { id: gruntId, name: gruntName, fill: "#2AA02C", parentId: parentGruntId };
    if(!window.hierarchyArray.includes(node)) {
        window.hierarchyArray.push(node);
    }
}

window.HierarchyAddGruntToGrunt_Inactive = (parentGruntId, gruntId, gruntName) => {
    const node = { id: gruntId, name: gruntName, fill: "#365037", parentId: parentGruntId };
    if(!window.hierarchyArray.includes(node)) {
        window.hierarchyArray.push(node);
    }
}

window.InitializeGraph = (selector) => {
    const data = d3.stratify()(window.hierarchyArray);

    // mouse event vars
    window.graphSelectedNode = null;
    window.graphMousedownNode = null;
    window.graphMouseupNode = null;

    window.resetMouseVars = () => {
        window.graphMousedownNode = null;
        window.graphMouseupNode = null;
    }

    Tree(data, selector);
}

window.GraphRestart = () => {};


// Copyright 2021 Observable, Inc.
// Released under the ISC license.
// https://observablehq.com/@d3/tree
function Tree(data, selector, { // data is either tabular (array of objects) or hierarchy (nested objects)
  path, // as an alternative to id and parentId, returns an array identifier, imputing internal nodes
  id = Array.isArray(data) ? d => d.id : null, // if tabular data, given a d in data, returns a unique identifier (string)
  parentId = Array.isArray(data) ? d => d.parentId : null, // if tabular data, given a node d, returns its parent’s identifier
  children, // if hierarchical data, given a d in data, returns its children
  tree = d3.tree, // layout algorithm (typically d3.tree or d3.cluster)
  sort, // how to sort nodes prior to layout (e.g., (a, b) => d3.descending(a.height, b.height))
  label = d => d.data.name, // given a node d, returns the display name
  title, // given a node d, returns its hover text
  link, // given a node d, its link (if any)
  linkTarget = "_blank", // the target attribute for links (if any)
  width = 1080, // outer width, in pixels
  height = 640, // outer height, in pixels
  r = 8, // radius of nodes
  padding = 1, // horizontal padding for first and last column
  fill = d => d.data.fill, // fill for nodes
  fillOpacity, // fill opacity for nodes
  stroke = "#555", // stroke for links
  strokeWidth = 1.5, // stroke width for links
  strokeOpacity = 0.4, // stroke opacity for links
  strokeLinejoin, // stroke line join for links
  strokeLinecap, // stroke line cap for links
  halo = "#ddd", // color of label halo 
  haloWidth = 3, // padding around the labels
  highlight = () => false,
} = {}) {

  // If id and parentId options are specified, or the path option, use d3.stratify
  // to convert tabular data to a hierarchy; otherwise we assume that the data is
  // specified as an object {children} with nested objects (a.k.a. the “flare.json”
  // format), and use d3.hierarchy.
  const root = path != null ? d3.stratify().path(path)(data)
      : id != null || parentId != null ? d3.stratify().id(id).parentId(parentId)(data)
      : d3.hierarchy(data, children);

  // Sort the nodes.
  if (sort != null) root.sort(sort);

  // Compute labels and titles.
  const descendants = root.descendants();
  const L = label == null ? null : descendants.map(d => label(d.data, d));

  // Compute the layout.
  //const dx = 20;
  const dx = height / (window.hierarchyArray.length);
  const dy = width / (root.height + padding);
  tree().nodeSize([dx, dy])(root);

// Center the tree.
  let x0 = Infinity;
  let x1 = -x0;
  root.each(d => {
    if (d.x > x1) x1 = d.x;
    if (d.x < x0) x0 = d.x;
  });

  // Compute the default height.
  if (height === undefined) height = x1 - x0 + dx * 2;

  const svg = d3.select(selector).append("svg")
      .attr("viewBox", [-dy * padding / 2, x0 - dx, width, height])
      .attr("width", width)
      .attr("height", height)
      .on('contextmenu', () => { d3.event.preventDefault(); })
      .attr("style", "max-width: 100%; height: auto; height: intrinsic;")
      .attr("font-family", "sans-serif")
      .attr("font-size", 10);

  svg.append("g")
      .attr("fill", "none")
      .attr("stroke", stroke)
      .attr("stroke-opacity", strokeOpacity)
      .attr("stroke-linecap", strokeLinecap)
      .attr("stroke-linejoin", strokeLinejoin)
      .attr("stroke-width", strokeWidth)
    .selectAll("path")
      .data(root.links())
      .join("path")
        .attr("d", d3.linkHorizontal()
            .x(d => d.y)
            .y(d => d.x));

  const node = svg.append("g")
    .selectAll("a")
    .data(root.descendants())
    .join("a")
      .attr("xlink:href", link == null ? null : d => link(d.data, d))
      .attr("target", link == null ? null : linkTarget)
      .attr("transform", d => `translate(${d.y},${d.x})`);

  node.append("circle")
      .attr("fill", d => fill(d.data, d))
      .attr("r", r)
      .on('click', (d) => {
            // select node
            window.graphMousedownNode = d;
            window.graphSelectedNode = (window.graphMousedownNode === window.graphSelectedNode) ? null : window.graphMousedownNode;
            $("#" + window.graphMousedownNode.data.id + "-tab").tab('show');
        });

  if (title != null) node.append("title")
      .text(d => title(d.data, d));

  if (L) node.append("text")
      .attr("dy", "0.32em")
      .attr("x", d => d.children ? -10 : 10)
      .attr("text-anchor", d => d.children ? "end" : "start")
      .attr("paint-order", "stroke")
      .attr("fill", halo)
      .text((d, i) => L[i]);

  return svg.node();
}
