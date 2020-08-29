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

window.InitializeGruntDataTable = () => {
    $('#grunt-table').DataTable({
        "pageLength": 5,
        "lengthChange": false,
        "searching": false,
        "info": false,
        "order": [[5, "desc"]]
    });
}

window.InitializeListenerDataTable = () => {
    $('#listeners-table').DataTable({
        "pageLength": 50,
        "info": false,
        "lengthChange": false,
        "searching": false
    });
}

window.InitializeProfileDataTable = () => {
    $('#profiles-table').DataTable({
        "pageLength": 50,
        "info": false,
        "lengthChange": false,
        "searching": false
    });
}

window.InitializeImplantTemplateDataTable = () => {
    $('#profiles-table').DataTable({
        "pageLength": 50,
        "info": false,
        "lengthChange": false,
        "searching": false
    });
}

window.InitializeDataTable = (selector, pagelength, info, lengthChange, searching) => {
    if (!$.fn.dataTable.isDataTable(selector)) {
        if (pagelength === undefined) {
            pagelength = 50;
        }
        if (info === undefined) {
            info = false;
        }
        if (lengthChange === undefined) {
            lengthChange = false;
        }
        if (searching === undefined) {
            searching = true;
        }
        var dt = $(selector).DataTable({
            "pageLength": pagelength,
            "info": info,
            "lengthChange": lengthChange,
            "searching": searching
        });
    }
}

window.AddDataTableRow = (selector, row) => {
    if ($.fn.dataTable.isDataTable(selector)) {
        $(selector).DataTable().row.add(row).draw(false);
    }
}

window.DestroyDataTable = (selector) => {
    if ($.fn.dataTable.isDataTable(selector)) {
        $(selector).DataTable().destroy();
    }
}

window.InitializeDataDataTable = (selector) => {
    $(selector).DataTable({
        "info": false,
        "pageLength": 50,
        "sDom": 'Rfrtilp'
    });
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

// set up SVG for D3
window.width = 600;
window.height = 600;
window.colors = d3.scaleOrdinal(d3.schemeCategory10);
window.arrowColor = '#999999';
window.nodes = [];
window.links = [];
window.lastNodeId = 0;

window.GraphDisplayGrunt = (id, name) => {
    const node = { id: id, name: name, reflexive: false, x: 50, y: 50, color: "#007BFF" };
    window.nodes.push(node);
    window.GraphRestart();
}

window.GraphDisplayListener = (id, name) => {
    const node = { id: id, name: name, reflexive: false, x: 50, y: 50, color: "#D52728" };
    window.nodes.push(node);
    window.GraphRestart();
}

window.GraphDisplayGruntLink = (idFrom, idTo) => {
    const fromNode = window.nodes.filter(
        function (node) { return node.id == idFrom }
    )[0];
    const toNode = window.nodes.filter(
        function (node) { return node.id == idTo }
    )[0];
    toNode.color = "#2BA02C";
    const link = { source: fromNode, target: toNode, left: true, right: false, color: "#999999" };
    window.links.push(link);
    window.GraphRestart();
}

window.GraphDisplayGruntListenerLink = (listenerId, gruntId) => {
    const listenerNode = window.nodes.filter(
        function (node) { return node.id == listenerId }
    )[0];
    const gruntNode = window.nodes.filter(
        function (node) { return node.id == gruntId }
    )[0];
    const link = { source: listenerNode, target: gruntNode, left: true, right: false, color: "#999999" };
    window.links.push(link);
    window.GraphRestart();
}

window.InitializeGraph = (selector) => {
    window.svg = d3.select(selector)
        .append('svg')
        .on('contextmenu', () => { d3.event.preventDefault(); })
        .attr('width', window.width)
        .attr('height', window.height)
        .attr('fill', '#999999');

    // set up initial nodes and links
    //  - nodes are known by 'id', not by index in array.
    //  - reflexive edges are indicated on the node (as a bold black circle).
    //  - links are always source < target; edge directions are set by 'left' and 'right'.

    // init D3 force layout
    window.force = d3.forceSimulation()
        .force('link', d3.forceLink().id((d) => d.id).distance(150))
        .force('charge', d3.forceManyBody().strength(-500))
        .force('x', d3.forceX(window.width / 2))
        .force('y', d3.forceY(window.height / 2))
        .on('tick', tick);

    // init D3 drag support
    window.drag = d3.drag()
        // Mac Firefox doesn't distinguish between left/right click when Ctrl is held... 
        .filter(() => d3.event.button === 0 || d3.event.button === 2)
        .on('start', (d) => {
            if (!d3.event.active) window.force.alphaTarget(0.3).restart();

            d.fx = d.x;
            d.fy = d.y;
        })
        .on('drag', (d) => {
            d.fx = d3.event.x;
            d.fy = d3.event.y;
        })
        .on('end', (d) => {
            if (!d3.event.active) window.force.alphaTarget(0);

            d.fx = null;
            d.fy = null;
        });

    // define arrow markers for graph links
    window.svg.append('svg:defs').append('svg:marker')
        .attr('id', 'end-arrow')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 6)
        .attr('markerWidth', 3)
        .attr('markerHeight', 3)
        .attr('orient', 'auto')
        .append('svg:path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', window.arrowColor);

    window.svg.append('svg:defs').append('svg:marker')
        .attr('id', 'start-arrow')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 4)
        .attr('markerWidth', 3)
        .attr('markerHeight', 3)
        .attr('orient', 'auto')
        .append('svg:path')
        .attr('d', 'M10,-5L0,0L10,5')
        .attr('fill', window.arrowColor);

    // line displayed when dragging new nodes
    window.dragLine = window.svg.append('svg:path')
        .attr('class', 'link dragline hidden')
        .attr('d', 'M0,0L0,0');

    // handles to link and node element groups
    window.path = window.svg.append('svg:g').selectAll('path');
    window.circle = window.svg.append('svg:g').selectAll('g');

    // mouse event vars
    window.selectedNode = null;
    window.selectedLink = null;
    window.mousedownLink = null;
    window.mousedownNode = null;
    window.mouseupNode = null;

    window.resetMouseVars = () => {
        window.mousedownNode = null;
        window.mouseupNode = null;
        window.mousedownLink = null;
    }

    // update force layout (called automatically each iteration)
    function tick() {
        // draw directed edges with proper padding from node centers
        window.path.attr('d', (d) => {
            const deltaX = d.target.x - d.source.x;
            const deltaY = d.target.y - d.source.y;
            const dist = Math.sqrt(deltaX * deltaX + deltaY * deltaY);
            const normX = deltaX / dist;
            const normY = deltaY / dist;
            const sourcePadding = 40;
            const targetPadding = 36;
            const sourceX = d.source.x + (sourcePadding * normX);
            const sourceY = d.source.y + (sourcePadding * normY);
            const targetX = d.target.x - (targetPadding * normX);
            const targetY = d.target.y - (targetPadding * normY);

            return `M${sourceX},${sourceY}L${targetX},${targetY}`;
        });

        window.circle.attr('transform', (d) => `translate(${d.x},${d.y})`);
    }

    window.mousedown = () => {
        // because :active only works in WebKit?
        window.svg.classed('active', true);

        if (d3.event.ctrlKey || window.mousedownNode || window.mousedownLink) return;

        // insert new node at point
        const point = d3.mouse(this);
        const node = { id: ++window.lastNodeId, reflexive: false, x: point[0], y: point[1] };
        // nodes.push(node);

        window.GraphRestart();
    }

    window.mousemove = () => {
        if (!window.mousedownNode) return;

        // update drag line
        window.dragLine.attr('d', `M${window.mousedownNode.x},${window.mousedownNode.y}L${d3.mouse(this)[0]},${d3.mouse(this)[1]}`);
    }

    window.mouseup = () => {
        if (window.mousedownNode) {
            // hide drag line
            window.dragLine
                .classed('hidden', true)
                .style('marker-end', '');
        }

        // because :active only works in WebKit?
        window.svg.classed('active', false);

        // clear mouse event vars
        window.resetMouseVars();
    }

    window.spliceLinksForNode = (node) => {
        const toSplice = window.links.filter((l) => l.source === node || l.target === node);
        for (const l of toSplice) {
            window.links.splice(window.links.indexOf(l), 1);
        }
    }

    // only respond once per keydown
    window.lastKeyDown = -1;

    window.keydown = () => {
        d3.event.preventDefault();

        if (window.lastKeyDown !== -1) return;
        window.lastKeyDown = d3.event.keyCode;

        // ctrl
        if (d3.event.keyCode === 17) {
            window.circle.call(window.drag);
            window.svg.classed('ctrl', true);
            return;
        }

        if (!window.selectedNode && !window.selectedLink) return;

        switch (d3.event.keyCode) {
            case 8: // backspace
            case 46: // delete
                if (window.selectedNode) {
                    window.nodes.splice(window.nodes.indexOf(window.selectedNode), 1);
                    window.spliceLinksForNode(window.selectedNode);
                } else if (window.selectedLink) {
                    window.links.splice(window.links.indexOf(window.selectedLink), 1);
                }
                window.selectedLink = null;
                window.selectedNode = null;
                window.GraphRestart();
                break;
            case 66: // B
                if (window.selectedLink) {
                    // set link direction to both left and right
                    window.selectedLink.left = true;
                    window.selectedLink.right = true;
                }
                window.GraphRestart();
                break;
            case 76: // L
                if (window.selectedLink) {
                    // set link direction to left only
                    window.selectedLink.left = true;
                    window.selectedLink.right = false;
                }
                window.GraphRestart();
                break;
            case 82: // R
                if (window.selectedNode) {
                    // toggle node reflexivity
                    window.selectedNode.reflexive = !window.selectedNode.reflexive;
                } else if (window.selectedLink) {
                    // set link direction to right only
                    window.selectedLink.left = false;
                    window.selectedLink.right = true;
                }
                window.GraphRestart();
                break;
        }
    }

    window.keyup = () => {
        window.lastKeyDown = -1;

        // ctrl
        if (d3.event.keyCode === 17) {
            window.circle.on('.drag', null);
            window.svg.classed('ctrl', false);
        }
    }

    // app starts here
    window.svg.on('mousedown', window.mousedown)
        .on('mousemove', window.mousemove)
        .on('mouseup', window.mouseup);
    d3.select(window)
        .on('keydown', window.keydown)
        .on('keyup', window.keyup);
    window.GraphRestart();
}

window.GraphRestart = () => {
    // assignCoordinates();
    // path (link) group
    window.path = window.path.data(window.links);

    // update existing links
    window.path.style('marker-start', (d) => d.left ? 'url(#start-arrow)' : '')
        .style('marker-end', (d) => d.right ? 'url(#end-arrow)' : '')
        .style('fill', (d) => (d === window.selectedLink) ? d3.rgb(window.arrowColor).brighter().toString() : window.arrowColor)
        .style('stroke', (d) => (d === window.selectedLink) ? d3.rgb(window.arrowColor).brighter().toString() : window.arrowColor);

    // remove old links
    window.path.exit().remove();

    // add new links
    window.path = window.path.enter().append('svg:path')
        .attr('class', 'link')
        .style('marker-start', (d) => d.left ? 'url(#start-arrow)' : '')
        .style('marker-end', (d) => d.right ? 'url(#end-arrow)' : '')
        .style('fill', (d) => (d === window.selectedLink) ? d3.rgb(window.arrowColor).brighter().toString() : window.arrowColor)
        .style('stroke', (d) => (d === window.selectedLink) ? d3.rgb(window.arrowColor).brighter().toString() : window.arrowColor)
        .on('mousedown', (d) => {
            if (d3.event.ctrlKey) return;

            // select link
            window.mousedownLink = d;
            window.selectedLink = (window.mousedownLink === window.selectedLink) ? null : window.mousedownLink;
            window.selectedNode = null;
            window.GraphRestart();
        })
        .merge(window.path);
    // circle (node) group
    // NB: the function arg is crucial here! nodes are known by id, not by index!
    window.circle = window.circle.data(window.nodes, (d) => d.id);

    // update existing nodes (reflexive & selected visual states)
    window.circle.selectAll('circle')
        .style('fill', (d) => (d === window.selectedNode) ? d3.rgb(d.color).brighter().toString() : d.color)
        .style('stroke', (d) => d3.rgb(d.color).darker().toString())
        .classed('reflexive', (d) => d.reflexive);

    // remove old nodes
    window.circle.exit().remove();

    // add new nodes
    const g = window.circle.enter().append('svg:g');

    g.append('svg:circle')
        .attr('class', 'node')
        .attr('r', 35)
        .style('fill', (d) => (d === window.selectedNode) ? d3.rgb(d.color).brighter().toString() : d.color)
        .style('stroke', (d) => d3.rgb(d.color).darker().toString())
        .classed('reflexive', (d) => d.reflexive)
        .on('mouseover', function (d) {
            if (!window.mousedownNode || d === window.mousedownNode) return;
            // enlarge target node
            d3.select(this).attr('transform', 'scale(1.1)');
        })
        .on('mouseout', function (d) {
            if (!window.mousedownNode || d === window.mousedownNode) return;
            // unenlarge target node
            d3.select(this).attr('transform', '');
        })
        .on('mousedown', (d) => {
            if (d3.event.ctrlKey) return;

            // select node
            window.mousedownNode = d;
            window.selectedNode = (window.mousedownNode === window.selectedNode) ? null : window.mousedownNode;
            window.selectedLink = null;
            $("#" + window.mousedownNode.id + "-tab").tab('show');
            // reposition drag line
            // dragLine
            //  .style('marker-end', 'url(#end-arrow)')
            //   .classed('hidden', false)
            //  .attr('d', `M${mousedownNode.x},${mousedownNode.y}L${mousedownNode.x},${mousedownNode.y}`);

            window.GraphRestart();
        })
        .on('mouseup', function (d) {
            if (!window.mousedownNode) return;

            // needed by FF
            // dragLine
            //   .classed('hidden', true)
            //   .style('marker-end', '');

            // check for drag-to-self
            window.mouseupNode = d;
            if (window.mouseupNode === window.mousedownNode) {
                window.resetMouseVars();
                return;
            }

            // unenlarge target node
            d3.select(this).attr('transform', '');

            // add link to graph (update if exists)
            // NB: links are strictly source < target; arrows separately specified by booleans
            const isRight = window.mousedownNode.id < window.mouseupNode.id;
            const source = isRight ? window.mousedownNode : window.mouseupNode;
            const target = isRight ? window.mouseupNode : window.mousedownNode;

            // const link = links.filter((l) => l.source === source && l.target === target)[0];
            // if (link) {
            //   link[isRight ? 'right' : 'left'] = true;
            // } else {
            //   links.push({ source, target, left: !isRight, right: isRight });
            // }

            // select new link
            window.selectedLink = link;
            window.selectedNode = null;
            window.GraphRestart();
        });

    // show node names
    g.append('svg:text')
        .attr('x', 0)
        .attr('y', 4)
        .attr('class', 'id')
        .style('fill', 'rgba(255,255,255,0.8)')
        .text((d) => d.name);

    window.circle = g.merge(window.circle);

    // set the graph in motion
    window.force
        .nodes(window.nodes)
        .force('link').links(window.links);

    window.force.alphaTarget(0.3).restart();
};