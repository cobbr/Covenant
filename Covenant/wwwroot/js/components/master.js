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

// set up SVG for D3
window.graphWidth = 600;
window.graphHeight = 600;
window.graphColors = d3.scaleOrdinal(d3.schemeCategory10);
window.graphArrowColor = '#999999';
window.graphNodes = [];
window.graphLinks = [];
window.graphLastNodeId = 0;

window.ClearGraph = (selector) => {
    window.graphNodes = [];
    window.graphLinks = [];
    window.graphLastNodeId = 0;
}

window.GraphDisplayGrunt = (id, name) => {
    const node = { id: id, name: name, reflexive: false, x: 50, y: 50, color: "#007BFF" };
    if (!window.graphNodes.includes(node)) {
        window.graphNodes.push(node);
        window.GraphRestart();
    }
}

window.GraphDisplayListener = (id, name) => {
    const node = { id: id, name: name, reflexive: false, x: 50, y: 50, color: "#D52728" };
    if (!window.graphNodes.includes(node)) {
        window.graphNodes.push(node);
        window.GraphRestart();
    }
}

window.GraphDisplayGruntLink = (idFrom, idTo) => {
    const fromNode = window.graphNodes.filter(
        function (node) { return node.id == idFrom }
    )[0];
    const toNode = window.graphNodes.filter(
        function (node) { return node.id == idTo }
    )[0];
    toNode.color = "#2BA02C";
    const link = { source: fromNode, target: toNode, left: true, right: false, color: "#999999" };
    if (!window.graphLinks.includes(link)) {
        window.graphLinks.push(link);
        window.GraphRestart();
    }
}

window.GraphDisplayGruntListenerLink = (listenerId, gruntId) => {
    const listenerNode = window.graphNodes.filter(
        function (node) { return node.id == listenerId }
    )[0];
    const gruntNode = window.graphNodes.filter(
        function (node) { return node.id == gruntId }
    )[0];
    const link = { source: listenerNode, target: gruntNode, left: true, right: false, color: "#999999" };
    if (!window.graphLinks.includes(link)) {
        window.graphLinks.push(link);
        window.GraphRestart();
    }
}

window.InitializeGraph = (selector) => {
    window.graphsvg = d3.select(selector)
        .append('svg')
        .on('contextmenu', () => { d3.event.preventDefault(); })
        .attr('width', window.graphWidth)
        .attr('height', window.graphHeight)
        .attr('fill', '#999999');

    // set up initial nodes and links
    //  - nodes are known by 'id', not by index in array.
    //  - reflexive edges are indicated on the node (as a bold black circle).
    //  - links are always source < target; edge directions are set by 'left' and 'right'.

    // init D3 force layout
    window.graphForce = d3.forceSimulation()
        .force('link', d3.forceLink().id((d) => d.id).distance(150))
        .force('charge', d3.forceManyBody().strength(-500))
        .force('x', d3.forceX(window.graphWidth / 2))
        .force('y', d3.forceY(window.graphHeight / 2))
        .on('tick', tick);

    // init D3 drag support
    window.graphDrag = d3.drag()
        // Mac Firefox doesn't distinguish between left/right click when Ctrl is held... 
        .filter(() => d3.event.button === 0 || d3.event.button === 2)
        .on('start', (d) => {
            if (!d3.event.active) window.graphForce.alphaTarget(0.3).restart();

            d.fx = d.x;
            d.fy = d.y;
        })
        .on('drag', (d) => {
            d.fx = d3.event.x;
            d.fy = d3.event.y;
        })
        .on('end', (d) => {
            if (!d3.event.active) window.graphForce.alphaTarget(0);

            d.fx = null;
            d.fy = null;
        });

    // define arrow markers for graph links
    window.graphsvg.append('svg:defs').append('svg:marker')
        .attr('id', 'end-arrow')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 6)
        .attr('markerWidth', 3)
        .attr('markerHeight', 3)
        .attr('orient', 'auto')
        .append('svg:path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', window.graphArrowColor);

    window.graphsvg.append('svg:defs').append('svg:marker')
        .attr('id', 'start-arrow')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 4)
        .attr('markerWidth', 3)
        .attr('markerHeight', 3)
        .attr('orient', 'auto')
        .append('svg:path')
        .attr('d', 'M10,-5L0,0L10,5')
        .attr('fill', window.graphArrowColor);

    // line displayed when dragging new nodes
    window.graphDragLine = window.graphsvg.append('svg:path')
        .attr('class', 'link dragline hidden')
        .attr('d', 'M0,0L0,0');

    // handles to link and node element groups
    window.graphPath = window.graphsvg.append('svg:g').selectAll('path');
    window.graphCircle = window.graphsvg.append('svg:g').selectAll('g');

    // mouse event vars
    window.graphSelectedNode = null;
    window.graphSelectedLink = null;
    window.graphMousedownLink = null;
    window.graphMousedownNode = null;
    window.graphMouseupNode = null;

    window.resetMouseVars = () => {
        window.graphMousedownNode = null;
        window.graphMouseupNode = null;
        window.graphMousedownLink = null;
    }

    // update force layout (called automatically each iteration)
    function tick() {
        // draw directed edges with proper padding from node centers
        window.graphPath.attr('d', (d) => {
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

        window.graphCircle.attr('transform', (d) => `translate(${d.x},${d.y})`);
    }

    window.graphMousedown = () => {
        // because :active only works in WebKit?
        window.graphsvg.classed('active', true);

        if (d3.event.ctrlKey || window.graphMousedownNode || window.graphMousedownLink) return;

        // insert new node at point
        const point = d3.mouse(this);
        const node = { id: ++window.graphLastNodeId, reflexive: false, x: point[0], y: point[1] };
        // nodes.push(node);

        window.GraphRestart();
    }

    window.graphMousemove = () => {
        if (!window.graphMousedownNode) return;

        // update drag line
        window.graphDragLine.attr('d', `M${window.graphMousedownNode.x},${window.graphMousedownNode.y}L${d3.mouse(this)[0]},${d3.mouse(this)[1]}`);
    }

    window.graphMouseup = () => {
        if (window.graphMousedownNode) {
            // hide drag line
            window.graphDragLine
                .classed('hidden', true)
                .style('marker-end', '');
        }

        // because :active only works in WebKit?
        window.graphsvg.classed('active', false);

        // clear mouse event vars
        window.resetMouseVars();
    }

    window.graphSpliceLinksForNode = (node) => {
        const toSplice = window.graphLinks.filter((l) => l.source === node || l.target === node);
        for (const l of toSplice) {
            window.graphLinks.splice(window.graphLinks.indexOf(l), 1);
        }
    }

    // only respond once per keydown
    window.graphLastKeyDown = -1;

    window.graphKeydown = () => {
        if (window.graphLastKeyDown !== -1) return;
        window.graphLastKeyDown = d3.event.keyCode;

        // ctrl
        if (d3.event.keyCode === 17) {
            window.graphCircle.call(window.graphDrag);
            window.graphsvg.classed('ctrl', true);
            return;
        }

        if (!window.graphSelectedNode && !window.graphSelectedLink) return;

        switch (d3.event.keyCode) {
            case 8: // backspace
            case 46: // delete
                if (window.graphSelectedNode) {
                    window.graphNodes.splice(window.graphNodes.indexOf(window.graphSelectedNode), 1);
                    window.graphSpliceLinksForNode(window.graphSelectedNode);
                } else if (window.graphSelectedLink) {
                    window.graphLinks.splice(window.graphLinks.indexOf(window.graphSelectedLink), 1);
                }
                window.graphSelectedLink = null;
                window.graphSelectedNode = null;
                window.GraphRestart();
                break;
            case 66: // B
                if (window.graphSelectedLink) {
                    // set link direction to both left and right
                    window.graphSelectedLink.left = true;
                    window.graphSelectedLink.right = true;
                }
                window.GraphRestart();
                break;
            case 76: // L
                if (window.graphSelectedLink) {
                    // set link direction to left only
                    window.graphSelectedLink.left = true;
                    window.graphSelectedLink.right = false;
                }
                window.GraphRestart();
                break;
            case 82: // R
                if (window.graphSelectedNode) {
                    // toggle node reflexivity
                    window.graphSelectedNode.reflexive = !window.graphSelectedNode.reflexive;
                } else if (window.graphSelectedLink) {
                    // set link direction to right only
                    window.graphSelectedLink.left = false;
                    window.graphSelectedLink.right = true;
                }
                window.GraphRestart();
                break;
        }
    }

    window.graphKeyup = () => {
        window.graphLastKeyDown = -1;

        // ctrl
        if (d3.event.keyCode === 17) {
            window.graphCircle.on('.drag', null);
            window.graphsvg.classed('ctrl', false);
        }
    }

    // app starts here
    window.graphsvg.on('mousedown', window.graphMousedown)
        .on('mousemove', window.graphMousemove)
        .on('mouseup', window.graphMouseup);
    d3.select(window)
        .on('keydown', window.graphKeydown)
        .on('keyup', window.graphKeyup);
    window.GraphRestart();
}

window.GraphRestart = () => {
    // assignCoordinates();
    // path (link) group
    window.graphPath = window.graphPath.data(window.graphLinks);

    // update existing links
    window.graphPath.style('marker-start', (d) => d.left ? 'url(#start-arrow)' : '')
        .style('marker-end', (d) => d.right ? 'url(#end-arrow)' : '')
        .style('fill', (d) => (d === window.graphSelectedLink) ? d3.rgb(window.graphArrowColor).brighter().toString() : window.graphArrowColor)
        .style('stroke', (d) => (d === window.graphSelectedLink) ? d3.rgb(window.graphArrowColor).brighter().toString() : window.graphArrowColor);

    // remove old links
    window.graphPath.exit().remove();

    // add new links
    window.graphPath = window.graphPath.enter().append('svg:path')
        .attr('class', 'link')
        .style('marker-start', (d) => d.left ? 'url(#start-arrow)' : '')
        .style('marker-end', (d) => d.right ? 'url(#end-arrow)' : '')
        .style('fill', (d) => (d === window.graphSelectedLink) ? d3.rgb(window.graphArrowColor).brighter().toString() : window.graphArrowColor)
        .style('stroke', (d) => (d === window.graphSelectedLink) ? d3.rgb(window.graphArrowColor).brighter().toString() : window.graphArrowColor)
        .on('mousedown', (d) => {
            if (d3.event.ctrlKey) return;

            // select link
            window.graphMousedownLink = d;
            window.graphSelectedLink = (window.graphMousedownLink === window.graphSelectedLink) ? null : window.graphMousedownLink;
            window.graphSelectedNode = null;
            window.GraphRestart();
        })
        .merge(window.graphPath);
    // circle (node) group
    // NB: the function arg is crucial here! nodes are known by id, not by index!
    window.graphCircle = window.graphCircle.data(window.graphNodes, (d) => d.id);

    // update existing nodes (reflexive & selected visual states)
    window.graphCircle.selectAll('circle')
        .style('fill', (d) => (d === window.graphSelectedNode) ? d3.rgb(d.color).brighter().toString() : d.color)
        .style('stroke', (d) => d3.rgb(d.color).darker().toString())
        .classed('reflexive', (d) => d.reflexive);

    // remove old nodes
    window.graphCircle.exit().remove();

    // add new nodes
    const g = window.graphCircle.enter().append('svg:g');

    g.append('svg:circle')
        .attr('class', 'node')
        .attr('r', 35)
        .style('fill', (d) => (d === window.graphSelectedNode) ? d3.rgb(d.color).brighter().toString() : d.color)
        .style('stroke', (d) => d3.rgb(d.color).darker().toString())
        .classed('reflexive', (d) => d.reflexive)
        .on('mouseover', function (d) {
            if (!window.graphMousedownNode || d === window.graphMousedownNode) return;
            // enlarge target node
            d3.select(this).attr('transform', 'scale(1.1)');
        })
        .on('mouseout', function (d) {
            if (!window.graphMousedownNode || d === window.graphMousedownNode) return;
            // unenlarge target node
            d3.select(this).attr('transform', '');
        })
        .on('mousedown', (d) => {
            if (d3.event.ctrlKey) return;

            // select node
            window.graphMousedownNode = d;
            window.graphSelectedNode = (window.graphMousedownNode === window.graphSelectedNode) ? null : window.graphMousedownNode;
            window.graphSelectedLink = null;
            $("#" + window.graphMousedownNode.id + "-tab").tab('show');
            // reposition drag line
            // dragLine
            //  .style('marker-end', 'url(#end-arrow)')
            //   .classed('hidden', false)
            //  .attr('d', `M${mousedownNode.x},${mousedownNode.y}L${mousedownNode.x},${mousedownNode.y}`);

            window.GraphRestart();
        })
        .on('mouseup', function (d) {
            if (!window.graphMousedownNode) return;

            // needed by FF
            // dragLine
            //   .classed('hidden', true)
            //   .style('marker-end', '');

            // check for drag-to-self
            window.graphMouseupNode = d;
            if (window.graphMouseupNode === window.graphMousedownNode) {
                window.resetMouseVars();
                return;
            }

            // unenlarge target node
            d3.select(this).attr('transform', '');

            // add link to graph (update if exists)
            // NB: links are strictly source < target; arrows separately specified by booleans
            const isRight = window.graphMousedownNode.id < window.graphMouseupNode.id;
            const source = isRight ? window.graphMousedownNode : window.graphMouseupNode;
            const target = isRight ? window.graphMouseupNode : window.graphMousedownNode;

            // const link = links.filter((l) => l.source === source && l.target === target)[0];
            // if (link) {
            //   link[isRight ? 'right' : 'left'] = true;
            // } else {
            //   links.push({ source, target, left: !isRight, right: isRight });
            // }

            // select new link
            window.graphSelectedLink = link;
            window.graphSelectedNode = null;
            window.GraphRestart();
        });

    // show node names

    g.append('svg:text')
        .attr('x', 0)
        .attr('y', 4)
        .attr('class', 'id')
        .style('fill', 'rgba(255,255,255,0.8)')
        .text((d) => d.name);

    window.graphCircle = g.merge(window.graphCircle);

    // set the graph in motion
    window.graphForce
        .nodes(window.graphNodes)
        .force('link').links(window.graphLinks);

    // window.graphForce.alphaTarget(0.3).restart();
};