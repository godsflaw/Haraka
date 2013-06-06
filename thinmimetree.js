// Thin MIME Tree object

var mimelib = require("mimelib");
 
function ThinMimeTree() {
    if (false === (this instanceof ThinMimeTree)) {
      return new ThinMimeTree();
    }

    this.root     = "";
    this.tree     = {};
    this.nodes    = 0;
    this.boundary = [];
}

// Public functions

ThinMimeTree.prototype.add_boundary = function (boundary, offset) {
    if (!this.tree[boundary]) {
        if (!this.nodes) {
            this.root = boundary;
        }
        this.tree[boundary] = [];
        this.boundary.unshift(boundary);
        this.nodes++;
    }
    if (this.tree[boundary].length) {
      this.tree[boundary][this.tree[boundary].length - 1].end = offset - 1;
    }
    this.tree[boundary].push({
      start : offset
    });
}

ThinMimeTree.prototype.end_boundary = function (boundary, offset) {
    if (!this.tree[boundary]) {
        // Very interesting, fail silent
        return;
    }
    this.tree[boundary][this.tree[boundary].length - 1].end = offset;
    this.boundary.shift();
}

ThinMimeTree.prototype.add_headers = function (headers) {
    var header = mimelib.parseHeaders(headers);
    this._parse_content_type(header['content-type'][0]);
    this.tree[this.boundary[0]][this.tree[this.boundary[0]].length - 1].cte =
      header['content-transfer-encoding'] ?
        header['content-transfer-encoding'][0].replace(/["']/g, "") : "";
    this.tree[this.boundary[0]][this.tree[this.boundary[0]].length - 1].cd =
      header['content-disposition'] ?
        header['content-disposition'][0].replace(/["']/g, "") : "";
}

// Private functions

ThinMimeTree.prototype._parse_content_type = function (ct) {
    var ct_array = ct.split(";");

    // goodluck reading this mess
    for (var i = 0; i < ct_array.length; i++) {
        var pairs = ct_array[i].split(" ");
        for (var j = 0; j < pairs.length; j++) {
            var kv = pairs[j].split("=");
            if (kv[0] && kv[1] === undefined) {
                this.tree[this.boundary[0]]
                  [this.tree[this.boundary[0]].length - 1].ct =
                    kv[0].replace(/["']/g, "");
            }
            else if (kv[0] && kv[0] === "charset" && kv[1]) {
                this.tree[this.boundary[0]]
                  [this.tree[this.boundary[0]].length - 1].charset =
                    kv[1].replace(/["']/g, "");
            }
            else if (kv[0] && kv[0] === "boundary" && kv[1]) {
                this.tree[this.boundary[0]]
                  [this.tree[this.boundary[0]].length - 1].boundary =
                    kv[1].replace(/["']/g, "");
            }
        }
    }
}

module.exports = ThinMimeTree;
