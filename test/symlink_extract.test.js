"use strict";

const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const Utils = require("../util/utils");

// Regression tests for CVE-2026-76845 (symlink following during extraction).
// Utils.sanitize() only keeps the *textual* entry path inside the extraction
// root. When a symbolic link (or a Windows junction) already exists inside the
// target directory, writing an entry below it, or onto it, followed the link
// and created/overwrote files outside of the extraction root. extractAllTo,
// extractAllToAsync and extractEntryTo must refuse to write through such links.

const IN_THE_WAY = /There is a file in the way/;

// Create a symlink, skipping the calling test when the platform/user is not
// allowed to create one (e.g. Windows without the symlink privilege).
function link(ctx, target, linkPath, type) {
    try {
        fs.symlinkSync(target, linkPath, type);
    } catch (e) {
        if (e && (e.code === "EPERM" || e.code === "EACCES" || e.code === "ENOSYS")) {
            ctx.skip();
        }
        throw e;
    }
}

// directory links are created as junctions, which need no privilege on Windows
// (the type argument is ignored on other platforms)
const linkDir = (ctx, target, linkPath) => link(ctx, pth.resolve(target), linkPath, "junction");
const linkFile = (ctx, target, linkPath) => link(ctx, pth.resolve(target), linkPath, "file");

function makeZip(entries) {
    const zip = new Zip();
    entries.forEach((e) => zip.addFile(e.name, e.content === undefined ? null : Buffer.from(e.content)));
    // round trip through a buffer, as an archive received from elsewhere
    return new Zip(zip.toBuffer());
}

describe("adm-zip - extract: symlink following (CVE-2026-76845)", function () {
    let base, root, outside;

    beforeEach(function () {
        base = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-symlink-"));
        root = pth.join(base, "root");
        outside = pth.join(base, "outside");
        fs.mkdirSync(root);
        fs.mkdirSync(outside);
    });

    afterEach(function () {
        try {
            rimraf.sync(base);
        } catch (e) {
            /* best-effort cleanup of the temporary directory */
        }
    });

    // <root>/evil -> <outside>
    function plantDirLink(ctx) {
        linkDir(ctx, outside, pth.join(root, "evil"));
    }

    // <root>/<name> -> <outside>/victim.txt, which holds "original"
    function plantFileLink(ctx, name) {
        const victim = pth.join(outside, "victim.txt");
        fs.writeFileSync(victim, "original");
        linkFile(ctx, victim, pth.join(root, name || "victim.txt"));
        return victim;
    }

    const outsideEntries = () => fs.readdirSync(outside).sort();

    describe("extractAllTo()", function () {
        it("extractAllTo() does not write a file through a symlinked directory inside the target", function () {
            plantDirLink(this);
            const zip = makeZip([{ name: "evil/pwned.txt", content: "pwned" }]);

            expect(() => zip.extractAllTo(root, false)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "pwned.txt"))).to.be.false;
            expect(outsideEntries()).to.deep.equal([]);
        });

        it("extractAllTo() does not write through a symlink nested deeper in the target", function () {
            fs.mkdirSync(pth.join(root, "a"));
            fs.mkdirSync(pth.join(root, "a", "b"));
            linkDir(this, outside, pth.join(root, "a", "b", "evil"));
            const zip = makeZip([{ name: "a/b/evil/pwned.txt", content: "pwned" }]);

            expect(() => zip.extractAllTo(root, true)).to.throw(IN_THE_WAY);
            expect(outsideEntries()).to.deep.equal([]);
        });

        it("extractAllTo() does not overwrite a file through a symlink inside the target (overwrite = true)", function () {
            const victim = plantFileLink(this);
            const zip = makeZip([{ name: "victim.txt", content: "pwned" }]);

            expect(() => zip.extractAllTo(root, true)).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(victim, "utf8")).to.equal("original");
        });

        it("extractAllTo() does not create directories through a symlinked directory inside the target", function () {
            plantDirLink(this);
            const zip = makeZip([{ name: "evil/sub/" }]);

            expect(() => zip.extractAllTo(root, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "sub"))).to.be.false;
        });

        it("extractAllTo() rejects the symlink when the target path is given relative to the cwd", function () {
            plantDirLink(this);
            const zip = makeZip([{ name: "evil/pwned.txt", content: "pwned" }]);

            expect(() => zip.extractAllTo(pth.relative(process.cwd(), root), true)).to.throw(IN_THE_WAY);
            expect(outsideEntries()).to.deep.equal([]);
        });
    });

    describe("extractEntryTo()", function () {
        it("extractEntryTo() does not write a file entry through a symlinked directory inside the target", function () {
            plantDirLink(this);
            const zip = makeZip([{ name: "evil/pwned.txt", content: "pwned" }]);

            expect(() => zip.extractEntryTo("evil/pwned.txt", root, true, true)).to.throw(IN_THE_WAY);
            expect(outsideEntries()).to.deep.equal([]);
        });

        it("extractEntryTo() does not overwrite a file through a symlink inside the target (overwrite = true)", function () {
            const victim = plantFileLink(this);
            const zip = makeZip([{ name: "dir/victim.txt", content: "pwned" }]);

            expect(() => zip.extractEntryTo("dir/victim.txt", root, false, true)).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(victim, "utf8")).to.equal("original");
        });

        it("extractEntryTo() does not overwrite a file through a symlink named by outFileName", function () {
            const victim = plantFileLink(this);
            const zip = makeZip([{ name: "data.txt", content: "pwned" }]);

            expect(() => zip.extractEntryTo("data.txt", root, false, true, false, "victim.txt")).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(victim, "utf8")).to.equal("original");
        });

        it("extractEntryTo() does not write directory children through a symlinked directory inside the target", function () {
            plantDirLink(this);
            const zip = makeZip([{ name: "evil/" }, { name: "evil/pwned.txt", content: "pwned" }]);

            expect(() => zip.extractEntryTo("evil/", root, true, true)).to.throw(IN_THE_WAY);
            expect(outsideEntries()).to.deep.equal([]);
        });

        it("extractEntryTo() does not overwrite through a symlink when flattening directory children", function () {
            const victim = plantFileLink(this);
            const zip = makeZip([{ name: "dir/" }, { name: "dir/victim.txt", content: "pwned" }]);

            expect(() => zip.extractEntryTo("dir/", root, false, true)).to.throw(IN_THE_WAY);
            expect(fs.readFileSync(victim, "utf8")).to.equal("original");
        });
    });

    describe("extractAllToAsync()", function () {
        it("extractAllToAsync() does not write a file through a symlinked directory inside the target [callback]", function (done) {
            plantDirLink(this);
            const zip = makeZip([{ name: "evil/pwned.txt", content: "pwned" }]);

            let finished = false;
            zip.extractAllToAsync(root, false, false, (err) => {
                if (finished) return;
                finished = true;
                try {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(IN_THE_WAY);
                    expect(outsideEntries()).to.deep.equal([]);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });

        it("extractAllToAsync() does not overwrite a file through a symlink inside the target [Promise]", function () {
            const victim = plantFileLink(this);
            const zip = makeZip([{ name: "victim.txt", content: "pwned" }]);

            return zip.extractAllToAsync(root, true, false).then(
                () => {
                    throw new Error("extraction through a symlink must be rejected");
                },
                (err) => {
                    expect(err.message).to.match(IN_THE_WAY);
                    expect(fs.readFileSync(victim, "utf8")).to.equal("original");
                }
            );
        });

        it("extractAllToAsync() does not create directories through a symlinked directory inside the target [Promise]", function () {
            plantDirLink(this);
            const zip = makeZip([{ name: "evil/sub/" }]);

            return zip.extractAllToAsync(root, true, false).then(
                () => {
                    throw new Error("extraction through a symlink must be rejected");
                },
                (err) => {
                    expect(err.message).to.match(/Unable to create folder/);
                    expect(fs.existsSync(pth.join(outside, "sub"))).to.be.false;
                }
            );
        });
    });

    describe("legitimate extraction is unaffected", function () {
        const entries = [{ name: "a/" }, { name: "a/b.txt", content: "ok" }, { name: "c.txt", content: "c" }];

        it("extractAllTo() still overwrites regular files when overwrite = true", function () {
            fs.writeFileSync(pth.join(root, "c.txt"), "old");
            makeZip(entries).extractAllTo(root, true);

            expect(fs.readFileSync(pth.join(root, "a", "b.txt"), "utf8")).to.equal("ok");
            expect(fs.readFileSync(pth.join(root, "c.txt"), "utf8")).to.equal("c");
        });

        it("extractAllTo() and extractEntryTo() work when the target directory itself is a symlink", function () {
            const rootLink = pth.join(base, "rootlink");
            linkDir(this, root, rootLink);
            const zip = makeZip(entries);

            zip.extractAllTo(rootLink, true);
            expect(fs.readFileSync(pth.join(root, "a", "b.txt"), "utf8")).to.equal("ok");
            expect(fs.readFileSync(pth.join(root, "c.txt"), "utf8")).to.equal("c");

            expect(zip.extractEntryTo("a/b.txt", pth.join(rootLink, "single"), false, true)).to.be.true;
            expect(fs.readFileSync(pth.join(root, "single", "b.txt"), "utf8")).to.equal("ok");
        });

        it("extractAllToAsync() works when the target directory itself is a symlink", function () {
            const rootLink = pth.join(base, "rootlink");
            linkDir(this, root, rootLink);

            return makeZip(entries)
                .extractAllToAsync(rootLink, true, false)
                .then(() => {
                    expect(fs.readFileSync(pth.join(root, "a", "b.txt"), "utf8")).to.equal("ok");
                    expect(fs.readFileSync(pth.join(root, "c.txt"), "utf8")).to.equal("c");
                });
        });
    });

    describe("Utils.assertPathSafe()", function () {
        const utils = new Utils();

        it("accepts the root itself, paths without symlinks and not yet existing paths", function () {
            expect(() => utils.assertPathSafe(root, root)).to.not.throw();
            expect(() => utils.assertPathSafe(root, pth.join(root, "a", "b", "c.txt"))).to.not.throw();
            fs.mkdirSync(pth.join(root, "a"));
            fs.writeFileSync(pth.join(root, "a", "c.txt"), "c");
            expect(() => utils.assertPathSafe(root, pth.join(root, "a", "c.txt"))).to.not.throw();
            expect(() => utils.assertPathSafe(root + pth.sep, pth.join(root, "a", "x", "y"))).to.not.throw();
        });

        it("rejects a symlinked intermediate component below the root", function () {
            plantDirLink(this);
            expect(() => utils.assertPathSafe(root, pth.join(root, "evil"))).to.throw(IN_THE_WAY);
            expect(() => utils.assertPathSafe(root, pth.join(root, "evil", "x", "y.txt"))).to.throw(IN_THE_WAY);
        });

        it("rejects a symlinked leaf below the root", function () {
            plantFileLink(this);
            expect(() => utils.assertPathSafe(root, pth.join(root, "victim.txt"))).to.throw(IN_THE_WAY);
        });

        it("leaves components at or above the root alone", function () {
            const rootLink = pth.join(base, "rootlink");
            linkDir(this, root, rootLink);
            fs.mkdirSync(pth.join(root, "a"));
            expect(() => utils.assertPathSafe(rootLink, rootLink)).to.not.throw();
            expect(() => utils.assertPathSafe(rootLink, pth.join(rootLink, "a", "b.txt"))).to.not.throw();
            // paths that are not below the root are sanitize()'s concern
            expect(() => utils.assertPathSafe(pth.join(root, "sub"), rootLink)).to.not.throw();
        });
    });
});
