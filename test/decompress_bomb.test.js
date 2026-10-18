"use strict";

const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// RSS growth alone does not reliably expose the eager allocation: large zero-filled
// buffers are often backed by untouched pages. These tests instead watch the Buffer
// allocators directly while an entry is read and refuse any request above LIMIT,
// so a regression fails the assertion without committing gigabytes on the host.
const ALLOCATORS = ["alloc", "allocUnsafe", "allocUnsafeSlow"];

function guardAllocations(limit) {
    const originals = {};
    const guard = {
        largest: 0,
        restore: () => {
            ALLOCATORS.forEach((name) => {
                if (originals[name]) Buffer[name] = originals[name];
            });
        }
    };
    ALLOCATORS.forEach((name) => {
        const original = (originals[name] = Buffer[name]);
        Buffer[name] = function (size) {
            if (typeof size === "number" && size > guard.largest) guard.largest = size;
            if (size > limit) {
                throw new RangeError("refused oversized Buffer." + name + "(" + size + ")");
            }
            return original.apply(this, arguments);
        };
    });
    return guard;
}

function runGuarded(limit, fn) {
    const guard = guardAllocations(limit);
    let error;
    try {
        fn();
    } catch (e) {
        error = e;
    } finally {
        guard.restore();
    }
    return { largest: guard.largest, error };
}

describe("decompression bomb (declared size) - CVE-2026-39244 allocation guard", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024;
    // the crafted archives carry a single byte of payload
    const LIMIT = 1024 * 1024;
    const bombs = [
        { label: "STORED", method: 0, content: Buffer.from("A"), error: /CRC32/ },
        { label: "DEFLATED", method: 8, content: Buffer.from([0x00]), error: /./ }
    ];

    let guard;
    let destination;

    afterEach((done) => {
        if (guard) guard.restore();
        guard = undefined;
        if (!destination) return done();
        const dir = destination;
        destination = undefined;
        rimraf(dir, done);
    });

    bombs.forEach((bomb) => {
        it(`getData() on a ${bomb.label} entry allocates from the real data, not the declared size`, () => {
            const entry = new Zip(craftBomb(DECLARED, bomb.method, bomb.content)).getEntries()[0];
            const result = runGuarded(LIMIT, () => entry.getData());
            expect(result.largest).to.be.below(LIMIT);
            expect(result.error).to.be.an("error");
            expect(result.error.message).to.match(bomb.error);
        });

        it(`readFile(), readAsText() and test() on a ${bomb.label} entry stay bounded`, () => {
            const zip = new Zip(craftBomb(DECLARED, bomb.method, bomb.content));

            const readFile = runGuarded(LIMIT, () => zip.readFile("a"));
            expect(readFile.largest).to.be.below(LIMIT);
            expect(readFile.error).to.be.an("error");
            expect(readFile.error.message).to.match(bomb.error);

            const readAsText = runGuarded(LIMIT, () => zip.readAsText("a"));
            expect(readAsText.largest).to.be.below(LIMIT);
            expect(readAsText.error).to.be.an("error");
            expect(readAsText.error.message).to.match(bomb.error);

            let tested;
            const test = runGuarded(LIMIT, () => {
                tested = zip.test();
            });
            expect(test.largest).to.be.below(LIMIT);
            expect(test.error).to.equal(undefined);
            expect(tested).to.equal(false);
        });

        it(`extractAllTo() on a ${bomb.label} entry stays bounded and writes nothing`, () => {
            const zip = new Zip(craftBomb(DECLARED, bomb.method, bomb.content));
            destination = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-declared-"));
            const result = runGuarded(LIMIT, () => zip.extractAllTo(destination, true));
            expect(result.largest).to.be.below(LIMIT);
            expect(result.error).to.be.an("error");
            expect(result.error.message).to.match(bomb.error);
            expect(fs.existsSync(pth.join(destination, "a"))).to.equal(false);
        });
    });

    it("getDataAsync() on a STORED entry allocates from the real data, not the declared size", () => {
        const entry = new Zip(craftBomb(DECLARED, 0, Buffer.from("A"))).getEntries()[0];
        let reported;
        const result = runGuarded(LIMIT, () =>
            entry.getDataAsync((data, err) => {
                reported = err;
            })
        );
        expect(result.largest).to.be.below(LIMIT);
        expect(reported).to.be.an("error");
        expect(reported.message).to.match(/CRC32/);
    });

    it("getDataAsync() on a DEFLATED entry allocates from the real data, not the declared size", (done) => {
        const entry = new Zip(craftBomb(DECLARED, 8, Buffer.from([0x00]))).getEntries()[0];
        guard = guardAllocations(LIMIT);
        const finish = (err) => {
            if (guard) guard.restore();
            done(err);
        };
        try {
            entry.getDataAsync((data, err) => {
                try {
                    expect(guard.largest).to.be.below(LIMIT);
                    expect(err).to.be.an("error");
                    expect(data.length).to.equal(0);
                    finish();
                } catch (e) {
                    finish(e);
                }
            });
        } catch (e) {
            finish(e);
        }
    });

    it("extractAllToAsync() on a DEFLATED entry stays bounded and writes nothing", () => {
        const zip = new Zip(craftBomb(DECLARED, 8, Buffer.from([0x00])));
        destination = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-declared-"));
        guard = guardAllocations(LIMIT);
        let pending;
        try {
            pending = zip.extractAllToAsync(destination, true);
        } catch (e) {
            pending = Promise.reject(e);
        }
        return pending.then(
            () => {
                guard.restore();
                throw new Error("extractAllToAsync() should have rejected");
            },
            (err) => {
                guard.restore();
                expect(guard.largest).to.be.below(LIMIT);
                expect(err).to.be.an("error");
                expect(err.message).to.not.match(/refused oversized/);
                expect(fs.existsSync(pth.join(destination, "a"))).to.equal(false);
            }
        );
    });

    it("an honest STORED and DEFLATED archive still round-trips under the guard", () => {
        const stored = Buffer.from("stored payload");
        const deflated = Buffer.from("deflated payload ".repeat(1000));
        const source = new Zip();
        source.addFile("s.bin", stored);
        source.getEntry("s.bin").header.method = 0;
        source.addFile("d.txt", deflated);
        const zip = new Zip(source.toBuffer());
        expect(zip.getEntry("s.bin").header.method).to.equal(0);
        expect(zip.getEntry("d.txt").header.method).to.equal(8);

        let s, d;
        const result = runGuarded(LIMIT, () => {
            s = zip.readFile("s.bin");
            d = zip.readFile("d.txt");
        });
        expect(result.error).to.equal(undefined);
        expect(s.equals(stored)).to.equal(true);
        expect(d.equals(deflated)).to.equal(true);
    });
});
