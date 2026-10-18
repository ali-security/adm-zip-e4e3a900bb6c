const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const zlib = require("zlib");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");
const Inflater = require("../../methods/inflater");
const Utils = require("../../util");

const Constants = Utils.Constants;

// methods/inflater.js only hands zlib's maxOutputLength to the synchronous
// inflateRawSync() on Node >= 15, so the sync cap can only be asserted there.
// The async cap is enforced by hand and is asserted on every Node version.
const nodeMajor = +process.versions.node.split(".")[0];
const syncCapSupported = nodeMajor >= 15;

// 1 MiB of a single repeated byte deflates to about 1 KiB
const BOMB_SIZE = 1024 * 1024;
const bombData = Buffer.alloc(BOMB_SIZE, 0x61);
const bombDeflated = zlib.deflateRawSync(bombData);
const bombCrc = Utils.crc32(bombData);
const MAX_OUTPUT_EXCEEDED = Utils.Errors.MAX_OUTPUT_EXCEEDED().message;

// Builds a single-entry archive whose deflated payload expands to BOMB_SIZE bytes
// while its local and central headers declare `declaredSize` bytes and `crc`.
function makeLyingZip(declaredSize, crc) {
    const zip = new Zip();
    zip.addFile("bomb.txt", bombData);
    const buf = Buffer.from(zip.toBuffer());

    const locOffset = 0;
    const endOffset = buf.length - Constants.ENDHDR;
    expect(buf.readUInt32LE(locOffset)).to.equal(Constants.LOCSIG);
    expect(buf.readUInt32LE(endOffset)).to.equal(Constants.ENDSIG);
    const cenOffset = buf.readUInt32LE(endOffset + Constants.ENDOFF);
    expect(buf.readUInt32LE(cenOffset)).to.equal(Constants.CENSIG);

    buf.writeUInt32LE(declaredSize, locOffset + Constants.LOCLEN);
    buf.writeUInt32LE(declaredSize, cenOffset + Constants.CENLEN);
    buf.writeUInt32LE(crc >>> 0, locOffset + Constants.LOCCRC);
    buf.writeUInt32LE(crc >>> 0, cenOffset + Constants.CENCRC);

    const lying = new Zip(buf);
    const entry = lying.getEntry("bomb.txt");
    expect(entry.header.method).to.equal(Constants.DEFLATED);
    expect(entry.header.size).to.equal(declaredSize);
    return { zip: lying, entry };
}

// Wraps an async callback so that it must fire exactly once: a second call (or
// an assertion failure) fails the test instead of slipping by unnoticed.
function once(done, check) {
    let calls = 0;
    return function () {
        calls++;
        if (calls > 1) return;
        try {
            check.apply(null, arguments);
        } catch (e) {
            done(e);
            return;
        }
        setTimeout(function () {
            done(calls === 1 ? undefined : new Error("callback called " + calls + " times"));
        }, 50);
    };
}

describe("adm-zip - decompression bomb (methods/inflater.js)", () => {
    describe("Inflater - sync", () => {
        it("caps output at 1 byte when the declared size is 0", function () {
            if (!syncCapSupported) this.skip(); // maxOutputLength is only passed to zlib on Node >= 15
            const inflater = new Inflater(bombDeflated, 0);
            expect(() => inflater.inflate()).to.throw(RangeError);
        });

        it("caps output at the declared size when it is smaller than the real data", function () {
            if (!syncCapSupported) this.skip(); // maxOutputLength is only passed to zlib on Node >= 15
            const inflater = new Inflater(bombDeflated, 1024);
            expect(() => inflater.inflate()).to.throw(RangeError);
        });

        it("still inflates a genuinely empty entry declared with size 0", () => {
            const inflater = new Inflater(zlib.deflateRawSync(Buffer.alloc(0)), 0);
            const result = inflater.inflate();
            expect(result.length).to.equal(0);
        });

        it("still inflates data matching the declared size", () => {
            const inflater = new Inflater(bombDeflated, BOMB_SIZE);
            const result = inflater.inflate();
            expect(result.length).to.equal(BOMB_SIZE);
            expect(result.equals(bombData)).to.equal(true);
        });
    });

    describe("Inflater - async", () => {
        it("caps output at 1 byte when the declared size is 0", (done) => {
            const inflater = new Inflater(bombDeflated, 0);
            inflater.inflateAsync(
                once(done, (result, err) => {
                    expect(err).to.be.an("error");
                    expect(err.message).to.equal(MAX_OUTPUT_EXCEEDED);
                    expect(result.length).to.equal(0);
                })
            );
        });

        it("caps output at the declared size when it is smaller than the real data", (done) => {
            const inflater = new Inflater(bombDeflated, 1024);
            inflater.inflateAsync(
                once(done, (result, err) => {
                    expect(err).to.be.an("error");
                    expect(err.message).to.equal(MAX_OUTPUT_EXCEEDED);
                    expect(result.length).to.equal(0);
                })
            );
        });

        it("still inflates a genuinely empty entry declared with size 0", (done) => {
            const inflater = new Inflater(zlib.deflateRawSync(Buffer.alloc(0)), 0);
            inflater.inflateAsync(
                once(done, (result, err) => {
                    expect(err).to.equal(undefined);
                    expect(result.length).to.equal(0);
                })
            );
        });

        it("still inflates data matching the declared size", (done) => {
            const inflater = new Inflater(bombDeflated, BOMB_SIZE);
            inflater.inflateAsync(
                once(done, (result, err) => {
                    expect(err).to.equal(undefined);
                    expect(result.length).to.equal(BOMB_SIZE);
                    expect(result.equals(bombData)).to.equal(true);
                })
            );
        });

        it("reports malformed deflate data through the callback", (done) => {
            // BFINAL=1, BTYPE=3 (reserved) -> Z_DATA_ERROR
            const inflater = new Inflater(Buffer.from([0xff, 0xff, 0xff, 0xff]), 16);
            inflater.inflateAsync(
                once(done, (result, err) => {
                    expect(err).to.be.an("error");
                    expect(result.length).to.equal(0);
                })
            );
        });
    });

    describe("ZipEntry with a lying uncompressed size", () => {
        let destination;

        afterEach((done) => {
            if (!destination) return done();
            const dir = destination;
            destination = undefined;
            rimraf(dir, done);
        });

        it("getData() refuses an entry declaring size 0", function () {
            if (!syncCapSupported) this.skip(); // maxOutputLength is only passed to zlib on Node >= 15
            // crc 0 is the CRC-32 of an empty buffer, so only the size cap stops this
            const { entry } = makeLyingZip(0, 0);
            expect(() => entry.getData()).to.throw(RangeError);
        });

        it("readFile() refuses an entry declaring a size smaller than its data", function () {
            if (!syncCapSupported) this.skip(); // maxOutputLength is only passed to zlib on Node >= 15
            const { zip } = makeLyingZip(16, bombCrc);
            expect(() => zip.readFile("bomb.txt")).to.throw(RangeError);
        });

        it("getDataAsync() refuses an entry declaring size 0", (done) => {
            // the CRC matches the full data, so only the size cap stops this
            const { entry } = makeLyingZip(0, bombCrc);
            entry.getDataAsync(
                once(done, (data, err) => {
                    expect(err).to.be.an("error");
                    expect(err.message).to.equal(MAX_OUTPUT_EXCEEDED);
                    expect(data.length).to.equal(0);
                })
            );
        });

        it("readFileAsync() refuses an entry declaring a size smaller than its data", (done) => {
            const { zip } = makeLyingZip(16, bombCrc);
            zip.readFileAsync(
                "bomb.txt",
                once(done, (data, err) => {
                    expect(err).to.be.an("error");
                    expect(err.message).to.equal(MAX_OUTPUT_EXCEEDED);
                    expect(data.length).to.equal(0);
                })
            );
        });

        it("readAsTextAsync() refuses an entry declaring size 0", (done) => {
            const { zip } = makeLyingZip(0, bombCrc);
            zip.readAsTextAsync(
                "bomb.txt",
                once(done, (data, err) => {
                    expect(err).to.be.an("error");
                    expect(err.message).to.equal(MAX_OUTPUT_EXCEEDED);
                })
            );
        });

        it("extractAllToAsync() rejects and writes nothing for an entry declaring size 0", () => {
            const { zip } = makeLyingZip(0, bombCrc);
            destination = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-bomb-"));
            return zip.extractAllToAsync(destination, true).then(
                () => {
                    throw new Error("extractAllToAsync() should have rejected");
                },
                (err) => {
                    expect(err).to.be.an("error");
                    expect(err.message).to.equal(MAX_OUTPUT_EXCEEDED);
                    expect(fs.existsSync(pth.join(destination, "bomb.txt"))).to.equal(false);
                }
            );
        });

        it("an entry with an honest size still extracts sync and async", (done) => {
            const { entry } = makeLyingZip(BOMB_SIZE, bombCrc);
            expect(entry.getData().equals(bombData)).to.equal(true);
            entry.getDataAsync(
                once(done, (data, err) => {
                    expect(err).to.equal(undefined);
                    expect(data.equals(bombData)).to.equal(true);
                })
            );
        });
    });
});
