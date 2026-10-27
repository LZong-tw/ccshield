// SPDX-License-Identifier: MPL-2.0
import { inflateSync } from "node:zlib";

const MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const CHANNELS = { 0: 1, 2: 3, 4: 2, 6: 4 };

const invalid = () => new Error("unsupported PNG");

// Just enough PNG to read back what the image worker writes: 8-bit gray, RGB,
// gray-alpha or RGBA, not interlaced. Anything else throws.
export function decodePng(bytes, { maxPixels = 12_000_000 } = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 33 || !bytes.subarray(0, 8).equals(MAGIC)) throw invalid();
  let offset = 8;
  let header;
  const idat = [];
  while (offset + 12 <= bytes.length) {
    const length = bytes.readUInt32BE(offset);
    const type = bytes.toString("latin1", offset + 4, offset + 8);
    const data = bytes.subarray(offset + 8, offset + 8 + length);
    if (data.length !== length) throw invalid();
    if (type === "IHDR") header = data;
    else if (type === "IDAT") idat.push(data);
    else if (type === "IEND") break;
    offset += length + 12;
  }
  if (!header || header.length !== 13 || idat.length === 0) throw invalid();
  const width = header.readUInt32BE(0);
  const height = header.readUInt32BE(4);
  const channels = CHANNELS[header[9]];
  if (!width || !height || width * height > maxPixels || header[8] !== 8 || !channels || header[12] !== 0) throw invalid();

  const stride = width * channels;
  let raw;
  try { raw = inflateSync(Buffer.concat(idat), { maxOutputLength: (stride + 1) * height }); } catch { throw invalid(); }
  if (raw.length !== (stride + 1) * height) throw invalid();
  const pixels = Buffer.alloc(stride * height);
  for (let y = 0; y < height; y += 1) {
    const filter = raw[y * (stride + 1)];
    const line = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    const out = pixels.subarray(y * stride, (y + 1) * stride);
    const prev = y > 0 ? pixels.subarray((y - 1) * stride, y * stride) : null;
    for (let i = 0; i < stride; i += 1) {
      const a = i >= channels ? out[i - channels] : 0;
      const b = prev ? prev[i] : 0;
      const c = prev && i >= channels ? prev[i - channels] : 0;
      let predictor;
      if (filter === 0) predictor = 0;
      else if (filter === 1) predictor = a;
      else if (filter === 2) predictor = b;
      else if (filter === 3) predictor = (a + b) >> 1;
      else if (filter === 4) {
        const p = a + b - c;
        const pa = Math.abs(p - a);
        const pb = Math.abs(p - b);
        const pc = Math.abs(p - c);
        predictor = pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
      } else throw invalid();
      out[i] = (line[i] + predictor) & 0xff;
    }
  }
  return { width, height, channels, pixels };
}
