// SPDX-License-Identifier: MPL-2.0
const MiB = 1024 * 1024;

export const SHIELD_IMAGE_LIMITS = Object.freeze({
  maxBytes: 786432,
  maxBody: MiB,
  maxOutput: MiB,
  maxPixels: 12_000_000,
  maxImages: 8,
  maxFrame: 2 * MiB,
  confidenceFloor: 0.5,
});

export class ImageLimitError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

// Overrides may only tighten a limit. Anything that would loosen it is a bug in
// the caller, so it throws instead of being clamped.
export function imageLimits(overrides = {}) {
  const limits = { ...SHIELD_IMAGE_LIMITS };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) continue;
    if (!(key in SHIELD_IMAGE_LIMITS)) throw new TypeError(`unknown image limit: ${key}`);
    const isFloor = key === "confidenceFloor";
    const valid = isFloor ? Number.isFinite(value) && value >= 0 && value <= 1 : Number.isSafeInteger(value) && value > 0;
    if (!valid) throw new TypeError(`invalid image limit ${key}: ${value}`);
    const loosens = isFloor ? value < SHIELD_IMAGE_LIMITS[key] : value > SHIELD_IMAGE_LIMITS[key];
    if (loosens) throw new RangeError(`image limit ${key} can only be tightened`);
    limits[key] = value;
  }
  return Object.freeze(limits);
}

const u16be = (b, i) => b.readUInt16BE(i);
const u24le = (b, i) => b[i] | (b[i + 1] << 8) | (b[i + 2] << 16);

// Reads width and height from the container header only, so oversized images
// are rejected before anything is inflated. Returns null when unreadable.
export function readImageDimensions(bytes) {
  const b = Buffer.from(bytes);
  if (b.length >= 24 && b.readUInt32BE(0) === 0x89504e47 && b.toString("latin1", 12, 16) === "IHDR") {
    return { width: b.readUInt32BE(16), height: b.readUInt32BE(20) };
  }
  if (b.length >= 10 && (b.toString("latin1", 0, 6) === "GIF87a" || b.toString("latin1", 0, 6) === "GIF89a")) {
    return { width: b.readUInt16LE(6), height: b.readUInt16LE(8) };
  }
  if (b.length >= 30 && b.toString("latin1", 0, 4) === "RIFF" && b.toString("latin1", 8, 12) === "WEBP") {
    const chunk = b.toString("latin1", 12, 16);
    if (chunk === "VP8X") return { width: u24le(b, 24) + 1, height: u24le(b, 27) + 1 };
    if (chunk === "VP8L" && b[20] === 0x2f) {
      const bits = b.readUInt32LE(21);
      return { width: (bits & 0x3fff) + 1, height: ((bits >> 14) & 0x3fff) + 1 };
    }
    if (chunk === "VP8 ") return { width: b.readUInt16LE(26) & 0x3fff, height: b.readUInt16LE(28) & 0x3fff };
    return null;
  }
  if (b.length >= 4 && b[0] === 0xff && b[1] === 0xd8) {
    let i = 2;
    while (i + 9 < b.length) {
      if (b[i] !== 0xff) return null;
      const marker = b[i + 1];
      if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { i += 2; continue; }
      const length = u16be(b, i + 2);
      const isSof = marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc;
      if (isSof) return { width: u16be(b, i + 7), height: u16be(b, i + 5) };
      i += 2 + length;
    }
  }
  return null;
}

export function assertImageWithinLimits(bytes, limits = SHIELD_IMAGE_LIMITS) {
  if (bytes.length > limits.maxBytes) throw new ImageLimitError("image_too_large", `image is ${bytes.length} bytes`);
  const dims = readImageDimensions(bytes);
  if (!dims || dims.width <= 0 || dims.height <= 0) throw new ImageLimitError("image_unreadable", "image dimensions unreadable");
  if (dims.width * dims.height > limits.maxPixels) throw new ImageLimitError("image_too_many_pixels", `image is ${dims.width}x${dims.height}`);
  return dims;
}

// Decoders render a truncated file as far as it goes, and that partial picture
// is not what the user sent. Each allowed container has a fixed end to check.
export function assertImageComplete(bytes) {
  const b = Buffer.from(bytes);
  const truncated = () => { throw new ImageLimitError("image_truncated", "image container is incomplete"); };
  if (b.length >= 8 && b.readUInt32BE(0) === 0x89504e47) {
    if (b.length < 20 || b.toString("latin1", b.length - 8, b.length - 4) !== "IEND" || b.readUInt32BE(b.length - 12) !== 0) truncated();
    return;
  }
  if (b.length >= 2 && b[0] === 0xff && b[1] === 0xd8) {
    if (b.length < 4 || b[b.length - 2] !== 0xff || b[b.length - 1] !== 0xd9) truncated();
    return;
  }
  if (b.length >= 6 && (b.toString("latin1", 0, 6) === "GIF87a" || b.toString("latin1", 0, 6) === "GIF89a")) {
    if (b[b.length - 1] !== 0x3b) truncated();
    return;
  }
  if (b.length >= 12 && b.toString("latin1", 0, 4) === "RIFF" && b.toString("latin1", 8, 12) === "WEBP") {
    if (b.readUInt32LE(4) + 8 !== b.length) truncated();
    return;
  }
  truncated();
}
