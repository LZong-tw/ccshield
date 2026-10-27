// SPDX-License-Identifier: MPL-2.0
// Shield image worker, NDJSON protocol v1. `workerVersion` is generated at
// build time by compile.mjs. Decoding and PNG re-encoding follow the gateway
// worker (f1bfe36); the request loop and coordinate output are new.
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers
import Vision

let maxBytes = 786_432
let maxPixels = 12_000_000
let maxOutput = 1_048_576
let maxFrame = 2_097_152
let allowedTypes: Set<String> = [UTType.png.identifier, UTType.jpeg.identifier, UTType.gif.identifier, "org.webmproject.webp"]
let ocrLanguages = ["zh-Hant", "en-US"]

struct Failure: Error { let code: String }

func isInteger(_ value: Any?) -> NSNumber? {
    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
          number.doubleValue.isFinite, number.doubleValue.rounded() == number.doubleValue else { return nil }
    return number
}

func count(_ value: Any?) throws -> Int {
    guard let number = isInteger(value), number.doubleValue >= 0, number.doubleValue <= Double(Int32.max) else { throw Failure(code: "bad_request") }
    return number.intValue
}

func imageBytes(_ request: [String: Any]) throws -> Data {
    guard let base64 = request["image"] as? String, base64.utf8.count <= ((maxBytes + 2) / 3) * 4,
          let bytes = Data(base64Encoded: base64), !bytes.isEmpty, bytes.count <= maxBytes else { throw Failure(code: "bad_request") }
    return bytes
}

// Decodes one frame of an allowlisted type with EXIF orientation applied and
// alpha flattened onto white. Header dimensions and frame count are checked
// before any pixel allocation.
func decode(_ bytes: Data) throws -> CGContext {
    guard let source = CGImageSourceCreateWithData(bytes as CFData, [kCGImageSourceShouldCache: false] as CFDictionary),
          let type = CGImageSourceGetType(source) else { throw Failure(code: "decode_failed") }
    guard allowedTypes.contains(type as String) else { throw Failure(code: "unsupported_type") }
    guard CGImageSourceGetCount(source) == 1 else { throw Failure(code: "multi_frame") }
    guard let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
          let sourceWidth = isInteger(properties[kCGImagePropertyPixelWidth])?.intValue,
          let sourceHeight = isInteger(properties[kCGImagePropertyPixelHeight])?.intValue,
          sourceWidth > 0, sourceHeight > 0 else { throw Failure(code: "decode_failed") }
    guard sourceWidth <= maxPixels / sourceHeight else { throw Failure(code: "too_many_pixels") }
    let orientation = isInteger(properties[kCGImagePropertyOrientation] ?? 1)?.intValue ?? 0
    guard (1...8).contains(orientation) else { throw Failure(code: "decode_failed") }
    let width = orientation >= 5 ? sourceHeight : sourceWidth
    let height = orientation >= 5 ? sourceWidth : sourceHeight
    let options: [CFString: Any] = [kCGImageSourceCreateThumbnailFromImageAlways: true,
                                    kCGImageSourceCreateThumbnailWithTransform: true,
                                    kCGImageSourceThumbnailMaxPixelSize: max(sourceWidth, sourceHeight),
                                    kCGImageSourceShouldCacheImmediately: true]
    guard let decoded = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary),
          decoded.width == width, decoded.height == height,
          let space = CGColorSpace(name: CGColorSpace.sRGB),
          let context = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: width * 4, space: space,
                                  bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue | CGBitmapInfo.byteOrder32Big.rawValue)
    else { throw Failure(code: "decode_failed") }
    context.setFillColor(CGColor(gray: 1, alpha: 1))
    context.fill(CGRect(x: 0, y: 0, width: width, height: height))
    context.draw(decoded, in: CGRect(x: 0, y: 0, width: width, height: height))
    return context
}

final class EncodedBuffer {
    var data = Data()
    var overflow = false
}

// PNG of the rendered pixels only: IHDR, IDAT and IEND survive; EXIF, ICC and
// text chunks that ImageIO may synthesize are dropped.
func encode(_ context: CGContext) throws -> Data {
    guard let image = context.makeImage() else { throw Failure(code: "encode_failed") }
    let buffer = EncodedBuffer()
    var callbacks = CGDataConsumerCallbacks(putBytes: { info, bytes, count in
        guard let info = info else { return 0 }
        let buffer = Unmanaged<EncodedBuffer>.fromOpaque(info).takeUnretainedValue()
        guard count <= maxOutput - buffer.data.count else { buffer.overflow = true; return 0 }
        buffer.data.append(bytes.assumingMemoryBound(to: UInt8.self), count: count)
        return count
    }, releaseConsumer: nil)
    guard let consumer = CGDataConsumer(info: Unmanaged.passUnretained(buffer).toOpaque(), cbks: &callbacks),
          let destination = CGImageDestinationCreateWithDataConsumer(consumer, UTType.png.identifier as CFString, 1, nil)
    else { throw Failure(code: "encode_failed") }
    CGImageDestinationAddImage(destination, image, nil)
    let finalized = CGImageDestinationFinalize(destination)
    if buffer.overflow { throw Failure(code: "output_too_large") }
    guard finalized else { throw Failure(code: "encode_failed") }
    let data = buffer.data
    var output = data.prefix(8)
    var offset = 8
    while offset + 12 <= data.count {
        let length = data[offset..<(offset + 4)].reduce(0) { ($0 << 8) | Int($1) }
        guard length <= data.count - offset - 12 else { throw Failure(code: "encode_failed") }
        let type = String(decoding: data[(offset + 4)..<(offset + 8)], as: UTF8.self)
        if ["IHDR", "IDAT", "IEND"].contains(type) { output.append(data[offset..<(offset + length + 12)]) }
        offset += length + 12
    }
    guard offset == data.count else { throw Failure(code: "encode_failed") }
    return output
}

func supportedLanguages() -> [String] {
    (try? VNRecognizeTextRequest().supportedRecognitionLanguages()) ?? []
}

func ocr(_ context: CGContext) throws -> [String: Any] {
    let width = context.width, height = context.height
    guard let image = context.makeImage() else { throw Failure(code: "ocr_failed") }
    let request = VNRecognizeTextRequest()
    request.recognitionLevel = .accurate
    request.usesLanguageCorrection = false
    request.minimumTextHeight = 0
    let available = supportedLanguages()
    guard ocrLanguages.allSatisfy(available.contains) else { throw Failure(code: "ocr_failed") }
    request.recognitionLanguages = ocrLanguages
    do { try VNImageRequestHandler(cgImage: image, orientation: .up).perform([request]) } catch { throw Failure(code: "ocr_failed") }
    var regions: [(y: Int, x: Int, value: [String: Any])] = []
    for observation in request.results ?? [] {
        guard let candidate = observation.topCandidates(1).first else { continue }
        // Vision boxes are normalized with a bottom-left origin; round outward
        // into top-left integer pixels so a mask always covers the text.
        let box = observation.boundingBox
        let x = min(max(0, Int(floor(box.minX * Double(width)))), width)
        let y = min(max(0, Int(floor((1 - box.maxY) * Double(height)))), height)
        let right = min(max(0, Int(ceil(box.maxX * Double(width)))), width)
        let bottom = min(max(0, Int(ceil((1 - box.minY) * Double(height)))), height)
        guard right > x, bottom > y else { throw Failure(code: "ocr_failed") }
        let text = candidate.string.components(separatedBy: .newlines).joined(separator: " ")
        let confidence = min(1, max(0, Double(candidate.confidence)))
        regions.append((y, x, ["text": text, "confidence": confidence, "rect": ["x": x, "y": y, "w": right - x, "h": bottom - y]]))
    }
    regions.sort { ($0.y, $0.x) < ($1.y, $1.x) }
    return ["width": width, "height": height, "regions": regions.map(\.value)]
}

func mask(_ context: CGContext, _ value: Any?) throws -> [String: Any] {
    let width = context.width, height = context.height
    guard let rects = value as? [[String: Any]] else { throw Failure(code: "bad_request") }
    context.setBlendMode(.copy)
    context.setFillColor(CGColor(red: 0, green: 0, blue: 0, alpha: 1))
    for rect in rects {
        guard Set(rect.keys) == ["x", "y", "w", "h"] else { throw Failure(code: "bad_request") }
        let x = try count(rect["x"]), y = try count(rect["y"]), w = try count(rect["w"]), h = try count(rect["h"])
        guard x + w <= width, y + h <= height else { throw Failure(code: "bad_request") }
        context.fill(CGRect(x: x, y: height - y - h, width: w, height: h))
    }
    return ["width": width, "height": height, "image": try encode(context).base64EncodedString()]
}

func handle(_ request: [String: Any]) throws -> [String: Any] {
    switch request["op"] as? String {
    case "probe":
        guard Set(request.keys) == ["v", "id", "op"] else { throw Failure(code: "bad_request") }
        // The first recognition in a process loads the Vision models (~30 s
        // measured on macOS 27). Doing it here keeps that cost in readiness
        // instead of the first real request's deadline.
        guard let blank = CGContext(data: nil, width: 32, height: 32, bitsPerComponent: 8, bytesPerRow: 128,
                                    space: CGColorSpace(name: CGColorSpace.sRGB)!,
                                    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { throw Failure(code: "ocr_failed") }
        blank.setFillColor(CGColor(gray: 1, alpha: 1))
        blank.fill(CGRect(x: 0, y: 0, width: 32, height: 32))
        _ = try ocr(blank)
        return ["worker": workerVersion, "languages": supportedLanguages().sorted()]
    case "ocr":
        guard Set(request.keys) == ["v", "id", "op", "image"] else { throw Failure(code: "bad_request") }
        return try ocr(decode(try imageBytes(request)))
    case "mask":
        guard Set(request.keys) == ["v", "id", "op", "image", "rects"] else { throw Failure(code: "bad_request") }
        return try mask(decode(try imageBytes(request)), request["rects"])
    default:
        throw Failure(code: "bad_request")
    }
}

func write(_ object: [String: Any]) {
    guard var line = try? JSONSerialization.data(withJSONObject: object) else { exit(3) }
    line.append(10)
    FileHandle.standardOutput.write(line)
}

func respond(to line: Data) {
    // Without a usable id there is nothing to answer; the driver treats the
    // exit as a dead worker and fails the request closed.
    guard let request = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
          let idNumber = isInteger(request["id"]), idNumber.doubleValue >= 0 else { exit(2) }
    let id = idNumber.intValue
    var response: [String: Any]
    do {
        guard let version = isInteger(request["v"]), version.intValue == 1 else { throw Failure(code: "bad_request") }
        response = try autoreleasepool { try handle(request) }
        response["v"] = 1
        response["id"] = id
        response["ok"] = true
        if let data = try? JSONSerialization.data(withJSONObject: response), data.count + 1 > maxFrame {
            response = ["v": 1, "id": id, "ok": false, "code": "output_too_large"]
        }
    } catch let failure as Failure {
        response = ["v": 1, "id": id, "ok": false, "code": failure.code]
    } catch {
        response = ["v": 1, "id": id, "ok": false, "code": "bad_request"]
    }
    write(response)
}

// Persistent loop: one request per line, answered in order. A line longer than
// maxFrame is never buffered whole; the worker exits instead.
var pending = Data()
while true {
    let chunk = FileHandle.standardInput.availableData
    if chunk.isEmpty { exit(0) }
    pending.append(chunk)
    while let newline = pending.firstIndex(of: 10) {
        let line = pending[pending.startIndex..<newline]
        pending = Data(pending[(newline + 1)...])
        respond(to: Data(line))
    }
    if pending.count > maxFrame { exit(1) }
}
