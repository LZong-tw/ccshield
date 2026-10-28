// SPDX-License-Identifier: MPL-2.0
// Renders the synthetic image corpus for the native tests into argv[1].
// Synthetic only: every case is drawn text with known ground truth.
import CoreGraphics
import CoreText
import Foundation
import ImageIO
import UniformTypeIdentifiers

let out = URL(fileURLWithPath: CommandLine.arguments[1])

struct Style {
    var size: CGFloat = 28
    var font = "PingFangTC-Regular"
    var ink = CGColor(red: 0, green: 0, blue: 0, alpha: 1)
    var paper: CGColor? = CGColor(red: 1, green: 1, blue: 1, alpha: 1)
    var angle: CGFloat = 0
}

func draw(_ lines: [String], width: Int, height: Int, _ style: Style = Style()) -> CGImage {
    let ctx = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    if let paper = style.paper {
        ctx.setFillColor(paper)
        ctx.fill(CGRect(x: 0, y: 0, width: width, height: height))
    }
    if style.angle != 0 {
        ctx.translateBy(x: CGFloat(width) / 2, y: CGFloat(height) / 2)
        ctx.rotate(by: style.angle)
        ctx.translateBy(x: -CGFloat(width) / 2, y: -CGFloat(height) / 2)
    }
    let font = CTFontCreateWithName(style.font as CFString, style.size, nil)
    let step = style.size * 1.7
    for (i, text) in lines.enumerated() {
        let attr = NSAttributedString(string: text, attributes: [
            NSAttributedString.Key(kCTFontAttributeName as String): font,
            NSAttributedString.Key(kCTForegroundColorAttributeName as String): style.ink])
        ctx.textPosition = CGPoint(x: style.size * 0.6, y: CGFloat(height) - step * CGFloat(i + 1))
        CTLineDraw(CTLineCreateWithAttributedString(attr), ctx)
    }
    return ctx.makeImage()!
}

// Pixels rotated a quarter turn; EXIF orientation 8 turns them upright (checked against
// Vision: with 6 the text reads upside down).
func sideways(_ image: CGImage) -> CGImage {
    let ctx = CGContext(data: nil, width: image.height, height: image.width, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.translateBy(x: 0, y: CGFloat(image.width))
    ctx.rotate(by: -.pi / 2)
    ctx.draw(image, in: CGRect(x: 0, y: 0, width: image.width, height: image.height))
    return ctx.makeImage()!
}

func write(_ name: String, _ type: UTType, _ frames: [CGImage], _ properties: [CFString: Any] = [:]) {
    let dest = CGImageDestinationCreateWithURL(out.appendingPathComponent(name) as CFURL, type.identifier as CFString, frames.count, nil)!
    for frame in frames { CGImageDestinationAddImage(dest, frame, properties as CFDictionary) }
    guard CGImageDestinationFinalize(dest) else { fatalError("encode \(name)") }
}

let email = ["Contact the owner", "bob.lee@example.com", "before Friday"]
write("english.png", .png, [draw(email, width: 640, height: 200, Style(font: "Helvetica"))])
write("chinese.png", .png, [draw(["客戶聯絡人 王小明", "mei.chen@example.org", "請於週五前回覆"], width: 640, height: 200)])
write("rotated.png", .png, [draw(email, width: 760, height: 360, Style(font: "Helvetica", angle: 0.12))])
write("exif.jpg", .jpeg, [sideways(draw(email, width: 640, height: 200, Style(font: "Helvetica")))], [kCGImagePropertyOrientation: 8])
write("alpha.png", .png, [draw(email, width: 640, height: 200, Style(font: "Helvetica", paper: nil))])
write("dark.png", .png, [draw(email, width: 640, height: 200, Style(font: "Helvetica", ink: CGColor(red: 0.9, green: 0.9, blue: 0.9, alpha: 1), paper: CGColor(red: 0.12, green: 0.12, blue: 0.12, alpha: 1)))])
write("ui-11.png", .png, [draw(["Settings  Account  Billing", "Signed in as ann.wu@example.net", "Sign out"], width: 360, height: 80, Style(size: 11, font: "Helvetica"))])
write("ui-12.png", .png, [draw(["Settings  Account  Billing", "Signed in as ann.wu@example.net", "Sign out"], width: 380, height: 84, Style(size: 12, font: "Helvetica"))])
write("card.png", .png, [draw(["Payment method on file", "Card 4242 4242 4242 4242", "Expires 08/29"], width: 640, height: 200, Style(font: "Helvetica"))])
write("secret.png", .png, [draw(["aws_access_key_id =", "AKIAZ7WQ3MRX2KBTLYPV"], width: 760, height: 160, Style(size: 34, font: "Menlo-Regular"))])
write("clean.png", .png, [draw(["Quarterly roadmap", "Ship the onboarding flow", "Review dashboards"], width: 640, height: 200, Style(font: "Helvetica"))])
write("empty.png", .png, [draw([], width: 320, height: 120)])
let frame = draw(["frame"], width: 160, height: 80)
write("animated.gif", .gif, [frame, frame])
write("animated.png", .png, [frame, frame])
