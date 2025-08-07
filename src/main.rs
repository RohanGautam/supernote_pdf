use anyhow::{Ok, Result};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use image::{ Rgba, RgbaImage, imageops};
use itertools::Itertools;
use lazy_static::lazy_static;
use rayon::prelude::*;
use regex::Regex;
use std::fs::File;
use std::collections::HashMap;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};

const A5X_WIDTH: usize = 1404;
const A5X_HEIGHT: usize = 1872;

// precompile regex
lazy_static! {
    static ref METADATA_RE: Regex = Regex::new(r"<(?P<key>[^:]+?):(?P<value>.*?)>").unwrap();
}

#[derive(Debug)]
pub struct Notebook {
    pub signature: String,
    pub pages: Vec<Page>,
}

#[derive(Debug)]
pub struct Page {
    pub addr: u64,
    pub layers: Vec<Layer>,
}

#[derive(Debug, Default)]
pub struct Layer {
    pub key: String,
    pub protocol: String,
    pub bitmap_address: u64,
}

#[derive(Debug)]
struct PdfPageChunk {
    page_object: Vec<u8>,
    contents_object: Vec<u8>,
    image_object: Vec<u8>,
}

fn get_signature(file: &mut File) -> Result<String> {
    const SIGNATURE_OFFSET: u64 = 4;
    const SIGNATURE_LENGTH: usize = 20;

    // The `?` operator is used here. If `File::open` returns an `Err`, the `?`
    // will immediately stop this function and return that `Err` to the caller.
    // If it returns `Ok(file)`, it unwraps the value and assigns it to `file`.

    // Seek to the signature's starting position.
    file.seek(SeekFrom::Start(SIGNATURE_OFFSET))?;

    // Read the signature bytes.
    let mut signature_bytes = vec![0; SIGNATURE_LENGTH];
    file.read_exact(&mut signature_bytes)?;

    // Convert the bytes into a readable string.
    // since it is an anyhow result, "?" can propagate any type of error back in a generic way.
    let signature_string = String::from_utf8(signature_bytes)?;

    Ok(signature_string)
}

/// Reads a metadata block at a given address and parses it into a HashMap.
/// Metadata format is `<KEY1:VALUE1><KEY2:VALUE2>...`
fn parse_metadata_block(file: &mut File, address: u64) -> Result<HashMap<String, String>> {
    // The regex for parsing the key-value format.
    // It's "lazy" (`*?`) to handle nested or unusual values correctly.
    if address == 0 {
        let empty: HashMap<String, String> = HashMap::new();
        return Ok(empty);
    }

    file.seek(SeekFrom::Start(address))?;

    // Read the 4-byte block length
    let mut len_bytes = [0u8; 4];
    file.read_exact(&mut len_bytes)?;
    let block_len = u32::from_le_bytes(len_bytes) as usize;

    // Read the block content
    let mut content_bytes = vec![0; block_len];
    file.read_exact(&mut content_bytes)?;
    let content = String::from_utf8(content_bytes)?;

    // Use the regex to find all key-value pairs and collect them into a map.
    let map: HashMap<String, String> = METADATA_RE
        .captures_iter(&content)
        .map(|cap| {
            let key = cap.name("key").unwrap().as_str().to_string();
            let value = cap.name("value").unwrap().as_str().to_string();
            (key, value)
        })
        .collect();

    Ok(map)
}

fn parse_notebook(file: &mut File) -> Result<Notebook> {
    let file_signature = get_signature(file)?;

    // Get footer address and map
    file.seek(SeekFrom::End(-4))?;
    let mut addr_bytes = [0u8; 4];
    file.read_exact(&mut addr_bytes)?;
    let footer_addr = u32::from_le_bytes(addr_bytes) as u64; // Convert the little-endian bytes to a u32, then cast to u64
    let footer_map = parse_metadata_block(file, footer_addr)?;
    // println!("{:?}", footer_map);

    // get page addresses from the hashmap, sorted
    let page_addrs = footer_map
        .iter()
        .filter(|(k, _v)| k.starts_with("PAGE"))
        // .map(|(k, v)| (k.strip_prefix("PAGE").unwrap().parse::<u64>().unwrap(), v))
        .sorted_by_key(|(k, _v)| k.strip_prefix("PAGE").unwrap().parse::<u64>().unwrap())
        .map(|(_k, v)| v.parse::<u64>())
        .collect::<std::result::Result<Vec<u64>, _>>()?;

    // let page_map = parse_metadata_block(&mut file, *page_addrs.get(0).unwrap());
    // println!("{:?}", page_map);

    let mut pages: Vec<Page> = Vec::new();
    for addr in page_addrs {
        let page_map = parse_metadata_block(file, addr)?;
        let layer_order = page_map
            .get("LAYERSEQ")
            .map(|s| s.split(',').map(String::from).collect())
            .unwrap_or_else(|| {
                // Default order if LAYERSEQ is missing
                vec![
                    "BGLAYER".to_string(),
                    "MAINLAYER".to_string(),
                    "LAYER1".to_string(),
                    "LAYER2".to_string(),
                    "LAYER3".to_string(),
                ]
            });
        let mut layers: Vec<Layer> = Vec::new();
        for layer_key in layer_order.iter() {
            // if page_map.contains_key(layer_key.as_str()) {
            if let Some(addr_str) = page_map.get(layer_key.as_str()) {
                let layer_addr = addr_str.parse::<u64>()?;
                let data = parse_metadata_block(file, layer_addr)?;
                layers.push(Layer {
                    key: layer_key.to_string(),
                    protocol: data.get("LAYERPROTOCOL").cloned().unwrap_or_default(),
                    bitmap_address: data
                        .get("LAYERBITMAP")
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0),
                });
            }
        }
        pages.push(Page {
            addr: addr,
            layers: layers,
        });
    }

    Ok(Notebook {
        signature: file_signature,
        pages: pages,
    })
}

/// Decodes a byte stream compressed with the RATTA_RLE algorithm.
fn decode_rle(compressed_data: &[u8]) -> Result<Vec<u8>> {
    // A5X screen dimensions
    let expected_len = A5X_WIDTH * A5X_HEIGHT;
    let mut decompressed = Vec::with_capacity(expected_len);

    let mut i = 0; // Our position in the compressed_data slice
    let mut holder: Option<(u8, u8)> = None; // State for multi-byte lengths

    while i < compressed_data.len() {
        // Ensure we can read a pair of bytes
        if i + 1 >= compressed_data.len() {
            break;
        }
        let color_code = compressed_data[i];
        let length_code = compressed_data[i + 1];
        i += 2; // Move to the next pair

        let length: usize;

        if let Some((prev_color_code, prev_length_code)) = holder.take() {
            // We are in the "holder" state from the previous iteration.
            if color_code == prev_color_code {
                // The colors match, so combine the lengths.
                length = 1 + length_code as usize + (((prev_length_code & 0x7f) as usize + 1) << 7);
            } else {
                // Colors don't match. First, process the held-over length.
                let held_length = ((prev_length_code & 0x7f) as usize + 1) << 7;
                decompressed.extend(std::iter::repeat(prev_color_code).take(held_length));
                // Then, process the current pair normally.
                length = length_code as usize + 1;
            }
        } else if length_code == 0xff {
            // Special marker for a long run
            length = 0x4000; // 16384
        } else if length_code & 0x80 != 0 {
            // Most significant bit is set. This is a multi-byte length marker.
            // We store the current pair in the `holder` and continue to the next iteration.
            holder = Some((color_code, length_code));
            continue;
        } else {
            // Standard case: length is just length_code + 1.
            length = length_code as usize + 1;
        }

        // Add the `color_code` to our output `length` times.
        decompressed.extend(std::iter::repeat(color_code).take(length));
    }

    // After the loop, check if there's a final item in the holder.
    // This can happen if the last block was a multi-byte marker.
    if let Some((color_code, length_code)) = holder {
        let remaining_len = expected_len.saturating_sub(decompressed.len());
        // A simple heuristic for the tail length
        let tail_length = std::cmp::min(((length_code & 0x7f) as usize + 1) << 7, remaining_len);
        if tail_length > 0 {
            decompressed.extend(std::iter::repeat(color_code).take(tail_length));
        }
    }

    // Final sanity check
    if decompressed.len() != expected_len {
        // In a real app, you might want a more robust way to handle this,
        // but for now, we can pad or truncate to the expected size.
        decompressed.resize(expected_len, 0x62); // Pad with transparent if too short
    }

    Ok(decompressed)
}

/// Maps a Supernote color codes to an RGBA pixel.
fn to_rgba(pixel_byte: u8) -> Rgba<u8> {
    match pixel_byte {
        // --- Core Colors ---
        0x61 => Rgba([0, 0, 0, 255]),       // Black
        0x65 => Rgba([255, 255, 255, 255]), // White
        0x62 => Rgba([0, 0, 0, 0]),         // Transparent (used for background layer)

        // --- Grays (and their aliases/compat codes) ---
        // Dark Gray
        0x63 | 0x9d | 0x9e => Rgba([0x9d, 0x9d, 0x9d, 255]),
        // Gray
        0x64 | 0xc9 | 0xca => Rgba([0xc9, 0xc9, 0xc9, 255]),

        // --- Handle all other bytes as anti-aliasing pixels ---
        _ => {
            // The byte value itself represents the grayscale intensity.
            // This renders the smooth edges of handwritten strokes.
            // this encoding is from the newer note format.
            Rgba([pixel_byte, pixel_byte, pixel_byte, 255])
        }
    }
}

fn main() -> Result<()> {
    let file_path = "./data/sample.note";

    // file handle dropped outside this scope
    let notebook = {
        let mut file = File::open(file_path)?;
        parse_notebook(&mut file)?
    };

    let page_images = notebook
        .pages
        .par_iter()
        .map(|page| {
            let mut file = File::open(file_path)?;

            let mut base_canvas = RgbaImage::from_pixel(
                A5X_WIDTH as u32,
                A5X_HEIGHT as u32,
                Rgba([255, 255, 255, 255]),
            );

            for layer in page.layers.iter() {
                if layer.bitmap_address == 0 {
                    continue;
                } else if layer.protocol.as_str() == "RATTA_RLE" {
                    file.seek(SeekFrom::Start(layer.bitmap_address))?;
                    let mut len_bytes = [0u8; 4];
                    file.read_exact(&mut len_bytes)?;
                    let block_len = u32::from_le_bytes(len_bytes) as usize;
                    let mut compressed_data = vec![0; block_len];
                    file.read_exact(&mut compressed_data)?;
                    let pixel_data = decode_rle(&compressed_data)?;

                    let mut layer_image = RgbaImage::new(A5X_WIDTH as u32, A5X_HEIGHT as u32);
                    for (i, &pixel_byte) in pixel_data.iter().enumerate() {
                        let x = (i % A5X_WIDTH) as u32;
                        let y = (i / A5X_WIDTH) as u32;
                        layer_image.put_pixel(x, y, to_rgba(pixel_byte));
                    }
                    imageops::overlay(&mut base_canvas, &layer_image, 0, 0);
                } else if layer.protocol.as_str() == "PNG" {
                    file.seek(SeekFrom::Start(layer.bitmap_address))?;
                    let mut len_bytes = [0u8; 4];
                    file.read_exact(&mut len_bytes)?;
                    let block_len = u32::from_le_bytes(len_bytes) as usize;

                    let mut png_bytes = vec![0; block_len];
                    file.read_exact(&mut png_bytes)?;
                    let png_image = image::load_from_memory(&png_bytes)?.to_rgba8();
                    imageops::overlay(&mut base_canvas, &png_image, 0, 0);
                }
            }

            Ok(base_canvas)
        })
        .collect::<Result<Vec<_>>>()?;

    let total_pages = page_images.len();
    let page_chunks: Vec<PdfPageChunk> = page_images
        .into_par_iter()
        .enumerate() 
        .map(|(i, canvas)| {
            // Each page will use 3 objects: Page, Contents, Image
            let page_obj_id = (i * 3) + 3;
            let contents_obj_id = (i * 3) + 4;
            let image_obj_id = (i * 3) + 5;

            let dynamic_image = image::DynamicImage::ImageRgba8(canvas);

            let raw_pixels = dynamic_image.to_rgb8().into_raw();

            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&raw_pixels).unwrap();
            let compressed_pixels = encoder.finish().unwrap();

            let page_object = format!(
                "{} 0 obj\n<< /Type /Page\n   /Parent 2 0 R\n   /MediaBox [0 0 595 842]\n   /Contents {} 0 R\n   /Resources << /XObject << /Im1 {} 0 R >> >>\n>>\nendobj\n",
                page_obj_id,
                contents_obj_id,
                image_obj_id
            ).into_bytes();

            let contents = "q\n595 0 0 842 0 0 cm\n/Im1 Do\nQ\n";
            let contents_object = format!(
                "{} 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n",
                contents_obj_id,
                contents.len(),
                contents
            ).into_bytes();
            
            let image_header = format!(
                "{} 0 obj\n<< /Type /XObject\n   /Subtype /Image\n   /Width {}\n   /Height {}\n   /ColorSpace /DeviceRGB\n   /BitsPerComponent 8\n   /Filter /FlateDecode\n   /Length {} >>\nstream\n",
                image_obj_id,
                A5X_WIDTH,
                A5X_HEIGHT,
                compressed_pixels.len()
            ).into_bytes();

            // Combine the header, the compressed data, and the footer for the image object
            let final_image_object = [
                image_header,
                compressed_pixels,
                b"\nendstream\nendobj\n".to_vec()
            ].concat();

            PdfPageChunk {
                page_object,
                contents_object,
                image_object: final_image_object,
            }
        })
        .collect();

    // Write everything to a file sequentially 
    let out_file = File::create("output.pdf")?;
    let mut writer = BufWriter::new(out_file);
    let mut byte_offset = 0u64;
    let mut xref_offsets = vec![0u64; total_pages * 3 + 2]; // Room for all objects

    // Write PDF Header
    let header = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n"; // Header + binary comment
    writer.write_all(header)?;
    byte_offset += header.len() as u64;

    // Object 1: Catalog
    xref_offsets[0] = byte_offset;
    let catalog = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
    writer.write_all(catalog)?;
    byte_offset += catalog.len() as u64;

    // Object 2: The root Pages object
    xref_offsets[1] = byte_offset;
    let page_refs: String = (0..total_pages)
        .map(|i| format!("{} 0 R", (i * 3) + 3))
        .collect::<Vec<_>>()
        .join(" ");
    let pages_root = format!(
        "2 0 obj\n<< /Type /Pages /Kids [ {} ] /Count {} >>\nendobj\n",
        page_refs, total_pages
    ).into_bytes();
    writer.write_all(&pages_root)?;
    byte_offset += pages_root.len() as u64;

    // --- Write all the page chunks : cannot be parallelised ---
    for (i, chunk) in page_chunks.iter().enumerate() {
        let page_obj_id_idx = (i * 3) + 2;
        
        xref_offsets[page_obj_id_idx] = byte_offset;
        writer.write_all(&chunk.page_object)?;
        byte_offset += chunk.page_object.len() as u64;

        xref_offsets[page_obj_id_idx + 1] = byte_offset;
        writer.write_all(&chunk.contents_object)?;
        byte_offset += chunk.contents_object.len() as u64;
        
        xref_offsets[page_obj_id_idx + 2] = byte_offset;
        writer.write_all(&chunk.image_object)?;
        byte_offset += chunk.image_object.len() as u64;
    }

    // --- Write Cross-Reference Table and Trailer ---
    let xref_start_offset = byte_offset;
    writer.write_all(b"xref\n")?;
    writer.write_all(format!("0 {}\n", xref_offsets.len() + 1).as_bytes())?;
    writer.write_all(b"0000000000 65535 f \n")?; // XRef entry for object 0
    for offset in &xref_offsets {
        writer.write_all(format!("{:010} 00000 n \n", offset).as_bytes())?;
    }

    writer.write_all(b"trailer\n")?;
    writer.write_all(format!("<< /Size {} /Root 1 0 R >>\n", xref_offsets.len() + 1).as_bytes())?;
    writer.write_all(b"startxref\n")?;
    writer.write_all(format!("{}\n", xref_start_offset).as_bytes())?;
    writer.write_all(b"%%EOF\n")?;

    writer.flush()?;

    println!("Successfully created PDF.");
    Ok(())
}
