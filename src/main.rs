use anyhow::{Ok, Result};
use image::{Rgba, RgbaImage, imageops};
use itertools::Itertools;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use vtracer::{ColorImage, convert};

const A5X_WIDTH: usize = 1404;
const A5X_HEIGHT: usize = 1872;

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
    let re = Regex::new(r"<(?P<key>[^:]+?):(?P<value>.*?)>")?;

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
    let map: HashMap<String, String> = re
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
        .sorted_by_key(|(k, _v)| *k)
        .map(|(_k, v)| v.parse::<u64>())
        .collect::<std::result::Result<Vec<u64>, _>>()?;

    // let page_map = parse_metadata_block(&mut file, *page_addrs.get(0).unwrap());
    // println!("{:?}", page_map);

    let mut pages: Vec<Page> = Vec::new();
    for addr in page_addrs {
        let page_map = parse_metadata_block(file, addr)?;
        let layer_keys = ["BGLAYER", "MAINLAYER", "LAYER1", "LAYER2", "LAYER3"];
        let mut layers: Vec<Layer> = Vec::new();
        for layer_key in layer_keys {
            if page_map.contains_key(layer_key) {
                let layer_addr = page_map.get(layer_key).unwrap().parse::<u64>()?;
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

// make main return result so you can work with functions returning result
// and just use ? to access the ok value
fn main() -> Result<()> {
    let file_path = "./data/sample.note";
    let mut file = File::open(file_path)?;
    println!("Attempting to read signature from: {}", file_path);

    let signature = get_signature(&mut file)?;
    println!("File Signature: {}", signature);

    let notebook = parse_notebook(&mut file)?;
    // println!("{:?}", notebook);
    // Let's try to decode the first RLE layer we find.

    // Let's process the very first page of the notebook.
    if let Some(first_page) = notebook.pages.get(0) {
        println!("\n--- Compositing Page 0 ---");

        let mut base_canvas = RgbaImage::from_pixel(
            A5X_WIDTH as u32,
            A5X_HEIGHT as u32,
            Rgba([255, 255, 255, 255]), // Solid White
        );
        // iterate through layers in page
        for (l, layer) in first_page.layers.iter().enumerate() {
            if layer.bitmap_address == 0 {
                continue; // Skip empty/unused layers
            }

            // println!(
            //     "Processing Layer {}: Protocol='{}', Address={}",
            //     l, layer.protocol, layer.bitmap_address
            // );

            let pixel_data = match layer.protocol.as_str() {
                "RATTA_RLE" => {
                    // Read the compressed RLE data block
                    file.seek(SeekFrom::Start(layer.bitmap_address))?;
                    let mut len_bytes = [0u8; 4];
                    file.read_exact(&mut len_bytes)?;
                    let block_len = u32::from_le_bytes(len_bytes) as usize;
                    let mut compressed_data = vec![0; block_len];
                    file.read_exact(&mut compressed_data)?;
                    // this is returned to the match arm
                    decode_rle(&compressed_data)?
                }
                "PNG" => {
                    // this match arm mutates base canvas directly
                    file.seek(SeekFrom::Start(layer.bitmap_address))?;
                    let mut len_bytes = [0u8; 4];
                    file.read_exact(&mut len_bytes)?;
                    let block_len = u32::from_le_bytes(len_bytes) as usize;

                    let mut png_bytes = vec![0; block_len];
                    file.read_exact(&mut png_bytes)?;
                    let png_image = image::load_from_memory(&png_bytes)?.to_rgba8();

                    imageops::overlay(&mut base_canvas, &png_image, 0, 0);
                    continue;
                }
                _ => {
                    println!("  -> Skipping unsupported protocol '{}'", layer.protocol);
                    continue;
                }
            };

            let mut layer_image = RgbaImage::new(A5X_WIDTH as u32, A5X_HEIGHT as u32);
            for (i, &pixel_byte) in pixel_data.iter().enumerate() {
                let x = (i % A5X_WIDTH) as u32;
                let y = (i / A5X_WIDTH) as u32;
                layer_image.put_pixel(x, y, to_rgba(pixel_byte));
            }

            imageops::overlay(&mut base_canvas, &layer_image, 0, 0);
        }

        let output_filename = "output_page_0_composite.png";
        base_canvas.save(output_filename)?;
        println!("\n✅ Page 0 composite image saved as '{}'", output_filename);
    } else {
        println!("\nNotebook has no pages to process.");
    }

    Ok(())
}
