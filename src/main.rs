use anyhow::{Ok, Result};
use itertools::Itertools;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::hash::Hash;
use std::io::{Read, Seek, SeekFrom};

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
    pub protocol: String,
    pub bitmap_address: u64,
}

fn get_signature(file_path: &str) -> Result<String> {
    const SIGNATURE_OFFSET: u64 = 4;
    const SIGNATURE_LENGTH: usize = 20;

    // The `?` operator is used here. If `File::open` returns an `Err`, the `?`
    // will immediately stop this function and return that `Err` to the caller.
    // If it returns `Ok(file)`, it unwraps the value and assigns it to `file`.
    let mut file = File::open(file_path)?;

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

fn parse_notebook(file_path: &str) -> Result<Notebook> {
    let file_signature = get_signature(file_path)?;
    let mut file = File::open(file_path)?;

    // Get footer address and map
    file.seek(SeekFrom::End(-4))?;
    let mut addr_bytes = [0u8; 4];
    file.read_exact(&mut addr_bytes)?;
    let footer_addr = u32::from_le_bytes(addr_bytes) as u64; // Convert the little-endian bytes to a u32, then cast to u64
    let footer_map = parse_metadata_block(&mut file, footer_addr)?;
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
        let page_map = parse_metadata_block(&mut file, addr)?;
        let layer_keys = ["BGLAYER", "MAINLAYER", "LAYER1", "LAYER2", "LAYER3"];
        let mut layers: Vec<Layer> = Vec::new();
        for layer_key in layer_keys {
            if page_map.contains_key(layer_key) {
                let layer_addr = page_map.get(layer_key).unwrap().parse::<u64>()?;
                let data = parse_metadata_block(&mut file, layer_addr)?;
                layers.push(Layer {
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

// make main return result so you can work with functions returning result
// and just use ? to access the ok value
fn main() -> Result<()> {
    let file_path = "./data/sample.note";
    println!("Attempting to read signature from: {}", file_path);

    let signature = get_signature(file_path)?;
    println!("File Signature: {}", signature);

    let notebook = parse_notebook(file_path)?;
    println!("{:?}", notebook);

    Ok(())
}
