#![recursion_limit = "1024"]
extern crate byteorder;
extern crate clap;
#[macro_use]
extern crate error_chain;
extern crate pcap;

mod errors {
    error_chain!{}
}
use errors::*;
use clap::{App, Arg};
use pcap::Capture;
use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const AUTHOR: &'static str = concat!("by ", env!("CARGO_PKG_AUTHORS"));

fn run() -> Result<()> {
    // manage command line arguments using clap
    let matches = App::new("pcap2canlog")
        .version(VERSION)
        .author(AUTHOR)
        .about("A small utility to convert pcap files of socketcan traffic to the canlog format used by can-utils\nthe result is written to stdout")
        .arg(
            Arg::with_name("pcap_file")
                .value_name("pcap file")
                .help("the pcap file to convert")
                .required(true),
        )
        .get_matches();

    // load pcap file
    let mut cap =
        Capture::from_file(matches
            .value_of("pcap_file")
            .chain_err(|| "invalid pcap file name")?)
            .chain_err(|| "could not load pcap file")?;

    while let Ok(packet) = cap.next() {
        // slice protocol from packet
        let protocol = &packet.data[14..16];
        // check if it is a can packet, if not ignore it
        if protocol == [0, 0xc] {
            // split packet data from packet metadata
            let packet_data = &packet.data[16..];
            // create byte reader to convert multiple u8 with correct endianess
            let mut rdr = Cursor::new(packet_data);
            // extract can id
            let can_id = rdr.read_u16::<LittleEndian>()
                .chain_err(|| "could not read can id from packet")?;
            // extract length of can data
            let can_data_len = packet_data[4] as usize;
            // extract can data
            if packet_data.len() < can_data_len + 8 {
                eprintln!("malformed can packet, data is shorter than given length");
                continue;
            }
            let can_msg = &packet_data[8..can_data_len + 8];
            // convert can data to hex string
            let mut can_hex_str = String::new();
            for b in can_msg.iter() {
                can_hex_str.push_str(format!("{:02X}", b).as_ref());
            }
            // print the packet in canlog format
            // one might what to change the device name used, but thats future work :D
            println!(
                "({}.{}) can0 {:X}#{}",
                packet.header.ts.tv_sec, packet.header.ts.tv_usec, can_id, can_hex_str
            );
        };
    }

    Ok(())
}

// main with error handling
fn main() {
    if let Err(ref e) = run() {
        use std::io::Write;
        let stderr = &mut ::std::io::stderr();
        let errmsg = "Error writing to stderr";

        writeln!(stderr, "error: {}", e).expect(errmsg);

        for e in e.iter().skip(1) {
            writeln!(stderr, "caused by: {}", e).expect(errmsg);
        }

        // The backtrace is not always generated. Try to run this example
        // with `RUST_BACKTRACE=1`.
        if let Some(backtrace) = e.backtrace() {
            writeln!(stderr, "backtrace: {:?}", backtrace).expect(errmsg);
        }

        ::std::process::exit(1);
    }
}
