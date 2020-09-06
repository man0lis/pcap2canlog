#![recursion_limit = "1024"]
#[macro_use]
extern crate error_chain;

mod errors {
    error_chain! {}
}
use byteorder::{LittleEndian, ReadBytesExt};
use clap::{App, Arg};
use errors::*;
use pcap::Capture;
use std::io::Cursor;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const AUTHOR: &'static str = concat!("by ", env!("CARGO_PKG_AUTHORS"));

const EXTENDED_FLAG_MASK: u32 = 1 << 31;
const ID_PART_MASK: u32 = (1 << 29) - 1;

type CanId = u32;

#[derive(Debug, PartialEq, Eq)]
struct CanFrame {
    is_extended: bool,
    id: CanId,
    datalen: u8,
    data: [u8; 8],
}

impl CanFrame {
    // https://github.com/torvalds/linux/blob/3926a3a/include/uapi/linux/can.h#L93
    /// Decodes a CAN frame
    fn new(frame: &[u8]) -> Option<CanFrame> {
        let mut reader = Cursor::new(frame);
        let id_ = reader.read_u32::<LittleEndian>().ok()?;
        let id = id_ & ID_PART_MASK;
        let is_extended = ((id_ & EXTENDED_FLAG_MASK) >> 31) == 1;
        let datalen = reader.read_u8().ok()?;

        // skip reserved bytes
        reader.set_position(reader.position() + 3);
        if datalen > 8 {
            return None;
        }

        let mut dataout = [0u8; 8];

        for i in 0..datalen as usize {
            dataout[i] = reader.read_u8().ok()?;
        }
        Some(CanFrame {
            is_extended,
            id,
            datalen,
            data: dataout,
        })
    }
}

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
        .arg(
            Arg::with_name("devname")
                .long("devname")
                .help("device name to put in the log")
                .required(false)
                .default_value("can0"),
        )
        .get_matches();

    // load pcap file
    let mut cap = Capture::from_file(
        matches
            .value_of("pcap_file")
            .chain_err(|| "invalid pcap file name")?,
    )
    .chain_err(|| "could not load pcap file")?;

    let devname = matches
        .value_of("devname")
        .chain_err(|| "invalid devname")?;

    while let Ok(packet) = cap.next() {
        // slice protocol from packet
        let protocol = &packet.data[14..16];
        // check if it is a can packet, if not ignore it
        if protocol != [0, 0xc] {
            continue;
        }

        // split packet data from packet metadata
        let packet_data = &packet.data[16..];
        let frame = CanFrame::new(packet_data);
        let frame = match frame {
            Some(f) => f,
            None => continue,
        };

        // convert can data to hex string
        let mut can_hex_str = String::new();
        for b in frame.data[0..frame.datalen as usize].iter() {
            can_hex_str.push_str(format!("{:02X}", b).as_ref());
        }

        // print the packet in canlog format
        match frame.is_extended {
            // candump help:
            // "When the can_id is 8 digits long the CAN_EFF_FLAG is set for 29 bit EFF format."
            true => println!(
                "({}.{:06}) {} {:08X}#{}",
                packet.header.ts.tv_sec, packet.header.ts.tv_usec, devname, frame.id, can_hex_str
            ),
            // otherwise it is 3 digits long
            false => println!(
                "({}.{:06}) {} {:03X}#{}",
                packet.header.ts.tv_sec, packet.header.ts.tv_usec, devname, frame.id, can_hex_str
            ),
        }
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_decoding() {
        // only actual payload
        let ext1 = b"\x48\x20\x00\x80\x02\x00\xad\xde\x01\x30\x00\x00\x00\x00\xad\xde";

        assert_eq!(
            CanFrame::new(ext1),
            Some(CanFrame {
                is_extended: true,
                id: 0x2048,
                datalen: 2,
                data: [0x01, 0x30, 0, 0, 0, 0, 0, 0],
            })
        );

        let bas1 = b"\x99\x07\x00\x00\x02\x10\x00\x00\x01\x31\x36\x2e\x35\x00\x00\x00";
        assert_eq!(
            CanFrame::new(bas1),
            Some(CanFrame {
                is_extended: false,
                id: 0x799,
                datalen: 2,
                data: [0x01, 0x31, 0, 0, 0, 0, 0, 0],
            })
        );
    }
}
