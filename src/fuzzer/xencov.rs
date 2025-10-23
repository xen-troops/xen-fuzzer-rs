use std::collections::HashMap;
use std::io::Read;
use serde::{Deserialize, Serialize};
use bytes::Buf;
use std::slice::from_raw_parts;

const GCDA_MAGIC: u32 = 0x67636461;
const GCOV_TAG_FUNCTION: u32 = 0x01000000;
const GCOV_TAG_COUNTER_COV: u32 = 0x01a10000;
const GCOV_TAG_COUNTER_COND: u32 = 0x01b10000;
const GCOV_WORD_SIZE: u32 = 4;

const XENCOV_AREA_SIZE: usize = 2 * 1024 * 1024;

// TODO: disabled by default
#[unsafe(no_mangle)]
pub static mut __xencov_available: core::ffi::c_uint = 1;
#[unsafe(no_mangle)]
pub static mut __xencov_data_buf: [u8; XENCOV_AREA_SIZE] = [0; XENCOV_AREA_SIZE];
#[unsafe(no_mangle)]
pub static mut __xencov_data_size: core::ffi::c_uint = XENCOV_AREA_SIZE as core::ffi::c_uint;

pub type CovDiscovered = u32;
pub type CovDone = u32;

pub trait XenCovStat {
    fn get_stat(&self) -> (CovDone, CovDiscovered);
}

pub fn xencov_map_data_ptr() -> *const u8 {
    unsafe {
	__xencov_available = 1;
	&raw const __xencov_data_buf as *const u8
    }
}

pub fn xencov_map_data_slice() -> &'static [u8] {
    unsafe {
	from_raw_parts(xencov_map_data_ptr(), __xencov_data_size as usize)
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize)]
struct CondCounter {
    t_val: u64, // TRUE counter
    f_val: u64, // FALSE counter
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct GcdaFunc {
    id: u32,
    line_check: u32,
    cfg_check: u32,
    mcdc_counters: Vec<CondCounter>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct GcdaFile {
    version: u32,
    stamp: u32,
    checksum: u32,
    functions: Vec<GcdaFunc>,
}

#[derive(Debug, Clone)]
struct GcdaTag {
    tag: u32,
    entries: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct XenCov {
    entries: HashMap<String, GcdaFile>,
}

fn read_u32<T: Read>(f: &mut T) -> Option<u32> {
    let mut buf = [0; 4];

    match f.read_exact(&mut buf) {
        Ok(_) => Some(u32::from_le_bytes(buf)),
        Err(_) => None,
    }
}

fn read_entry<T: Read>(f: &mut T) -> Option<(String, GcdaFile)> {
    let mut name = String::new();

    for byte in f.bytes() {
        match byte {
            Ok(0) => break,
            Ok(ch) => name.push(ch as char),
            _ => panic!("Error reading file name"),
        };
    }

    if name.is_empty() {
        return None;
    }

    let size = read_u32(f).expect("Can't read size");
    let data = GcdaFile::parse(&mut f.take(size as u64));

    Some((name, data))
}

impl GcdaFunc {
    fn ensure_same(&self, other: &GcdaFunc) {
        if self.id != other.id
            || self.cfg_check != other.cfg_check
            || self.line_check != other.line_check
        {
            panic!("GCOV function mismatch");
        }
    }

    fn parse(tag: &GcdaTag) -> GcdaFunc {
        if tag.entries.len() < 3 {
            panic!("Not enough entries for a GCDA function tag");
        }

        GcdaFunc {
            id: tag.entries[0],
            line_check: tag.entries[1],
            cfg_check: tag.entries[2],
            mcdc_counters: Vec::new(),
        }
    }
}

impl GcdaFile {
    fn ensure_same(&self, other: &GcdaFile) {
        if self.version != other.version
            || self.stamp != other.stamp
            || self.checksum != other.checksum
        {
            panic!("GCOV file attributes mismatch");
        }
    }
    fn parse<T: Read>(f: &mut T) -> GcdaFile {
        let magic = read_u32(f).expect("Can't read GCDA magic");
        if magic != GCDA_MAGIC {
            panic!("GCDA magic mismatch: {magic}")
        }

        let version = read_u32(f).expect("Can't read GCDA version");
        let stamp = read_u32(f).expect("Can't read GCDA stamp");
        let checksum = read_u32(f).expect("Can't read GCDA checksum");

        let mut func = GcdaFunc {
            id: 0,
            line_check: 0,
            cfg_check: 0,
            mcdc_counters: Vec::new(),
        };
        let mut functions = Vec::new();

        loop {
            let tag = match GcdaTag::parse(f) {
                Some(tag) => tag,
                None => break,
            };

            match tag.tag {
                GCOV_TAG_FUNCTION => {
                    if func.id != 0 {
                        functions.push(func);
                    };
                    func = GcdaFunc::parse(&tag);
                }
                GCOV_TAG_COUNTER_COV => (),
                GCOV_TAG_COUNTER_COND => {
                    let mut cond_cnt = CondCounter::parse(&tag);
                    func.mcdc_counters.append(&mut cond_cnt);
                }
                _ => println!("Skipping unknown tag {:x}", tag.tag),
            }
        }
        GcdaFile {
            version,
            stamp,
            checksum,
            functions,
        }
    }

    fn diff_new(&self, other: &GcdaFile) -> bool {
        self.ensure_same(&other);
        for i in 0..self.functions.len() {
            self.functions[i].ensure_same(&other.functions[i]);
            for k in 0..self.functions[i].mcdc_counters.len() {
                if self.functions[i].mcdc_counters[k].diff_new(&other.functions[i].mcdc_counters[k])
                {
                    println!(
                        "F:{:#x}({k}) t/f {:#b}/{:#b} != {:#b}/{:#b}",
                        self.functions[i].id,
                        self.functions[i].mcdc_counters[k].t_val,
                        self.functions[i].mcdc_counters[k].f_val,
                        other.functions[i].mcdc_counters[k].t_val,
                        other.functions[i].mcdc_counters[k].f_val
                    );
                    return true;
                }
            }
        }
        false
    }
}

impl GcdaTag {
    fn parse<T: Read>(f: &mut T) -> Option<GcdaTag> {
        let tag = read_u32(f)?;
        let len = read_u32(f).expect("Can't read tag len") / GCOV_WORD_SIZE;

        let mut entries: Vec<u32> = Vec::new();

        for _ in 0..len {
            entries.push(read_u32(f).expect("Can't read GCDA tag data"))
        }

        Some(GcdaTag { tag, entries })
    }
}

// TODO: Endianess...
fn u32tou64(v1: u32, v2: u32) -> u64 {
    (v1 as u64) + ((v2 as u64) << 32)
}

impl CondCounter {
    fn diff_new(&self, other: &CondCounter) -> bool {
        ((self.f_val | other.f_val) != self.f_val) || ((self.t_val | other.t_val) != self.t_val)
    }

    fn parse(tag: &GcdaTag) -> Vec<CondCounter> {
        let num = tag.entries.len() / 4;

        let mut counters = Vec::new();

	for i in 0..num {
            counters.push(CondCounter {
                t_val: u32tou64(tag.entries[i * 2], tag.entries[i * 2 + 1]),
                f_val: u32tou64(tag.entries[i * 2 + 2], tag.entries[i * 2 + 3]),
            });
	}

        counters
    }
}

impl XenCov {
    // Returns true if there was a difference
    pub fn diff_new(&self, other: &XenCov) -> bool {
        // We expect that list of files is persistent between test cases
        for k in self.entries.keys() {
            if self.entries[k].diff_new(&other.entries[k]) {
                println!("Difference in {k}");
                return true;
            }
        }
        false
    }

    pub fn merge(&mut self, other: &XenCov) {
        // We expect that list of files is persistent between test cases
        for k in other.entries.keys() {
            let gcda_into = self.entries.get_mut(k).unwrap();
            let gcda_from = &other.entries[k];
            for i in 0..gcda_into.functions.len() {
                gcda_into.functions[i].ensure_same(&gcda_from.functions[i]);

                let counters_into = &mut gcda_into.functions[i].mcdc_counters;
                let counters_from = &gcda_from.functions[i].mcdc_counters;

                for k in 0..counters_into.len() {
                    counters_into[k].t_val |= counters_from[k].t_val;
                    counters_into[k].f_val |= counters_from[k].f_val;
                }
            }
        }
    }

    pub fn parse<T: Read>(f: &mut T) -> Option<XenCov> {
        let mut magic = [0; 4];

        f.read_exact(&mut magic).expect("Can't read header");

        if magic[0] != b'V' || magic[1] != b'O' || magic[2] != b'C' || magic[3] != b'X' {
	    println!("Xencov: invalid magic");
	    return None;
        };

        let mut cov_files = HashMap::new();

        loop {
            match read_entry(f) {
                Some((fname, data)) => cov_files.insert(fname, data),
                None => break,
            };
        }

        Some(XenCov { entries: cov_files })
    }

    // TODO: Take a pointer to memory + size
    pub fn parse_from_mem() -> Option<XenCov> {
	Self::parse(xencov_map_data_slice().reader().get_mut())
    }

    pub fn hacky_save() -> () {
	// Determine next free file and save data
	for idx in 0..100000 {
	    let fname = format!("/home/lorc/mnt/ssd/xen_fuzz/xen_fuzzer/gcov_reports/{idx:0>5}.cov");
	    if !std::fs::exists(&fname).expect("Can't check for existence") {
		println!("Saved gcov into {fname}");
		std::fs::write(&fname, xencov_map_data_slice()).expect("Failed to hacky write coverage data");
		return;
	    }
	}
	panic!("We are out of free files")
    }
}

impl AsRef<Self> for XenCov {
    fn as_ref(&self) -> &Self {
	self
    }
}

impl AsMut<Self> for XenCov {
    fn as_mut(&mut self) -> &mut Self {
	self
    }
}

impl XenCovStat for CondCounter {
    fn get_stat(&self) -> (CovDone, CovDiscovered) {
	let done = (self.f_val & self.t_val).count_ones();
	let discovered = (self.f_val | self.t_val).count_ones();

	(done, discovered)
    }
}

impl XenCovStat for GcdaFunc {
    fn get_stat(&self) -> (CovDone, CovDiscovered) {
	let mut done = 0;
	let mut discovered = 0;
	for cnt in self.mcdc_counters.iter() {
	    let (cnt_done, cnt_discovered) = cnt.get_stat();
	    done += cnt_done;
	    discovered += cnt_discovered;
	}

	(done, discovered)
     }
}

impl XenCovStat for GcdaFile {
   fn get_stat(&self) -> (CovDone, CovDiscovered) {
	let mut done = 0;
	let mut discovered = 0;
	for cnt in self.functions.iter() {
	    let (cnt_done, cnt_discovered) = cnt.get_stat();
	    done += cnt_done;
	    discovered += cnt_discovered;
	}

       (done, discovered)
   }
}

impl XenCovStat for XenCov {
  fn get_stat(&self) -> (CovDone, CovDiscovered) {
	let mut done = 0;
	let mut discovered = 0;
	for cnt in self.entries.iter() {
	    let (cnt_done, cnt_discovered) = cnt.1.get_stat();
	    done += cnt_done;
	    discovered += cnt_discovered;
	}

       (done, discovered)
   }
}
