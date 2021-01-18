// Allow SnakeCase, block the warn
#![allow(non_snake_case)]

// List of Import/ lib used
use structopt::StructOpt;
use std::path::Path;
use std::string::String;
use walkdir::WalkDir;
use error_chain::error_chain;
use data_encoding::HEXUPPER;
use ring::digest::{Context, Digest, SHA256};
use std::fs::File;
use std::io::{BufReader, Read, BufRead, Write};

// Block many error for the reading 
// and pass the reading object 
error_chain! {
    foreign_links {
        Io(std::io::Error);
        Decode(data_encoding::DecodeError);
    }
}

// Structure for the option which can be used 
// by the program, structopt is use
#[derive(StructOpt, Debug)]
#[structopt(about="\tDescription: 
	\tThis program iter in directory present in a path or driver letter
	\tTo hash	the files and check in black or white list if they are good or bad.
	\tThe hash use for this program is the SHA256.
	\t\t\tDeveloped by Icenuke")]
struct Opt {
    /// Type a Driver letter or path to start Scan by the root 
    /// For drive letter enter this with ':/'!
    #[structopt(short="p", long="path", default_value="")]
    path: std::path::PathBuf,
    /// The file which contain no wanted hash
    #[structopt(short="b", long="blacklist")]
    blst: Option<std::path::PathBuf>,
    /// The file which contain good hash
    #[structopt(short="w", long="whitelist")]
    wlst: Option<std::path::PathBuf>,
    /// The file to export the result
    #[structopt(short="o", long="output")]
	out: Option<std::path::PathBuf>,
	/// Verbose Version, with verbose style all file check and not in 
	/// whitelist are printed. Without this option only the blacklisted file
	/// are printed
	#[structopt(short="v", long="verbose")]
	verb: bool,
}

// structure for the Hash from whitelist and blacklist
#[derive(Debug)]
struct Hash {
	name: String,
	hash: String,
}

// This function export the result
// of the scan in text file like this:
// <PathFile> - <Hash> 
fn ExportResult(exportpath: String, values: Vec<Hash>){
	let mut file = std::fs::File::create(exportpath).expect("create failed");
	for v in &values{
		let mut line = String::new();
		line.push_str(&v.name.to_string());
		line.push('\t');
		line.push_str(&v.hash.to_string());
		line.push('\n');
		file.write_all(line.as_bytes()).expect("write failed");

	}
}

// This function readfile 
// and return the result as a vector
fn Readfile(path: String) -> Vec<Hash>{
	println!("\t\t\t[>] Recording the Hash from:\n\t\t\t\t|> {}", path);
	// init vector with type struct Hash
	let mut lstVec: Vec<Hash> = Vec::new();
	// init the reading file object
	let fl = File::open(path).unwrap();
	// init the buffer object file
	let reader = BufReader::new(fl);

	// iter in all line in file
	for ln in reader.lines(){
		// create mutable string hash variable
		let mut hash: String = ln.unwrap().to_string();
		// find the offset of tab in string
		let tabOffset = hash.find("\t").unwrap_or(hash.len());
		// split the string in 2 part
		// name of file and the hash
		let name: String = hash.drain(..tabOffset+1).collect();
		// remove the last char (the special char \t)
		let name: String = (&name[..name.len()-1]).to_string();
		// convert hash string in lowercase
		hash = hash.to_lowercase();
		// add in hash structure the name and the hash 
		let theHash = Hash {name, hash};
		// push in vetor the structure
		lstVec.push(theHash);
		
	}
	println!("\t\t\t[>] Hash Record finish!");

	// return the vector which contain the hash struc
	lstVec

}

// This function hash the files passed
// passed in parameter and return the result 
// as a vector
fn Hashfile<R: Read>(mut reader: R) -> Result<Digest>{
    // init the SHA256 hashing object 
    let mut context = Context::new(&SHA256);
    // init the buffer size use to reading
    let mut buffer = [0; 1024];

    // Iter in all bytes in files until the EOF
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
        	// break the loop, see if another way for this exist
            break;
        }
        // update the hashing object with the part that was iterated
        context.update(&buffer[..count]);
    }
    // when the loop end, return the finaly context hash 
    Ok(context.finish())

}


// This function iter in path/driver
// for hash the file and check with white 
// or black list
fn ScanSys(originScan: String) -> Result<bool>{
	println!("\t\t[+] Enter in Scanning Section:");

	// Record the blacklist arg, create a blacklst vector var
	// check with match if arg exist and is exist then
	// record in string the pass of blacklist and go to read this file
	// and record the hash list else 
	// go to default pass to record the hash list
	let bl = Opt::from_args().blst;
	let mut blacklst: Vec<Hash> = Vec::new();
	match bl {
		Some(bls) => {
			// if path of blacklist file exist then go go go
			match Path::new(&bls).exists() {
				true => {
					println!("\t\t\t[>] Blacklist used: {}", bls.as_path().display().to_string());
					blacklst = Readfile(bls.as_path().display().to_string());
				}
				// if no path exist print error
				false => println!("\t[!] Path doesn't exist: {}", bls.as_path().display().to_string()),
			}
		},
		None => {
			// if default blacklist file exist then go go go
			let blDef = "blacklist.txt".to_string();
			match Path::new(&blDef).exists() {
				true => {
					println!("\t\t\t[>] Default Blacklist used: {}", blDef);
					blacklst = Readfile(blDef);
				}
				// if default blacklist not exist print error
				false => println!("\t[!] Blacklist doesn't exist: {}", blDef),
			}
		},
	}

	// Record the whitelist arg, create a whitelst vector var
	// check with match if arg exist and is exist then
	// record in string the pass of whitelist and go to read this file
	// and record the hash list else 
	// go to default pass to record the hash list
	let wl = Opt::from_args().wlst;
	let mut whitelst: Vec<Hash> = Vec::new();
	match wl {
		Some(wls) => {
			// if path of whitelist file exist then go go go
			match Path::new(&wls).exists() {
				true => {
					println!("\t\t\t[>] Whitelist used: {}", wls.as_path().display().to_string());
					whitelst = Readfile(wls.as_path().display().to_string());
				}
				// if no path exist print error
				false => println!("\t[!] Whitelist doesn't exist: {}", wls.as_path().display().to_string()),
			}	
		},
		None => {
			// if default whitelist file exist then go go go
			let wlDef = "whitelist.txt".to_string();
			match Path::new(&wlDef).exists() {
				true => {
					println!("\t\t\t[>] Default Whitelist used: {}", wlDef);
					whitelst = Readfile(wlDef);
				}
				// if default whitelist not exist print error
				false => println!("\t[!] Whitelist doesn't exist: {}", wlDef),
			}
		},
	}

	println!("\n\t\t[+] Start Scanning:");
	// init vector with type struct Hash for all file scan
	let mut vecFiles: Vec<Hash> = Vec::new();
	
	// Iter recursively in the 'originPath'
	for line in WalkDir::new(originScan).into_iter().filter_map(|e| e.ok()) {
    	// if the line is a file then 
    	// Send to hash function
    	if line.file_type().is_file(){
    		// Open the file to reading
			let input = File::open(line.path().display().to_string())?;
			// Init the buffer for the reader object 
		    let reader = BufReader::new(input);
    		
    		// call Hashfile to hash the file  ahah
    		let digest = Hashfile(reader)?;
			// encode the digest in hex and convert it to string
			let hash = HEXUPPER.encode(digest.as_ref()).to_string().to_lowercase();

			// convert dirEntry to string
			let name: String = line.path().display().to_string();

			// add in hash structure the name and the hash 
			let filesHash = Hash {name, hash};
			// push in vetor the structure
			vecFiles.push(filesHash);
		}
	}

	// init vector with type struct Hash for all file scan blacklisted
	let mut blackFlExp: Vec<Hash> = Vec::new();
	// init vector with type struct Hash for all file scan blacklisted
	let mut otherFlExp: Vec<Hash> = Vec::new();
	// check verbosity opion
	let vb = Opt::from_args().verb;

	for h in &vecFiles{
		// iter in hashing vector 
		for bh in &blacklst{
			// check if the hash of file is in blacklist
			if bh.hash == h.hash{
				println!("\t\t\t-------------------------------------------------");
				println!("\t\t\t[F] Filename 		 -> {}", h.name);
				println!("\t\t\t[H] Hash 		 -> {}", h.hash);
				println!("\t\t\t[!] Find in Blacklist 	 -> {}", bh.name);

				// add information in structure
				let blFlExp = Hash {name: h.name.to_string(), hash: h.hash.to_string()};
				// push in vetor the structure
				blackFlExp.push(blFlExp);
			}
		}

		// if verbosity option exist then iter in whitelist and
		// check if the hash of file isn't in whitlist 
		match vb {
			true => {
				for wh in &whitelst{
					// if hash different of whitelist hash
					if wh.hash != h.hash{
						println!("\t\t\t-------------------------------------------------");
	    				println!("\t\t\t[F] Filename 		 -> {}", h.name);
	    				println!("\t\t\t[H] Hash 		 -> {}", h.hash);
	    				println!("\t\t\t[?] Not in Whitelist!!");

		    			// add information in structure
						let otFlExp = Hash {name: h.name.to_string(), hash: h.hash.to_string()};
						// push in vetor the structure
						otherFlExp.push(otFlExp);

					}else{
						continue;
					}
				}
			},
			false => continue,
		}
	}
	vecFiles.clear();

	println!("\n\t\t[+] Scanning Finished!!");

	// Record the output option
	// check if option is present
	// if present then export result in file
	// else nothing passed
	//let outPath = Opt::from_args().out.as_path().display().to_string();
	let output = Opt::from_args().out;
	
	// if oupput arg present then go to export the result
	match output {
		Some(o) => {
			// if path exist then continue to export files
			match Path::new(&o).exists() {
				true => { 
					println!("\n\t\t[+] Start Export:");

					// Export blacklisted files 
					let outP: String = o.display().to_string() + "/Blacklist-o.txt"; 
					println!("\t\t\t-------------------------------------------------");
					ExportResult(outP, blackFlExp); 
					println!("\t\t\t[>] Output file {}/blacklist-o.txt created ", o.display().to_string());

					// if verbosity then export no matched files
					match vb{
						true => {
							// call export result for the no matched files
							let outP2: String = o.display().to_string() + "/NoMatchedFiles-o.txt"; 
							println!("\t\t\t-------------------------------------------------");
							ExportResult(outP2, otherFlExp); 
							println!("\t\t\t[>] Output file {}/NoMatchedFiles-o.txt created ", o.display().to_string());

						},
						false => println!(""),
					}
					println!("\n\t\t[+] Export Finish!!");
				},
				false => {
					println!("\t\t\t-------------------------------------------------");
					println!("\t\t\t[!] Path doesn't exist: {}", o.display().to_string());
					std::process::exit(exitcode::OK);
				},
			}
		}, 
		None => {
			println!("\t\t\t-------------------------------------------------");
			println!("\t\t\t[>] No output file wanted");
		},
	}


	// leave that here, whitout the fonction have a problem
	Ok(true)
}

fn main(){
	println!("\t\t    .---------.");
	println!("\t\t--==[ SysScan ]==--");
	println!("\t\t    '---------'");

	// Record args driver and path from Opt struct 
	let pathStr = Opt::from_args().path.as_path().display().to_string();
	let pathBuf = Opt::from_args().path;

	// if path not Empty then check
	// if the path exist and go to Scan else 
	// show error message
	if pathStr != "" {
		match Path::new(&pathBuf).exists() {
			true => { let _B = ScanSys(pathStr); },
			false => println!("\t[!] Path doesn't exist: {}", pathStr),
		}
	}
	// if no driver or path show Error message
	else{
		println!("\t[!] No Driver/Path!\n\tFor more information use -h/--help!");
		std::process::exit(exitcode::OK);
	}

}
