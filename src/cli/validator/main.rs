use clap::{App, Arg, SubCommand};
use sp_core::{crypto::Pair, sr25519, Pair as PairT, H256};
use sp_runtime::MultiSignature;
use std::{fs, path::Path, str::FromStr};

mod api;
mod commands;
mod config;
mod types;

use api::PeoChainApi;
use commands::ValidatorCommands;
use config::Config;
use types::{Balance, BlockNumber, ProofOfEscrow, ValidatorId};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("PeoChain Validator CLI")
        .version("1.0")
        .author("PeoChain Team")
        .about("CLI tool for PeoChain validator operations")
        .subcommand(
            SubCommand::with_name("generate-keys")
                .about("Generate validator keys")
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .value_name("DIR")
                        .help("Output directory for keys")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("create-escrow")
                .about("Create a non-custodial escrow")
                .arg(
                    Arg::with_name("node")
                        .short("n")
                        .long("node")
                        .value_name("URL")
                        .help("Node URL")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("amount")
                        .short("a")
                        .long("amount")
                        .value_name("AMOUNT")
                        .help("Amount to bond")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("timelock")
                        .short("t")
                        .long("timelock")
                        .value_name("BLOCKS")
                        .help("Timelock period in blocks")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("register-validator")
                .about("Register as a validator")
                .arg(
                    Arg::with_name("node")
                        .short("n")
                        .long("node")
                        .value_name("URL")
                        .help("Node URL")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("key")
                        .short("k")
                        .long("key")
                        .value_name("FILE")
                        .help("Path to validator key file")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("escrow")
                        .short("e")
                        .long("escrow")
                        .value_name("ID")
                        .help("Escrow ID")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("submit-performance")
                .about("Submit performance proof")
                .arg(
                    Arg::with_name("node")
                        .short("n")
                        .long("node")
                        .value_name("URL")
                        .help("Node URL")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("key")
                        .short("k")
                        .long("key")
                        .value_name("FILE")
                        .help("Path to validator key file")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("epoch")
                        .short("e")
                        .long("epoch")
                        .value_name("EPOCH")
                        .help("Epoch number")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("start-block")
                        .short("s")
                        .long("start-block")
                        .value_name("BLOCK")
                        .help("Start block number")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("end-block")
                        .short("d")
                        .long("end-block")
                        .value_name("BLOCK")
                        .help("End block number")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("participation")
                        .short("p")
                        .long("participation")
                        .value_name("HEX")
                        .help("Participation bitmap in hex")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("unbond")
                .about("Unbond validator")
                .arg(
                    Arg::with_name("node")
                        .short("n")
                        .long("node")
                        .value_name("URL")
                        .help("Node URL")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("key")
                        .short("k")
                        .long("key")
                        .value_name("FILE")
                        .help("Path to validator key file")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("validator-id")
                        .short("v")
                        .long("validator-id")
                        .value_name("ID")
                        .help("Validator ID")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("create-threshold-escrow")
                .about("Create a threshold signature escrow")
                .arg(
                    Arg::with_name("node")
                        .short("n")
                        .long("node")
                        .value_name("URL")
                        .help("Node URL")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("amount")
                        .short("a")
                        .long("amount")
                        .value_name("AMOUNT")
                        .help("Amount to bond")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("threshold")
                        .short("t")
                        .long("threshold")
                        .value_name("THRESHOLD")
                        .help("Threshold value")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("participants")
                        .short("p")
                        .long("participants")
                        .value_name("PARTICIPANTS")
                        .help("Total participants")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("timelock")
                        .short("l")
                        .long("timelock")
                        .value_name("BLOCKS")
                        .help("Timelock period in blocks")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .get_matches();

    // Load configuration
    let config = Config::load()?;

    // Process subcommands
    match matches.subcommand() {
        ("generate-keys", Some(sub_matches)) => {
            let output_dir = sub_matches.value_of("output").unwrap();
            ValidatorCommands::generate_keys(Path::new(output_dir))?;
        }
        ("create-escrow", Some(sub_matches)) => {
            let node_url = sub_matches.value_of("node").unwrap();
            let amount = sub_matches.value_of("amount").unwrap().parse::<Balance>()?;
            let timelock = sub_matches.value_of("timelock").unwrap().parse::<BlockNumber>()?;
            
            let escrow_id = ValidatorCommands::create_escrow(node_url, amount, timelock)?;
            println!("Escrow created with ID: {}", escrow_id);
        }
        ("register-validator", Some(sub_matches)) => {
            let node_url = sub_matches.value_of("node").unwrap();
            let key_path = sub_matches.value_of("key").unwrap();
            let escrow_id = H256::from_str(sub_matches.value_of("escrow").unwrap())?;
            
            let tx_hash = ValidatorCommands::register_validator(
                node_url,
                Path::new(key_path),
                escrow_id,
            )?;
            println!("Validator registration submitted with transaction hash: {}", tx_hash);
        }
        ("submit-performance", Some(sub_matches)) => {
            let node_url = sub_matches.value_of("node").unwrap();
            let key_path = sub_matches.value_of("key").unwrap();
            let epoch = sub_matches.value_of("epoch").unwrap().parse::<u32>()?;
            let start_block = sub_matches.value_of("start-block").unwrap().parse::<u32>()?;
            let end_block = sub_matches.value_of("end-block").unwrap().parse::<u32>()?;
            let participation_hex = sub_matches.value_of("participation").unwrap();
            
            let tx_hash = ValidatorCommands::submit_performance(
                node_url,
                Path::new(key_path),
                epoch,
                (start_block, end_block),
                hex::decode(participation_hex)?,
            )?;
            println!("Performance proof submitted with transaction hash: {}", tx_hash);
        }
        ("unbond", Some(sub_matches)) => {
            let node_url = sub_matches.value_of("node").unwrap();
            let key_path = sub_matches.value_of("key").unwrap();
            let validator_id_hex = sub_matches.value_of("validator-id").unwrap();
            
            let mut validator_id_bytes = [0u8; 32];
            hex::decode_to_slice(validator_id_hex, &mut validator_id_bytes)?;
            let validator_id = ValidatorId(validator_id_bytes);
            
            let tx_hash = ValidatorCommands::unbond(
                node_url,
                Path::new(key_path),
                validator_id,
            )?;
            println!("Unbond request submitted with transaction hash: {}", tx_hash);
        }
        ("create-threshold-escrow", Some(sub_matches)) => {
            let node_url = sub_matches.value_of("node").unwrap();
            let amount = sub_matches.value_of("amount").unwrap().parse::<Balance>()?;
            let threshold = sub_matches.value_of("threshold").unwrap().parse::<u32>()?;
            let participants = sub_matches.value_of("participants").unwrap().parse::<u32>()?;
            let timelock = sub_matches.value_of("timelock").unwrap().parse::<BlockNumber>()?;
            
            let escrow_id = ValidatorCommands::create_threshold_escrow(
                node_url,
                amount,
                threshold,
                participants,
                timelock,
            )?;
            println!("Threshold escrow created with ID: {}", escrow_id);
        }
        _ => {
            println!("No subcommand specified. Use --help for usage information.");
        }
    }

    Ok(())
}

// Helper function to prompt for password
fn prompt_password(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    use rpassword::read_password;
    print!("{}", prompt);
    std::io::Write::flush(&mut std::io::stdout())?;
    let password = read_password()?;
    Ok(password)
}
