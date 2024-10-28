use clap::Parser;
use dotenv::dotenv;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Name of the person to greet
    #[arg(short, long, env = "TEXAS_NAME")]
    texas_name: String,

    /// Number of times to greet
    #[arg(short, long, default_value_t = 1)]
    count: u8,
}

fn main() {
    let _ = dotenv(); // load .env if present

    let args = Args::parse();

    for _ in 0..args.count {
        println!("Howdy, {}!", args.texas_name);
    }
}
