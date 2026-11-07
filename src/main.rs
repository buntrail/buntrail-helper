fn main() {
    if let Err(error) = run() {
        eprintln!("buntrail-helper: {error}");
        std::process::exit(1);
    }
}
fn run() -> std::io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(unix)]
    if let Some(result) = buntrail_helper::framed::run(&args) {
        return result;
    }
    if args.len() == 1 && args[0] == "--stdio" {
        return buntrail_helper::serve(std::io::stdin().lock(), std::io::stdout().lock());
    }
    #[cfg(unix)]
    {
        if args.len() == 2 && args[0] == "--supervisor" {
            return buntrail_helper::supervisor::run(
                std::path::Path::new(&args[1]),
                buntrail_helper::supervisor::RETENTION,
            );
        }
        let socket = if args.len() == 2 && args[0] == "--socket" {
            std::path::PathBuf::from(&args[1])
        } else if args.is_empty() {
            buntrail_helper::supervisor::default_socket()?
        } else {
            return Err(std::io::Error::other(
                "usage: buntrail-helper [--stdio | --socket PATH | --supervisor PATH]",
            ));
        };
        buntrail_helper::supervisor::bridge(&socket)
    }
    #[cfg(not(unix))]
    {
        if !args.is_empty() {
            return Err(std::io::Error::other("this platform supports --stdio only"));
        }
        buntrail_helper::serve(std::io::stdin().lock(), std::io::stdout().lock())
    }
}
