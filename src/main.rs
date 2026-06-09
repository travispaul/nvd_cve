use clap::clap_app;

mod cli;
use cli::{search, sync};

fn main() {
    let matches = clap_app!(nvd_cve =>
        (version: option_env!("CARGO_PKG_VERSION").unwrap_or("?"))
        (author: option_env!("CARGO_PKG_AUTHORS").unwrap_or("?"))
        (@subcommand sync =>
            (about: "Sync CVE feeds to local database via the NVD 2.0 API")
            (version: option_env!("CARGO_PKG_VERSION").unwrap_or("?"))
            (@arg feeds: -l --feeds [LIST] "Comma-separated feed tokens: year (`2024`), year range (`2002:2024`), `recent`, `modified`")
            (@arg db: -d --db [FILE] "Path to SQLite database where CVE data will be stored")
            (@arg api_key: -k --("api-key") [KEY] "NVD API key (also via NVD_API_KEY env var); raises rate limit from 5 to 50 req/30s")
            (@arg show: -s --("show-default") "Show default config values and exit")
            (@arg no_progress: -n --("no-progress") "Don't show progress bar when syncing feeds")
            (@arg force: -f --force "Re-sync feeds even if sync_state has them")
            (@arg verbose: -v --verbose "Print verbose logs (Set level with RUST_LOG)")
        )
        (@subcommand search =>
            (about: "Search for a CVE by ID in the local cache")
            (version: option_env!("CARGO_PKG_VERSION").unwrap_or("?"))
            (@arg CVE: "CVE ID to retrieve")
            (@arg db: -d --db [FILE] "Path to SQLite database where CVE feed data will be stored")
            (@arg text: -t --text [STRING] "Search the CVE descriptions instead.")
            (@arg verbose: -v --verbose "Print verbose logs (Set level with RUST_LOG)")
        )
    ).get_matches();

    if let Some(matches) = matches.subcommand_matches("sync") {
        return sync(matches);
    }

    if let Some(matches) = matches.subcommand_matches("search") {
        return search(matches);
    }

    eprintln!("Error:\n At least one subcommand required: 'sync' or 'search'\n");
    eprintln!("{}", matches.usage());
    std::process::exit(1);
}
