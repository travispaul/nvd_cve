# nvd_cve
🔎 Search for CVEs against a local cached copy of NIST National Vulnerability Database (NVD).

[![Build and Run Tests](https://github.com/travispaul/nvd_cve/actions/workflows/build_and_test.yml/badge.svg)](https://github.com/travispaul/nvd_cve/actions/workflows/build_and_test.yml)

## Usage

### Command line usage

The `nvd_cve` command line application offers `sync` and `search` commands.

```
USAGE:
    nvd_cve [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    help      Prints this message or the help of the given subcommand(s)
    search    Search for a CVE, trying the online API first and falling back to the local cache
    sync      Sync CVE feeds to local database

```

#### Sync

Before you can search for CVEs you first need to perform a `sync` which will pull the datafeeds and build a local cache in SQLite.

```
Sync CVE feeds to local database

USAGE:
    nvd_cve sync [FLAGS] [OPTIONS]

FLAGS:
    -h, --help            Prints help information
    -n, --no-progress     Don't show progress bar when syncing feeds
    -s, --show-default    Show default config values and exit
    -V, --version         Prints version information

OPTIONS:
    -d, --db <FILE>       Path to SQLite database where CVE feed data will be stored
    -l, --feeds <LIST>    Comma separate list of CVE feeds to fetch and sync, defaults to: all known feeds
    -u, --url <URL>       URL to use for fetching feeds, defaults to: https://nvd.nist.gov/feeds/json/cve/1.1/

```

#### Search

```
Search for a CVE, trying the online API first and falling back to the local cache

USAGE:
    nvd_cve search [OPTIONS] [CVE]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -d, --db <FILE>    Path to SQLite database where CVE feed data will be stored

ARGS:
    <CVE>    CVE ID to retrieve
```

### Module usage

``TODO``
