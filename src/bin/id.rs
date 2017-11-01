extern crate arg_parser;
extern crate extra;
extern crate redox_users;

use std::borrow::Borrow;
use std::hash::Hash;
use std::env;
use std::io::{self, Write, Stderr, StdoutLock};
use std::process::exit;

use extra::io::fail;
use extra::option::OptionalExt;
use arg_parser::{ArgParser, Param};
use redox_users::{get_egid, get_gid, get_euid, get_uid, get_user_by_uid, get_group_by_gid};

const HELP_INFO: &'static str = "Try ‘id --help’ for more information.\n";
const MAN_PAGE: &'static str = /* @MANSTART{id} */ r#"
NAME
    id - display user identity

SYNOPSIS
    id
    id -g [-nr]
    id -u [-nr]
    id [ -h | --help ]

DESCRIPTION
    The id utility displays the user and group names and numeric IDs, of
    the calling process, to the standard output.

OPTIONS
    -G
        Display the different group IDs (effective and real) as white-space
        separated numbers, in no particular order.

    -g
        Display the effective group ID as a number.

    -n  Display the name of the user or group ID for the -g and -u options
        instead of the number.

    -u
        Display the effective user ID as a number.

    -a
        Ignored for compatibility with other id implementations.

    -r
        Display the real ID for the -g and -u options instead of the effective ID.

    -h
    --help
        Display this help and exit.

EXIT STATUS
     The whoami utility exits 0 on success, and >0 if an error occurs.

AUTHOR
    Written by Jose Narvaez.
"#; /* @MANEND */

pub fn main() {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let mut stderr = io::stderr();

    let mut parser = ArgParser::new(1)
        .add_flag(&["h", "help"])
        .add_flag(&["a"])
        .add_flag(&["G"])
        .add_flag(&["g"])
        .add_flag(&["u"])
        .add_flag(&["n"])
        .add_flag(&["r"]);
    parser.parse(env::args());

    // Shows the help
    if parser.found("help") {
        print_msg(MAN_PAGE, &mut stdout, &mut stderr);
        exit(0);
    }

    // Unrecognized flags
    if let Err(err) = parser.found_invalid() {
        stderr.write_all(err.as_bytes()).try(&mut stderr);
        print_msg(HELP_INFO, &mut stdout, &mut stderr);
        exit(1);
    }

    // Display the different group IDs (effective and real)
    // as white-space separated numbers, in no particular order.
    if parser.found(&'G') {
        if any_of_found(&parser, &[&'g', &'u']) {
            let msg = "id: -G option must be used without others\n";
            print_msg(msg, &mut stdout, &mut stderr);
            print_msg(HELP_INFO, &mut stdout, &mut stderr);
            exit(1);
        }

        let egid = get_egid();
        let gid = get_gid();
        print_msg(&format!("{} {}\n", egid, gid), &mut stdout, &mut stderr);
        exit(0);
   }

   // Check if people passed both -g -u which are mutually exclusive
   if parser.found(&'u') && parser.found(&'g') {
        let msg = "id: specify either -u or -g but not both\n";
        print_msg(msg, &mut stdout, &mut stderr);
        print_msg(HELP_INFO, &mut stdout, &mut stderr);
        exit(1);
   }

   // Display effective/real process user ID UNIX user name
   if parser.found(&'u') && parser.found(&'n') {
        // Did they pass -r? F so, we show the real
        let uid = if parser.found(&'r') {
            get_uid()
        } else {
            get_euid()
        };

        get_user_by_uid(uid).map(|user| {
            print_msg(&format!("{}\n", user.user), &mut stdout, &mut stderr);
            exit(0);
        }).or_else(|| {
            fail(&format!("id: no user found for uid: {}", uid), &mut stderr)
        });
    }

    // Display real user ID
    if parser.found(&'u') && parser.found(&'r') {
        let uid = get_uid();
        print_msg(&format!("{}\n", uid), &mut stdout, &mut stderr);
        exit(0);
    }

    // Display effective user ID
    if parser.found(&'u') {
        let euid = get_euid();
        print_msg(&format!("{}\n", euid), &mut stdout, &mut stderr);
        exit(0);
    }

   // Display effective/real process group ID UNIX group name
   if parser.found(&'g') && parser.found(&'n') {
        // Did they pass -r? If so we show the real one
        let gid = if parser.found(&'r') {
            get_gid()
        } else {
            get_egid()
        };

        get_group_by_gid(gid).map(|group| {
            print_msg(&format!("{}\n", group.group), &mut stdout, &mut stderr);
            exit(0);
        }).or_else(|| {
            fail(&format!("id: no group found for gid: {}", gid), &mut stderr)
        });
    }

    // Display the real group ID
    if parser.found(&'g') && parser.found(&'r') {
        let gid = get_gid();
        print_msg(&format!("{}\n", gid), &mut stdout, &mut stderr);
        exit(0);
    }

    // Display effective group ID
    if parser.found(&'g') {
        let egid = get_egid();
        print_msg(&format!("{}\n", egid), &mut stdout, &mut stderr);
        exit(0);
    }

    // -n does not apply if there is no -u or -g
    if parser.found(&'n') && none_of_found(&parser, &[&'u', &'g']) {
        let msg = "id: the -n option must be used with either -u or -g\n";
        fail(msg, &mut stderr);
    }

    // -r does not apply if there is no -u or -g
    if parser.found(&'r') && none_of_found(&parser, &[&'u', &'g']) {
        let msg = "id: the -r option must be used with either -u or -g\n";
        fail(msg, &mut stderr);
    }

    // We get everything we can and show that
    let euid = get_euid();
    let egid = get_egid();
    let user = get_user_by_uid(euid).unwrap_or_else(|| {
        fail(&format!("id: no user found for uid: {}", euid), &mut stderr);
    });

    let group = get_group_by_gid(egid).unwrap_or_else(|| {
        fail(&format!("id: no group found for gid: {}", euid), &mut stderr);
    });

    let msg = format!("uid={}({}) gid={}({})\n", euid, user.user, egid, group.group);
    print_msg(&msg, &mut stdout, &mut stderr);
    exit(0);
}

pub fn any_of_found<P: Hash + Eq + ?Sized>(parser: &ArgParser, flags: &[&P]) -> bool
    where Param: Borrow<P>
{
    for flag in flags {
        if parser.found(*flag) { return true }
    }

    false
}

fn none_of_found<P: Hash + Eq + ?Sized>(parser: &ArgParser, flags: &[&P]) -> bool
    where Param: Borrow<P>
{
    !any_of_found(parser, flags)
}

fn print_msg(msg: &str, stdout: &mut StdoutLock, stderr: &mut Stderr) {
    stdout.write_all(msg.as_bytes()).try(stderr);
    stdout.flush().try(stderr);
}
