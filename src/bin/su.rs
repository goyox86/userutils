#![deny(warnings)]

extern crate arg_parser;
extern crate extra;
extern crate termion;
extern crate redox_users;

use std::env;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::process::{exit, Command};
use std::str;

use arg_parser::ArgParser;
use extra::option::OptionalExt;
use termion::input::TermRead;
use redox_users::{User, get_uid, get_user_by_name};

const MAN_PAGE: &'static str = /* @MANSTART{su} */ r#"
NAME
    su - substitute user identity

SYNOPSIS
    su [ user ]
    su [ -h | --help ]

DESCRIPTION
    The su utility requests appropriate user credentials via PAM and switches to
    that user ID (the default user is the superuser).  A shell is then executed.

OPTIONS

    -h
    --help
        Display this help and exit.

AUTHOR
    Written by Jeremy Soller.
"#; /* @MANEND */

pub fn main() {
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let mut stderr = io::stderr();

    let mut parser = ArgParser::new(1)
        .add_flag(&["h", "help"]);
    parser.parse(env::args());

    // Shows the help
    if parser.found("help") {
        stdout.write_all(MAN_PAGE.as_bytes()).try(&mut stderr);
        stdout.flush().try(&mut stderr);
        exit(0);
    }

    // TODO: Improve this name
    let target_user = if parser.args.is_empty() {
        String::from("root")
    } else {
        parser.args[0].to_string()
    };

    let uid = get_uid();
    let user = get_user_by_name(&target_user).unwrap_or_else(|| {
        eprintln!("su: user {} not found", target_user);
        exit(1);
    });

    if uid > 0 || user.hash != "" {
        stdout.write_all(b"password: ").try(&mut stderr);
        stdout.flush().try(&mut stderr);

        if let Some(password) = stdin.read_passwd(&mut stdout).try(&mut stderr) {

            if user.verify(&password) {
                spawn_shell(user);
                exit(0);
            } else {
                stdout.write(b"su: authentication failed\n").try(&mut stderr);
                stdout.flush().try(&mut stderr);
            }
        }
    }

    spawn_shell(user);
}

fn spawn_shell(user: User) {
    let mut command = Command::new(&user.shell);

    command.uid(user.uid);
    command.gid(user.gid);

    command.env("USER", &user.user);
    command.env("UID", format!("{}", &user.uid));
    command.env("GROUPS", format!("{}", &user.gid));
    command.env("HOME", &user.home);
    command.env("SHELL", &user.shell);

    match command.spawn() {
        Ok(mut child) => match child.wait() {
            Ok(_status) => (),
            Err(err) => eprintln!("su: failed to wait for '{}': {}", user.shell, err)
        },
        Err(err) => eprintln!("su: failed to execute '{}': {}", user.shell, err)
    }
}