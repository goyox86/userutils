#![deny(warnings)]

extern crate arg_parser;
extern crate extra;
extern crate liner;
extern crate termion;
extern crate redox_users;

use std::fs::File;
use std::io::{self, Write, Stderr, Stdout};
use std::os::unix::process::CommandExt;
use std::process::{exit, Command};
use std::env;
use std::str;

use extra::option::OptionalExt;
use arg_parser::ArgParser;
use termion::input::TermRead;
use redox_users::{User, get_user_by_name};

const MAN_PAGE: &'static str = /* @MANSTART{login} */ r#"
NAME
    login - log into the computer

SYNOPSIS
    login

DESCRIPTION
    The login utility logs users (and pseudo-users) into the computer system.

OPTIONS

    -h
    --help
        Display this help and exit.

AUTHOR
    Written by Jeremy Soller.
"#; /* @MANEND */

const ISSUE_FILE: &'static str = "/etc/issue";
const MOTD_FILE: &'static str = "/etc/motd";

pub fn main() {
    let mut stdout = io::stdout();
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

    if let Ok(mut issue) = File::open(ISSUE_FILE) {
        io::copy(&mut issue, &mut stdout).try(&mut stderr);
        stdout.flush().try(&mut stderr);
    }

    loop {
        let user = liner::Context::new()
            .read_line("\x1B[1mredox login:\x1B[0m ", &mut |_| {})
            .try(&mut stderr);

        if ! user.is_empty() {
            let stdin = io::stdin();
            let mut stdin = stdin.lock();

            let user_option = get_user_by_name(user);
            match user_option {
                None => {
                    stdout.write(b"\nLogin incorrect\n").try(&mut stderr);
                    stdout.write(b"\n").try(&mut stderr);
                    stdout.flush().try(&mut stderr);
                    continue;
                },
                Some(user) => {
                    if user.hash == "" {
                        spawn_shell(user, &mut stdout, &mut stderr);
                        break;
                    }
                    
                    stdout.write_all(b"\x1B[1mpassword:\x1B[0m ").try(&mut stderr);
                    stdout.flush().try(&mut stderr);
                    if let Some(password) = stdin.read_passwd(&mut stdout).try(&mut stderr) {
                        stdout.write(b"\n").try(&mut stderr);
                        stdout.flush().try(&mut stderr);

                        if user.verify(&password) {
                            spawn_shell(user, &mut stdout, &mut stderr);
                            break;
                        }
                    }
                }
            }
        } else {
            stdout.write(b"\n").try(&mut stderr);
            stdout.flush().try(&mut stderr);;
        }
    }
}

fn spawn_shell(user: User, stdout: &mut Stdout, stderr: &mut Stderr) {
    if let Ok(mut motd) = File::open(MOTD_FILE) {
        io::copy(&mut motd, stdout).try(stderr);
        stdout.flush().try(stderr);
    }

    let mut command = Command::new(&user.shell);

    command.uid(user.uid);
    command.gid(user.gid);

    command.current_dir(&user.home);

    command.env("USER", &user.user);
    command.env("UID", format!("{}", user.uid));
    command.env("GROUPS", format!("{}", user.gid));
    command.env("HOME", &user.home);
    command.env("SHELL", &user.shell);

    match command.spawn() {
        Ok(mut child) => match child.wait() {
            Ok(_status) => (),
            Err(err) => panic!("login: failed to wait for '{}': {}", user.shell, err)
        },
        Err(err) => panic!("login: failed to execute '{}': {}", user.shell, err)
    }
}
