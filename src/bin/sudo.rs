// extern crate arg_parser;
// extern crate syscall;
// extern crate termion;
// extern crate userutils;

// use std::env;
// use std::fs::File;
// use std::io::{self, Read, Write};
// use std::os::unix::process::CommandExt;
// use std::process::{self, Command};

// use arg_parser::ArgParser;
// use termion::input::TermRead;
// use userutils::{Passwd, Group};

// const MAN_PAGE: &'static str = /* @MANSTART{sudo} */ r#"
// NAME
//     sudo - execute a command as another user

// SYNOPSIS
//     sudo command
//     sudo [ -h | --help ]

// DESCRIPTION
//     The sudo utility allows a permitted user to execute a command as the
//     superuser or another user, as specified by the security policy.

// OPTIONS

//     -h
//     --help
//         Display this help and exit.

// EXIT STATUS
//     Upon successful execution of a command, the exit status from sudo will
//     be the exit status of the program that was executed. In case of error
//     the exit status will be >0.

// AUTHOR
//     Written by Jeremy Soller.
// "#; /* @MANEND */

// pub fn main() {
//     let stdin = io::stdin();
//     let mut stdin = stdin.lock();
//     let stdout = io::stdout();
//     let mut stdout = stdout.lock();
//     let stderr = io::stderr();
//     let mut stderr = stderr.lock();

//     let mut parser = ArgParser::new(1)
//         .add_flag(&["h", "help"]);
//     parser.parse(env::args());

//     // Shows the help
//     if parser.found("help") {
//         let _ = stdout.write_all(MAN_PAGE.as_bytes());
//         let _ = stdout.flush();
//         process::exit(0);
//     }

//     let mut args = env::args().skip(1);
//     match args.next() {
//         None => {
//             writeln!(stderr, "sudo: no command provided").unwrap();
//             process::exit(1);
//         },
//         Some(cmd) => {
//             let uid = syscall::getuid().unwrap() as u32;

//             if uid != 0 {
//                 let mut passwd_string = String::new();
//                 if let Ok(mut file) = File::open("/etc/passwd") {
//                     let _ = file.read_to_string(&mut passwd_string);
//                 }

//                 let mut passwd_option = None;
//                 for line in passwd_string.lines() {
//                     if let Ok(passwd) = Passwd::parse(line) {
//                         if uid == passwd.uid {
//                             passwd_option = Some(passwd);
//                             break;
//                         }
//                     }
//                 }

//                 match passwd_option {
//                     None => {
//                         writeln!(stderr, "sudo: user not found in passwd").unwrap();
//                         process::exit(1);
//                     },
//                     Some(passwd) => {
//                         let mut group_string = String::new();
//                         if let Ok(mut file) = File::open("/etc/group") {
//                             let _ = file.read_to_string(&mut group_string);
//                         }

//                         let mut group_option = None;
//                         for line in group_string.lines() {
//                             if let Ok(group) = Group::parse(line) {
//                                 if group.group == "sudo" && group.users.split(',').any(|name| name == passwd.user) {
//                                     group_option = Some(group);
//                                     break;
//                                 }
//                             }
//                         }

//                         if group_option.is_none() {
//                             writeln!(stderr, "sudo: '{}' not in sudo group", passwd.user).unwrap();
//                             process::exit(1);
//                         }

//                         if ! passwd.hash.is_empty() {
//                             let max_attempts = 3;
//                             let mut attempts = 0;
//                             loop {
//                                 write!(stdout, "[sudo] password for {}: ", passwd.user).unwrap();
//                                 let _ = stdout.flush();

//                                 match stdin.read_passwd(&mut stdout).unwrap() {
//                                     Some(password) => {
//                                         write!(stdout, "\n").unwrap();
//                                         let _ = stdout.flush();

//                                         if passwd.verify(&password) {
//                                             break;
//                                         } else {
//                                             attempts += 1;
//                                             writeln!(stderr, "sudo: incorrect password ({}/{})", attempts, max_attempts).unwrap();
//                                             if attempts >= max_attempts {
//                                                 process::exit(1);
//                                             }
//                                         }
//                                     },
//                                     None => {
//                                         write!(stdout, "\n").unwrap();
//                                         process::exit(1);
//                                     }
//                                 }
//                             }
//                         }
//                     }
//                 }
//             }

//             let mut command = Command::new(&cmd);
//             for arg in args {
//                 command.arg(&arg);
//             }

//             command.uid(0);
//             command.gid(0);
//             command.env("USER", "root");
//             command.env("UID", "0");
//             command.env("GROUPS", "0");

//             match command.spawn() {
//                 Ok(mut child) => match child.wait() {
//                     Ok(status) => process::exit(status.code().unwrap_or(0)),
//                     Err(err) => {
//                         writeln!(stderr, "sudo: failed to wait for {}: {}", cmd, err).unwrap();
//                         process::exit(1);
//                     }
//                 },
//                 Err(err) => {
//                     writeln!(stderr, "sudo: failed to execute {}: {}", cmd, err).unwrap();
//                     process::exit(1);
//                 }
//             }
//         }
//     }
// }

fn main() {
    
}