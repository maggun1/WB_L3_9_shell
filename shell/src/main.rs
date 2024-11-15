use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::process::{Child, Command, Stdio};
use std::path::PathBuf;

struct Flag {
    name: String,
    short: Option<String>,
    long: Option<String>,
    takes_value: bool,
    description: String,
}

struct ParsedFlags {
    flags: HashMap<String, Option<String>>,
    args: Vec<String>,
}

struct Shell {
    env_vars: HashMap<String, String>,
    current_dir: PathBuf,
    command_flags: HashMap<String, Vec<Flag>>,
}

impl Shell {
    fn new() -> Result<Shell, Box<dyn Error>> {
        let mut command_flags = HashMap::new();

        command_flags.insert("ls".to_string(), vec![
            Flag {
                name: "all".to_string(),
                short: Some("a".to_string()),
                long: Some("all".to_string()),
                takes_value: false,
                description: "show hidden files".to_string(),
            },
            Flag {
                name: "long".to_string(),
                short: Some("l".to_string()),
                long: Some("long".to_string()),
                takes_value: false,
                description: "use long listing format".to_string(),
            },
        ]);

        command_flags.insert("echo".to_string(), vec![
            Flag {
                name: "no_newline".to_string(),
                short: Some("n".to_string()),
                long: None,
                takes_value: false,
                description: "do not output the trailing newline".to_string(),
            },
        ]);

        Ok(Shell {
            env_vars: env::vars().collect(),
            current_dir: env::current_dir()?,
            command_flags,
        })
    }

    fn run(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            print!(">>> $ ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();

            if input == "exit" {
                break;
            }

            if let Err(e) = self.execute_command(input) {
                eprintln!("{}", e);
            }
        }
        Ok(())
    }

    fn parse_flags(&self, command: &str, args: &[String]) -> ParsedFlags {
        let mut parsed = ParsedFlags {
            flags: HashMap::new(),
            args: Vec::new(),
        };

        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];

            if arg.starts_with('-') {
                if let Some(flags) = self.command_flags.get(command) {
                    let flag_name = if arg.starts_with("--") {
                        arg[2..].to_string()
                    } else {
                        arg[1..].to_string()
                    };

                    if let Some(flag) = flags.iter().find(|f| {
                        Some(flag_name.clone()) == f.short || Some(flag_name.clone()) == f.long
                    }) {
                        if flag.takes_value && i + 1 < args.len() {
                            parsed.flags.insert(flag.name.clone(), Some(args[i + 1].clone()));
                            i += 2;
                            continue;
                        } else {
                            parsed.flags.insert(flag.name.clone(), None);
                        }
                    }
                }
            } else {
                parsed.args.push(arg.clone());
            }
            i += 1;
        }

        parsed
    }

    fn process_redirects(&self, parts: &[String]) -> (Vec<String>, Option<File>, Option<File>) {
        let mut args = parts.to_vec();
        let mut input = None;
        let mut output = None;
        let mut i = 0;

        while i < args.len() {
            match args[i].as_str() {
                "<" => {
                    if i + 1 < args.len() {
                        if let Ok(file) = File::open(&args[i + 1]) {
                            input = Some(file);
                            args.drain(i..=i + 1);
                            continue;
                        }
                    }
                }
                ">" => {
                    if i + 1 < args.len() {
                        if let Ok(file) = File::create(&args[i + 1]) {
                            output = Some(file);
                            args.drain(i..=i + 1);
                            continue;
                        }
                    }
                }
                ">>" => {
                    if i + 1 < args.len() {
                        if let Ok(file) = OpenOptions::new()
                            .append(true)
                            .create(true)
                            .open(&args[i + 1])
                        {
                            output = Some(file);
                            args.drain(i..=i + 1);
                            continue;
                        }
                    }
                }
                _ => {}
            }
            i += 1;
        }

        (args, input, output)
    }

    fn execute_command(&mut self, input: &str) -> Result<(), Box<dyn Error>> {
        let commands: Vec<&str> = input.split('|').collect();
        let mut previous_output: Option<Vec<u8>> = None;

        for (i, cmd) in commands.iter().enumerate() {
            let parts: Vec<String> = cmd
                .trim()
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();

            if parts.is_empty() {
                continue;
            }

            let (processed_parts, input_file, output_file) = self.process_redirects(&parts);
            let command_name = &processed_parts[0];
            let parsed = self.parse_flags(command_name, &processed_parts[1..]);
            let is_last = i == commands.len() - 1;


            let input_data = if let Some(prev_output) = previous_output.take() {
                prev_output
            } else if let Some(mut file) = input_file {
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;
                buf
            } else {
                Vec::new()
            };

            match command_name.as_str() {
                "cd" => self.cd(parsed.args.get(0).map(|s| s.as_str()))?,
                "ls" => {
                    let mut buf = Vec::new();
                    {
                        let entries = std::fs::read_dir(&self.current_dir)?;
                        self.ls(entries, &parsed.flags, &mut buf)?;
                    }

                    if is_last {
                        if let Some(mut file) = output_file {
                            file.write_all(&buf)?;
                        } else {
                            io::stdout().write_all(&buf)?;
                        }
                    } else {
                        previous_output = Some(buf);
                    }
                },
                "pwd" => {
                    let mut buf = Vec::new();
                    writeln!(&mut buf, "{}", self.current_dir.display())?;

                    if is_last {
                        if let Some(mut file) = output_file {
                            file.write_all(&buf)?;
                        } else {
                            io::stdout().write_all(&buf)?;
                        }
                    } else {
                        previous_output = Some(buf);
                    }
                },
                "echo" => {
                    let mut buf = Vec::new();
                    self.echo(&parsed.args, &parsed.flags, &mut buf)?;

                    if is_last {
                        if let Some(mut file) = output_file {
                            file.write_all(&buf)?;
                        } else {
                            io::stdout().write_all(&buf)?;
                        }
                    } else {
                        previous_output = Some(buf);
                    }
                },
                _ => {
                    let mut child = self.execute_external(
                        &processed_parts,
                        if input_data.is_empty() { None } else { Some(input_data) },
                        is_last,
                    )?;

                    if !is_last {
                        let mut buf = Vec::new();
                        if let Some(mut stdout) = child.stdout.take() {
                            stdout.read_to_end(&mut buf)?;
                            previous_output = Some(buf);
                        }
                    }
                    child.wait()?;
                }
            }
        }

        Ok(())
    }

    fn execute_external(
        &self,
        parts: &[String],
        input_data: Option<Vec<u8>>,
        is_last: bool)
        -> Result<Child, Box<dyn Error>> {
        let mut command = Command::new(&parts[0]);
        command.args(&parts[1..]);
        command.current_dir(&self.current_dir);

        let stdin = if let Some(data) = input_data {
            let mut temp = tempfile::tempfile()?;
            temp.write_all(&data)?;
            temp.seek(SeekFrom::Start(0))?;
            Stdio::from(temp)
        } else {
            Stdio::inherit()
        };

        let stdout = if is_last {
            Stdio::inherit()
        } else {
            Stdio::piped()
        };

        command
            .stdin(stdin)
            .stdout(stdout)
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| Box::new(io::Error::new(io::ErrorKind::Other, format!("Failed to execute command: {}", e))) as Box<dyn Error>)
    }

    fn cd(&mut self, dir: Option<&str>) -> Result<(), Box<dyn Error>> {
        let new_dir = match dir {
            Some(path) => {
                if path.starts_with('~') {
                    let home = env::var("HOME")?;
                    PathBuf::from(path.replacen('~', &home, 1))
                } else {
                    PathBuf::from(path)
                }
            }
            None => PathBuf::from(env::var("HOME")?),
        };

        env::set_current_dir(&new_dir)?;
        self.current_dir = env::current_dir()?;
        Ok(())
    }

    fn ls(
        &self,
        entries: std::fs::ReadDir,
        flags: &HashMap<String, Option<String>>,
        output: &mut dyn Write)
        -> Result<(), Box<dyn Error>> {
        let show_hidden = flags.contains_key("all");
        let long_format = flags.contains_key("long");

        for entry in entries {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();

            if !show_hidden && file_name.starts_with('.') {
                continue;
            }

            if long_format {
                let metadata = entry.metadata()?;
                self.print_long_format(&entry, &metadata, output)?;
            } else {
                writeln!(output, "{}", file_name)?;
            }
        }

        Ok(())
    }

    fn print_long_format(
        &self,
        entry: &std::fs::DirEntry,
        metadata: &std::fs::Metadata,
        output: &mut dyn Write)
        -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt;

        let mode = metadata.permissions().mode();
        let size = metadata.len();
        let modified = metadata.modified()?;

        let perm_str = format!("{}{}{}{}",
                               if metadata.is_dir() { 'd' } else { '-' },
                               Self::format_mode_triple((mode >> 6) & 0o7),
                               Self::format_mode_triple((mode >> 3) & 0o7),
                               Self::format_mode_triple(mode & 0o7)
        );

        #[cfg(unix)]
        let (username, groupname) = {
            use std::os::unix::fs::MetadataExt;
            let uid = metadata.uid();
            let gid = metadata.gid();

            (
                users::get_user_by_uid(uid)
                    .map(|u| u.name().to_string_lossy().into_owned())
                    .unwrap_or_else(|| uid.to_string()),
                users::get_group_by_gid(gid)
                    .map(|g| g.name().to_string_lossy().into_owned())
                    .unwrap_or_else(|| gid.to_string())
            )
        };

        #[cfg(not(unix))]
        let (username, groupname) = ("unknown".to_string(), "unknown".to_string());

        let time_str = chrono::DateTime::<chrono::Local>::from(modified)
            .format("%b %d %H:%M")
            .to_string();

        writeln!(output, "{} {:>8} {:>8} {:>8} {} {}",
                 perm_str, username, groupname, size, time_str,
                 entry.file_name().to_string_lossy()
        )?;

        Ok(())
    }

    fn format_mode_triple(mode: u32) -> String {
        format!("{}{}{}",
                if mode & 0o4 != 0 { 'r' } else { '-' },
                if mode & 0o2 != 0 { 'w' } else { '-' },
                if mode & 0o1 != 0 { 'x' } else { '-' }
        )
    }

    fn echo(
        &self,
        args: &[String],
        flags: &HashMap<String, Option<String>>,
        output: &mut dyn Write)
        -> Result<(), Box<dyn Error>> {
        let no_newline = flags.contains_key("no_newline");
        let mut output_str = String::new();

        for arg in args {
            if arg.starts_with('$') {
                let var_name = &arg[1..];
                if let Some(value) = self.env_vars.get(var_name) {
                    output_str.push_str(value);
                }
            } else {
                output_str.push_str(arg);
            }
            output_str.push(' ');
        }

        let output_str = output_str.trim_end();
        if no_newline {
            write!(output, "{}", output_str)?;
        } else {
            writeln!(output, "{}", output_str)?;
        }

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut shell = Shell::new()?;
    shell.run()

}