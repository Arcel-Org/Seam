use anyhow::Result;
use clap::{Args, ValueEnum};

/// Generate shell completion scripts.
#[derive(Args)]
pub struct CompletionsArgs {
    #[arg(value_enum)]
    pub shell: ShellKind,
}

#[derive(Clone, ValueEnum)]
pub enum ShellKind {
    Bash,
    Zsh,
    Fish,
}

pub fn run(args: CompletionsArgs) -> Result<()> {
    use clap::CommandFactory;
    use clap_complete::{Shell, generate};
    use std::io;

    let mut cmd = crate::Cli::command();
    let shell = match args.shell {
        ShellKind::Bash => Shell::Bash,
        ShellKind::Zsh => Shell::Zsh,
        ShellKind::Fish => Shell::Fish,
    };
    generate(shell, &mut cmd, "seam", &mut io::stdout());
    Ok(())
}
