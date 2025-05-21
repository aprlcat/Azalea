mod cmd;
#[cfg(test)]
mod tests;
mod util;

use cmd::CommandDispatcher;

fn main() -> anyhow::Result<()> {
    util::log::init();

    let dispatcher = CommandDispatcher::new();
    dispatcher.dispatch()?;

    Ok(())
}
