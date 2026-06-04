use super::*;

pub(super) fn load_local_process_state_for_stop(
    state_dir: &Path,
) -> Result<Option<(ProcessState, PathBuf)>> {
    let paths = process_manager::paths(state_dir, None);
    let runtime_state_file = process_manager::runtime_state_file(state_dir);
    for state_file in [&paths.state_file, &runtime_state_file] {
        match process_manager::load_state(state_file) {
            Ok(state) => return Ok(Some((state, state_file.clone()))),
            Err(_) if !state_file.exists() => {}
            Err(err) => {
                process_manager::remove_state_file(state_file)?;
                println!(
                    "removed unreadable TabbyMew state file {} ({err:#})",
                    state_file.display()
                );
            }
        }
    }
    Ok(None)
}
