use aya::{
    programs::{ProgramError, TracePoint},
    Bpf,
};

pub fn tp_load_and_attach_prog(
    bpf: &mut Bpf,
    prog_name: &str,
    category: &str,
    name: &str,
) -> Result<(), ProgramError> {
    let program: &mut TracePoint = bpf.program_mut(prog_name).unwrap().try_into()?;
    program.load()?;
    program.attach(category, name)?;
    return Ok(());
}
